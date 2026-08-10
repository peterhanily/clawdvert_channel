import io
import fcntl
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from clawdvert import frames

from artifact_bridge.adapters.owner_frame import OwnerFrameAdapter
from artifact_bridge.audit import audit_bundle
from artifact_bridge.cli import main
from artifact_bridge.client import BridgeClient
from artifact_bridge.errors import (
    AdapterError,
    CollisionError,
    IntegrityError,
    LockfileError,
    ReferenceError,
    ResponseTooLargeError,
    UnsafePathError,
    UnsupportedReferenceError,
    VersionNotFoundError,
)
from artifact_bridge.json_safety import strict_json_loads
from artifact_bridge.models import (
    Artifact,
    ArtifactRef,
    ArtifactVersion,
    AuthStatus,
    FetchedArtifact,
    Representation,
    safe_json_value,
)
from artifact_bridge.refs import parse_ref, require_resolvable
from artifact_bridge.store import ArtifactStore, LOCK_NAME


SLUG = "11111111-2222-4333-8444-555555555555"
OTHER_SLUG = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


class FakeAdapter:
    def __init__(self, name="owner", authenticated=True, wrong_version=False):
        self.name = name
        self.authenticated = authenticated
        self.wrong_version = wrong_version
        self.fetch_calls = []
        self.list_calls = []

    def auth_status(self):
        return AuthStatus(self.name, self.authenticated, "fixture", "offline fixture")

    def list_artifacts(self, limit=None):
        self.list_calls.append(limit)
        return [self._artifact(ArtifactRef(self.name, SLUG))]

    def inspect(self, ref):
        return self._artifact(ref)

    def versions(self, ref):
        return [
            ArtifactVersion(self.name, ref.artifact_id, "v1"),
            ArtifactVersion(self.name, ref.artifact_id, "v2", is_live=True),
        ]

    def fetch(self, ref, version):
        self.fetch_calls.append((ref, version))
        returned = "wrong" if self.wrong_version else version
        artifact = self._artifact(ref)
        if ref.kind == "standard":
            artifact = Artifact(
                provider=self.name,
                artifact_id="claude_artifact_stable_123",
                title="Standard",
                kind="standard",
            )
        data = {
            "v1": b"first\nline\n",
            "v2": b"second\nline\n",
            "escape-a": b"safe\n",
            "escape-b": b"\x1b]8;;https://evil.invalid\x07label\n",
        }.get(version, ("content " + version).encode("utf-8"))
        return FetchedArtifact(
            artifact=artifact,
            version=ArtifactVersion(self.name, artifact.artifact_id, returned),
            representations=(
                Representation(
                    label="served" if self.name == "owner" else "stored",
                    media_type="text/html",
                    data=data,
                    suggested_name="index.html",
                    source_url="https://example.invalid/exact/%s" % version,
                ),
            ),
            provenance={"provider": self.name, "exact_version": version},
        )

    def _artifact(self, ref):
        return Artifact(
            provider=self.name,
            artifact_id=ref.artifact_id,
            title="Fixture",
            live_version="v2",
            published_version="v1",
            kind=ref.kind,
        )


class FakeSession:
    def __init__(self):
        self.timeout = 1
        self.token_source = "fixture"
        self.requests = []
        self.closed = 0

    def request(self, method, path, body=None, headers=None, retries=2):
        self.requests.append((method, path))
        if path == "/api/frame/%s?via=model_read" % SLUG:
            return 404, {}, {}
        if path == "/api/frame/%s?via=model_read" % OTHER_SLUG:
            return 200, {
                "slug": OTHER_SLUG,
                "title": "Private",
                "live": "private-v2",
                "shared": None,
                "assetToken": "ASSET-DO-NOT-LEAK",
                "perm": {"mode": "owner"},
                "history": ["private-v1", "private-v2"],
            }, {}
        if path.startswith("/api/frame/versions/"):
            return 200, {"live": "private-v2", "versions": ["private-v1", "private-v2"]}, {}
        if path.startswith("/api/frame/frames?"):
            return 200, {"frames": [{"slug": OTHER_SLUG, "title": "Private", "live": "private-v2"}]}, {}
        return 404, {}, {}

    def close(self):
        self.closed += 1


class FakeResponse:
    status = 200

    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def read(self, amount=-1):
        return self.payload[:amount]

    def getcode(self):
        return self.status

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class ArtifactRefTests(unittest.TestCase):
    def test_code_viewer_and_exact_content_origin_urls(self):
        viewer = parse_ref("https://claude.ai/code/artifact/report-%s" % SLUG)
        self.assertEqual((viewer.provider, viewer.artifact_id, viewer.version), ("owner", SLUG, None))
        exact = parse_ref(
            "https://%s.frame.claudeusercontent.com/_f/1741803761-9f3a/" % SLUG
        )
        self.assertEqual(exact.provider, "owner")
        self.assertEqual(exact.version, "1741803761-9f3a")

    def test_official_compliance_ids_route_without_guessing_versions(self):
        code = parse_ref("cart_01Tu9VwXyZaBcDeFgHiJkLmN")
        self.assertEqual((code.provider, code.kind, code.version), ("compliance", "code", None))
        standard = parse_ref("claude_artifact_version_01AbCdEf")
        self.assertEqual(
            (standard.provider, standard.kind, standard.version),
            ("compliance", "standard", "claude_artifact_version_01AbCdEf"),
        )

    def test_public_chat_url_is_representable_but_not_exactly_resolvable(self):
        ref = parse_ref("https://claude.ai/public/artifacts/abc123")
        self.assertEqual(ref.kind, "standard-public")
        with self.assertRaises(UnsupportedReferenceError):
            require_resolvable(ref)

    def test_content_origin_query_capability_is_rejected(self):
        with self.assertRaises(ReferenceError):
            parse_ref(
                "https://%s.frame.claudeusercontent.com/_f/v1/?__frame_t=SECRET" % SLUG
            )

    def test_unsupported_reference_error_does_not_echo_query_material(self):
        secret = "SIGNED-QUERY-MATERIAL"
        with self.assertRaises(ReferenceError) as caught:
            parse_ref("https://example.invalid/not-an-artifact?signature=" + secret)

        self.assertNotIn(secret, str(caught.exception))
        self.assertIsNone(caught.exception.__context__)

    def test_malformed_port_error_does_not_retain_parser_secret(self):
        secret = "PORT-PARSER-SECRET"
        with self.assertRaises(ReferenceError) as caught:
            parse_ref("https://claude.ai:" + secret + "/code/artifact/" + SLUG)

        self.assertNotIn(secret, str(caught.exception))
        self.assertIsNone(caught.exception.__context__)


class ModelAndClientTests(unittest.TestCase):
    def test_json_safety_redacts_keys_and_bearer_shaped_values(self):
        data = safe_json_value(
            {
                "assetToken": "SECRET",
                "title": "Bearer abc.def.ghi",
                "url": "https://example.invalid/?__frame_t=CAPABILITY",
                "api": "sk-ant-api01-VERYSECRET",
                "x-api-key": "GENERIC-COMPLIANCE-KEY",
                "password": "do-not-store",
                "credential": "do-not-store-either",
                "api key": "space-separated-secret",
                "ｐｒｉｖａｔｅ＿ｋｅｙ": "nfkc-secret",
                "signed_url": "https://storage.invalid/object?X-Amz-Signature=URL-SIGNATURE",
                "userinfo_url": "https://user:URL-PASSWORD@example.invalid/object",
            }
        )
        encoded = json.dumps(data)
        self.assertNotIn("SECRET", encoded)
        self.assertNotIn("CAPABILITY", encoded)
        self.assertNotIn("abc.def.ghi", encoded)
        self.assertNotIn("sk-ant", encoded)
        self.assertNotIn("GENERIC-COMPLIANCE-KEY", encoded)
        self.assertNotIn("do-not-store", encoded)
        self.assertNotIn("space-separated-secret", encoded)
        self.assertNotIn("nfkc-secret", encoded)
        self.assertNotIn("URL-SIGNATURE", encoded)
        self.assertNotIn("URL-PASSWORD", encoded)
        self.assertIn("https://storage.invalid/object?[REDACTED]", encoded)

    def test_error_redaction_covers_generic_credential_headers(self):
        from artifact_bridge.errors import redact_text

        raw = (
            "x-api-key: GENERIC-KEY Authorization: Basic BASIC-VALUE "
            "Cookie=session-cookie password=hunter2 private key=PRIVATE-VALUE "
            "-----BEGIN PRIVATE KEY-----\nPEM-SECRET\n-----END PRIVATE KEY-----"
        )
        safe = redact_text(raw)
        for secret in (
            "GENERIC-KEY",
            "BASIC-VALUE",
            "session-cookie",
            "hunter2",
            "PRIVATE-VALUE",
            "PEM-SECRET",
        ):
            self.assertNotIn(secret, safe)
        self.assertGreaterEqual(safe.count("[REDACTED]"), 6)

    def test_private_key_redaction_is_linear_for_unclosed_markers(self):
        from artifact_bridge.errors import redact_text

        marker = "-----BEGIN PRIVATE KEY-----"
        safe = redact_text(marker * 5000 + "tail-secret")
        self.assertEqual(safe, "[REDACTED]")

    def test_default_fetch_resolves_live_to_one_exact_request(self):
        adapter = FakeAdapter()
        fetched = BridgeClient([adapter]).fetch(SLUG)
        self.assertEqual(fetched.version.version_id, "v2")
        self.assertEqual([call[1] for call in adapter.fetch_calls], ["v2"])

    def test_embedded_exact_version_conflict_fails_before_fetch(self):
        adapter = FakeAdapter()
        client = BridgeClient([adapter])
        ref = ArtifactRef("owner", SLUG, version="v1")
        with self.assertRaises(VersionNotFoundError):
            client.fetch(ref, "v2")
        self.assertEqual(adapter.fetch_calls, [])

    def test_symbolic_versions_are_rejected_on_every_content_path(self):
        adapter = FakeAdapter()
        client = BridgeClient([adapter])
        symbolic_ref = ArtifactRef("owner", SLUG, version="latest")
        with self.assertRaises(VersionNotFoundError):
            client.fetch(symbolic_ref)
        with self.assertRaises(VersionNotFoundError):
            client.mirror(SLUG, ["live"])
        with self.assertRaises(VersionNotFoundError):
            client.diff(SLUG, "published", "v2")
        self.assertEqual(adapter.fetch_calls, [])

    def test_adapter_returning_wrong_exact_version_is_rejected(self):
        adapter = FakeAdapter(wrong_version=True)
        with self.assertRaises(IntegrityError):
            BridgeClient([adapter]).fetch(SLUG, "v2")

    def test_standard_exact_ref_accepts_stable_lineage_id(self):
        adapter = FakeAdapter("compliance")
        client = BridgeClient([adapter])
        ref = "claude_artifact_version_01AbCdEf"
        fetched = client.fetch(ref)
        self.assertEqual(fetched.version.version_id, ref)
        self.assertEqual(fetched.artifact.artifact_id, "claude_artifact_stable_123")

    def test_list_requires_explicit_authority_surface(self):
        client = BridgeClient([FakeAdapter("owner"), FakeAdapter("compliance")])
        with self.assertRaises(ReferenceError):
            client.list_artifacts("auto", 10)
        result = client.list_artifacts("owner", 10)
        self.assertEqual(len(result), 1)

    def test_client_caps_faulty_plugin_bytes(self):
        adapter = FakeAdapter()
        client = BridgeClient([adapter], max_representation_bytes=3)
        with self.assertRaises(ResponseTooLargeError):
            client.fetch(SLUG, "v2")

    def test_diff_has_bounded_input_and_exact_versions(self):
        adapter = FakeAdapter()
        client = BridgeClient([adapter])
        diff = client.diff(SLUG, "v1", "v2")
        self.assertIn("-first", diff)
        self.assertIn("+second", diff)
        self.assertEqual([call[1] for call in adapter.fetch_calls], ["v1", "v2"])

    def test_mirror_enforces_cumulative_bound_before_returning_results(self):
        class FourByteAdapter(FakeAdapter):
            def fetch(self, ref, version):
                fetched = super().fetch(ref, version)
                return FetchedArtifact(
                    artifact=fetched.artifact,
                    version=fetched.version,
                    representations=(Representation("served", "text/plain", b"1234"),),
                )

        adapter = FourByteAdapter()
        client = BridgeClient([adapter], max_total_bytes=7)
        with self.assertRaises(ResponseTooLargeError):
            client.mirror(SLUG)
        self.assertEqual([call[1] for call in adapter.fetch_calls], ["v1", "v2"])

    def test_mirror_refuses_an_implicit_partial_version_listing(self):
        class PartialHistoryAdapter(FakeAdapter):
            def versions(self, ref):
                return [
                    ArtifactVersion(
                        self.name,
                        ref.artifact_id,
                        "public-v1",
                        metadata={"listing_completeness": "partial"},
                    )
                ]

        adapter = PartialHistoryAdapter()
        client = BridgeClient([adapter])
        with self.assertRaises(AdapterError):
            client.mirror(SLUG)
        self.assertEqual(adapter.fetch_calls, [])
        mirrored = client.mirror(SLUG, ["public-v1"])
        self.assertEqual(mirrored[0].version.version_id, "public-v1")

    def test_mirror_caps_implicit_and_explicit_version_fanout_before_fetch(self):
        class HugeHistoryAdapter(FakeAdapter):
            def versions(self, ref):
                return [
                    ArtifactVersion(self.name, ref.artifact_id, "v-%04d" % index)
                    for index in range(1025)
                ]

        adapter = HugeHistoryAdapter()
        client = BridgeClient([adapter])
        with self.assertRaises(ResponseTooLargeError):
            client.mirror(SLUG)
        with self.assertRaises(ResponseTooLargeError):
            client.mirror(SLUG, ["v-%04d" % index for index in range(1025)])
        self.assertEqual(adapter.fetch_calls, [])


class OwnerAdapterTests(unittest.TestCase):
    def test_authenticated_404_public_probe_does_not_discard_session(self):
        session = FakeSession()
        public = {"kind": "frame", "mode": "public", "ver": "public-v1", "title": "Public"}
        adapter = OwnerFrameAdapter(
            session=session,
            anonymous_opener=lambda request, timeout: FakeResponse(public),
            content_fetcher=lambda *args: b"public",
        )
        self.assertEqual(adapter.inspect(parse_ref(SLUG)).published_version, "public-v1")
        self.assertEqual(adapter.inspect(parse_ref(OTHER_SLUG)).live_version, "private-v2")
        self.assertEqual(len(adapter.list_artifacts(10)), 1)
        self.assertEqual(session.closed, 0)

    def test_anonymous_exact_content_url_fetches_pinned_public_bytes(self):
        calls = []
        public = {"kind": "frame", "mode": "public", "ver": "public-v1", "title": "Public"}

        def content_fetcher(session, slug, version, asset_token, limit):
            calls.append((session, slug, version, asset_token, limit))
            return b"<h1>untrusted</h1>", "text/html"

        adapter = OwnerFrameAdapter(
            anonymous_opener=lambda request, timeout: FakeResponse(public),
            content_fetcher=content_fetcher,
        )
        # Deterministically simulate a host with no owner credential.
        adapter._session_error = RuntimeError("fixture has no OAuth")
        url = "https://%s.frame.claudeusercontent.com/_f/public-v1/" % SLUG
        fetched = BridgeClient([adapter]).fetch(url)
        self.assertEqual(fetched.version.version_id, "public-v1")
        self.assertEqual(fetched.representations[0].label, "served")
        self.assertEqual(calls[0][0], None)
        self.assertEqual(calls[0][3], None)

    def test_owner_adapter_enforces_embedded_version_itself(self):
        adapter = OwnerFrameAdapter(session=FakeSession(), content_fetcher=lambda *args: b"x")
        ref = ArtifactRef("owner", OTHER_SLUG, version="private-v1")
        with self.assertRaises(VersionNotFoundError):
            adapter.fetch(ref, "private-v2")

    def test_asset_capability_never_enters_fetched_model(self):
        adapter = OwnerFrameAdapter(
            session=FakeSession(),
            content_fetcher=lambda session, slug, version, token, limit: b"private bytes",
        )
        fetched = adapter.fetch(ArtifactRef("owner", OTHER_SLUG), "private-v2")
        serialized = json.dumps(fetched.to_dict())
        self.assertNotIn("ASSET-DO-NOT-LEAK", serialized)
        self.assertNotIn("__frame_t", serialized)


class StoreAndCliTests(unittest.TestCase):
    def test_store_writes_hash_lock_and_refuses_changed_collision(self):
        adapter = FakeAdapter()
        fetched = adapter.fetch(ArtifactRef("owner", SLUG), "v1")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            lock = ArtifactStore().write([fetched], output)
            rep = lock["versions"][0]["representations"][0]
            target = output / rep["path"]
            self.assertNotIn("/", rep["path"])
            self.assertTrue(rep["path"].startswith("representation-"))
            self.assertTrue(target.is_file())
            self.assertEqual(rep["bytes"], target.stat().st_size)
            self.assertEqual(json.loads((output / LOCK_NAME).read_text()), lock)
            target.write_bytes(b"changed")
            with self.assertRaises(Exception):
                ArtifactStore().write([fetched], output)

    def test_store_rejects_current_directory_without_self_deadlock(self):
        adapter = FakeAdapter()
        original = os.getcwd()
        with tempfile.TemporaryDirectory() as temporary:
            os.chdir(temporary)
            try:
                with self.assertRaises(UnsafePathError):
                    ArtifactStore().write(
                        [adapter.fetch(ArtifactRef("owner", SLUG), "v1")], Path(".")
                    )
                Path("nested").mkdir()
                with self.assertRaises(UnsafePathError):
                    ArtifactStore().write(
                        [adapter.fetch(ArtifactRef("owner", SLUG), "v1")],
                        Path("nested/.."),
                    )
            finally:
                os.chdir(original)

    def test_store_refuses_to_nest_a_bundle_inside_an_intact_bundle(self):
        adapter = FakeAdapter()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            ArtifactStore().write(
                [adapter.fetch(ArtifactRef("owner", SLUG), "v1")], output
            )
            before = audit_bundle(output)
            self.assertTrue(before.ok, [issue.to_dict() for issue in before.issues])
            nested = output / "new" / "nested"
            with self.assertRaises(CollisionError):
                ArtifactStore().write(
                    [adapter.fetch(ArtifactRef("owner", SLUG), "v2")], nested
                )
            self.assertFalse((output / "new").exists())
            after = audit_bundle(output)
            self.assertTrue(after.ok, [issue.to_dict() for issue in after.issues])

    def test_store_refuses_a_symlinked_path_beneath_an_intact_bundle(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        adapter = FakeAdapter()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            output = base / "bundle"
            ArtifactStore().write(
                [adapter.fetch(ArtifactRef("owner", SLUG), "v1")], output
            )
            empty = output / "empty"
            empty.mkdir()
            link = base / "indirect"
            link.symlink_to(empty, target_is_directory=True)
            with self.assertRaises(CollisionError):
                ArtifactStore().write(
                    [adapter.fetch(ArtifactRef("owner", SLUG), "v2")],
                    link / "nested",
                )
            self.assertFalse((empty / "nested").exists())
            report = audit_bundle(output)
            self.assertTrue(report.ok, [issue.to_dict() for issue in report.issues])

    def test_bundle_ancestor_detection_ignores_current_operation_byte_limits(self):
        adapter = FakeAdapter()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            ArtifactStore().write(
                [adapter.fetch(ArtifactRef("owner", SLUG), "v1")], output
            )
            tiny_store = ArtifactStore(
                max_representation_bytes=1, max_total_bytes=1
            )
            tiny = adapter.fetch(ArtifactRef("owner", SLUG), "x")
            tiny = FetchedArtifact(
                artifact=tiny.artifact,
                version=tiny.version,
                representations=(Representation("served", "text/plain", b"x"),),
            )
            with self.assertRaises(CollisionError):
                tiny_store.write([tiny], output / "nested")
            self.assertFalse((output / "nested").exists())
            report = audit_bundle(output)
            self.assertTrue(report.ok, [issue.to_dict() for issue in report.issues])

    def test_cooperating_nested_writer_rechecks_after_parent_lock(self):
        adapter = FakeAdapter()
        first_store = ArtifactStore()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            claimed = threading.Event()
            release = threading.Event()
            outer_failures = []
            nested_failures = []
            original_claim = first_store._claim_output_directory

            def paused_claim(parent_fd, name, display_path):
                directory_fd = original_claim(parent_fd, name, display_path)
                claimed.set()
                if not release.wait(5):
                    os.close(directory_fd)
                    raise RuntimeError("test timed out waiting to publish outer bundle")
                return directory_fd

            def write_outer():
                try:
                    with mock.patch.object(
                        first_store,
                        "_claim_output_directory",
                        side_effect=paused_claim,
                    ):
                        first_store.write(
                            [adapter.fetch(ArtifactRef("owner", SLUG), "v1")],
                            output,
                        )
                except Exception as exc:
                    outer_failures.append(exc)

            def write_nested():
                try:
                    ArtifactStore().write(
                        [adapter.fetch(ArtifactRef("owner", SLUG), "v2")],
                        output / "mid" / "nested",
                    )
                except Exception as exc:
                    nested_failures.append(exc)

            outer = threading.Thread(target=write_outer)
            nested = threading.Thread(target=write_nested)
            outer.start()
            self.assertTrue(claimed.wait(5), "outer writer did not claim bundle")
            nested.start()
            release.set()
            outer.join(5)
            nested.join(5)
            self.assertFalse(outer.is_alive(), "outer writer deadlocked")
            self.assertFalse(nested.is_alive(), "nested writer deadlocked")
            self.assertEqual(outer_failures, [])
            self.assertEqual(len(nested_failures), 1)
            self.assertIsInstance(nested_failures[0], CollisionError)
            report = audit_bundle(output)
            self.assertTrue(report.ok, [issue.to_dict() for issue in report.issues])

    def test_store_verifies_untouched_versions_before_extension(self):
        adapter = FakeAdapter()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            lock = ArtifactStore().write(
                [adapter.fetch(ArtifactRef("owner", SLUG), "v1")], output
            )
            old_path = output / lock["versions"][0]["representations"][0]["path"]
            old_path.write_bytes(b"tampered")
            with self.assertRaises(CollisionError):
                ArtifactStore().write(
                    [adapter.fetch(ArtifactRef("owner", SLUG), "v2")], output
                )
            disk_lock = json.loads((output / LOCK_NAME).read_text())
            self.assertEqual([entry["version_id"] for entry in disk_lock["versions"]], ["v1"])

    def test_store_refuses_to_replace_an_existing_exact_version_snapshot(self):
        adapter = FakeAdapter()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            original = adapter.fetch(ArtifactRef("owner", SLUG), "v1")
            ArtifactStore().write([original], output)
            replacement = FetchedArtifact(
                artifact=original.artifact,
                version=original.version,
                representations=(
                    Representation(
                        label="replacement",
                        media_type="text/plain",
                        data=b"different exact-version snapshot",
                    ),
                ),
                provenance=original.provenance,
            )
            with self.assertRaises(CollisionError):
                ArtifactStore().write([replacement], output)
            lock = json.loads((output / LOCK_NAME).read_text())
            self.assertEqual(
                [rep["label"] for rep in lock["versions"][0]["representations"]],
                ["served"],
            )

    def test_store_rejects_deep_cyclic_and_nonfinite_provider_metadata(self):
        adapter = FakeAdapter()
        base = adapter.fetch(ArtifactRef("owner", SLUG), "v1")
        deep = {}
        cursor = deep
        for _ in range(1500):
            nested = {}
            cursor["x"] = nested
            cursor = nested
        cycle = {}
        cycle["self"] = cycle
        cases = (deep, cycle, {"score": float("nan")}, {"score": float("inf")})
        with tempfile.TemporaryDirectory() as temporary:
            for index, metadata in enumerate(cases):
                with self.subTest(index=index):
                    artifact = Artifact(
                        provider=base.artifact.provider,
                        artifact_id=base.artifact.artifact_id,
                        title=base.artifact.title,
                        kind=base.artifact.kind,
                        metadata=metadata,
                    )
                    item = FetchedArtifact(
                        artifact=artifact,
                        version=base.version,
                        representations=base.representations,
                    )
                    output = Path(temporary) / ("bundle-%d" % index)
                    with self.assertRaises(ValueError):
                        ArtifactStore().write([item], output)
                    self.assertFalse(output.exists())

    def test_store_redacts_signed_and_userinfo_urls_from_lock_metadata(self):
        adapter = FakeAdapter()
        base = adapter.fetch(ArtifactRef("owner", SLUG), "v1")
        artifact = Artifact(
            provider=base.artifact.provider,
            artifact_id=base.artifact.artifact_id,
            title=base.artifact.title,
            kind=base.artifact.kind,
            metadata={
                "download_url": "https://storage.invalid/item?X-Amz-Signature=LOCK-SIGNATURE",
                "source_url": "https://owner:LOCK-PASSWORD@example.invalid/item",
            },
        )
        item = FetchedArtifact(
            artifact=artifact,
            version=base.version,
            representations=base.representations,
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            ArtifactStore().write([item], output)
            serialized = (output / LOCK_NAME).read_text()

        self.assertNotIn("LOCK-SIGNATURE", serialized)
        self.assertNotIn("LOCK-PASSWORD", serialized)
        self.assertIn("[REDACTED]", serialized)

    def test_store_rejects_duplicate_manifest_object_names(self):
        adapter = FakeAdapter()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            ArtifactStore().write(
                [adapter.fetch(ArtifactRef("owner", SLUG), "v1")], output
            )
            lock_path = output / LOCK_NAME
            text = lock_path.read_text()
            marker = '"path": "'
            start = text.index(marker) + len(marker)
            end = text.index('"', start)
            real_path = text[start:end]
            text = text[: start - len(marker)] + (
                '"path": "../escape",\n          "path": "%s"' % real_path
            ) + text[end + 1 :]
            lock_path.write_text(text)
            with self.assertRaises(LockfileError):
                ArtifactStore().write(
                    [adapter.fetch(ArtifactRef("owner", SLUG), "v2")], output
                )

    def test_store_rejects_boolean_manifest_schema_version(self):
        adapter = FakeAdapter()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            ArtifactStore().write(
                [adapter.fetch(ArtifactRef("owner", SLUG), "v1")], output
            )
            lock_path = output / LOCK_NAME
            lock = json.loads(lock_path.read_text())
            lock["schema_version"] = True
            lock_path.write_text(json.dumps(lock))
            with self.assertRaises(LockfileError):
                ArtifactStore().write(
                    [adapter.fetch(ArtifactRef("owner", SLUG), "v2")], output
                )
            self.assertIs(json.loads(lock_path.read_text())["schema_version"], True)

    def test_store_rejects_non_nfkc_manifest_paths(self):
        adapter = FakeAdapter()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            lock = ArtifactStore().write(
                [adapter.fetch(ArtifactRef("owner", SLUG), "v1")], output
            )
            lock_path = output / LOCK_NAME
            original = output / lock["versions"][0]["representations"][0]["path"]
            compatibility_path = output / "Ａ.txt"
            original.rename(compatibility_path)
            lock["versions"][0]["representations"][0]["path"] = compatibility_path.name
            lock_path.write_text(json.dumps(lock))
            with self.assertRaises(UnsafePathError):
                ArtifactStore().write(
                    [adapter.fetch(ArtifactRef("owner", SLUG), "v2")], output
                )

    def test_strict_json_rejects_nonfinite_duplicate_and_oversize_numbers(self):
        for value in (
            '{"x":1,"x":2}',
            '{"x":NaN}',
            '{"x":Infinity}',
            '{"x":%s}' % ("9" * 300),
            '{"x":1e999}',
        ):
            with self.subTest(value=value[:40]):
                with self.assertRaises(ValueError):
                    strict_json_loads(value)

    def test_store_rolls_back_new_files_when_extension_fails(self):
        adapter = FakeAdapter()
        store = ArtifactStore()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            store.write([adapter.fetch(ArtifactRef("owner", SLUG), "v1")], output)
            before = {
                path.relative_to(output).as_posix()
                for path in output.rglob("*")
                if path.is_file()
            }
            original_create = store._atomic_create_at
            content_writes = 0

            def flaky_create(root_fd, relative, data, created_directories=None):
                nonlocal content_writes
                content_writes += 1
                if content_writes == 2:
                    raise OSError("simulated append failure")
                return original_create(
                    root_fd, relative, data, created_directories
                )

            with mock.patch.object(store, "_atomic_create_at", side_effect=flaky_create):
                with self.assertRaises(OSError):
                    store.write(
                        [
                            adapter.fetch(ArtifactRef("owner", SLUG), "v2"),
                            adapter.fetch(ArtifactRef("owner", SLUG), "v3"),
                        ],
                        output,
                    )
            after = {
                path.relative_to(output).as_posix()
                for path in output.rglob("*")
                if path.is_file()
            }
            self.assertEqual(after, before)
            disk_lock = json.loads((output / LOCK_NAME).read_text())
            self.assertEqual([entry["version_id"] for entry in disk_lock["versions"]], ["v1"])

    def test_store_rejects_deep_existing_lock_without_recursion_failure(self):
        adapter = FakeAdapter()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            output.mkdir()
            (output / LOCK_NAME).write_text("[" * 2000 + "0" + "]" * 2000)
            with self.assertRaises(LockfileError):
                ArtifactStore().write(
                    [adapter.fetch(ArtifactRef("owner", SLUG), "v1")], output
                )

    def test_store_rejects_wide_existing_lock_before_json_expansion(self):
        adapter = FakeAdapter()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            output.mkdir()
            wide = "[" + ",".join("{}" for _ in range(70000)) + "]"
            (output / LOCK_NAME).write_text(wide)
            with self.assertRaises(LockfileError):
                ArtifactStore().write(
                    [adapter.fetch(ArtifactRef("owner", SLUG), "v1")], output
                )

    def test_store_does_not_overwrite_a_path_created_after_preflight(self):
        adapter = FakeAdapter()
        store = ArtifactStore()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            store.write([adapter.fetch(ArtifactRef("owner", SLUG), "v1")], output)
            original_create = store._atomic_create_at
            victim = b"UNRELATED-CONCURRENT-DATA"

            def racing_create(root_fd, relative, data, created_directories=None):
                path = output / Path(relative)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(victim)
                return original_create(
                    root_fd, relative, data, created_directories
                )

            with mock.patch.object(store, "_atomic_create_at", side_effect=racing_create):
                with self.assertRaises(CollisionError):
                    store.write(
                        [adapter.fetch(ArtifactRef("owner", SLUG), "v2")], output
                    )
            new_files = [
                path
                for path in output.rglob("*")
                if path.is_file() and path.name != LOCK_NAME and path.read_bytes() == victim
            ]
            self.assertEqual(len(new_files), 1)

    def test_store_does_not_follow_a_parent_symlink_inserted_during_write(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        adapter = FakeAdapter()
        store = ArtifactStore()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            outside = Path(temporary) / "outside"
            outside.mkdir()
            store.write([adapter.fetch(ArtifactRef("owner", SLUG), "v1")], output)
            (output / "legacy-parent").symlink_to(
                outside, target_is_directory=True
            )
            root_fd = os.open(output, os.O_RDONLY)
            try:
                with self.assertRaises(UnsafePathError):
                    store._atomic_create_at(
                        root_fd, "legacy-parent/escaped.html", b"do not write"
                    )
            finally:
                os.close(root_fd)
            self.assertEqual(list(outside.iterdir()), [])
            lock = json.loads((output / LOCK_NAME).read_text())
            self.assertEqual([entry["version_id"] for entry in lock["versions"]], ["v1"])

    def test_store_rollback_preserves_a_preexisting_empty_parent_directory(self):
        adapter = FakeAdapter()
        store = ArtifactStore()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            store.write([adapter.fetch(ArtifactRef("owner", SLUG), "v1")], output)
            existing = json.loads((output / LOCK_NAME).read_text())
            addition = adapter.fetch(ArtifactRef("owner", SLUG), "v2")
            _, writes = store._build_lock([addition], existing)
            preexisting_parent = (output / Path(writes[0][0])).parent
            preexisting_parent.mkdir(parents=True, exist_ok=True)
            with mock.patch.object(
                store, "_atomic_replace_at", side_effect=OSError("manifest failure")
            ):
                with self.assertRaises(OSError):
                    store.write([addition], output)
            self.assertTrue(preexisting_parent.is_dir())

    def test_store_new_bundle_claim_never_replaces_an_appearing_directory(self):
        adapter = FakeAdapter()
        store = ArtifactStore()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            original_claim = store._claim_output_directory

            def racing_claim(parent_fd, name, display_path):
                os.mkdir(name, mode=0o700, dir_fd=parent_fd)
                victim_fd = os.open(name, os.O_RDONLY, dir_fd=parent_fd)
                try:
                    marker_fd = os.open(
                        "user-owned",
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600,
                        dir_fd=victim_fd,
                    )
                    os.close(marker_fd)
                finally:
                    os.close(victim_fd)
                return original_claim(parent_fd, name, display_path)

            with mock.patch.object(
                store, "_claim_output_directory", side_effect=racing_claim
            ):
                with self.assertRaises(CollisionError):
                    store.write(
                        [adapter.fetch(ArtifactRef("owner", SLUG), "v1")], output
                    )
            self.assertEqual((output / "user-owned").read_bytes(), b"")

    def test_store_new_bundle_claim_rejects_mkdir_open_replacement(self):
        adapter = FakeAdapter()
        store = ArtifactStore()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            real_open = os.open
            replaced = False

            def racing_open(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal replaced
                if path == output.name and dir_fd is not None and not replaced:
                    replaced = True
                    os.rmdir(path, dir_fd=dir_fd)
                    os.mkdir(path, mode=0o700, dir_fd=dir_fd)
                    replacement_fd = real_open(path, os.O_RDONLY, dir_fd=dir_fd)
                    try:
                        marker_fd = real_open(
                            "user-owned",
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                            0o600,
                            dir_fd=replacement_fd,
                        )
                        os.close(marker_fd)
                    finally:
                        os.close(replacement_fd)
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch("artifact_bridge.store.os.open", side_effect=racing_open):
                with self.assertRaises(UnsafePathError):
                    store.write(
                        [adapter.fetch(ArtifactRef("owner", SLUG), "v1")], output
                    )
            self.assertEqual((output / "user-owned").read_bytes(), b"")

    def test_store_new_bundle_rejects_a_swapped_parent_symlink(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        adapter = FakeAdapter()
        store = ArtifactStore()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            first = base / "first"
            second = base / "second"
            first.mkdir()
            second.mkdir()
            link = base / "selected"
            link.symlink_to(first, target_is_directory=True)
            output = link / "bundle"
            original_create = store._atomic_create_at
            swapped = False

            def swap_ancestor(root_fd, relative, data, created_directories=None):
                nonlocal swapped
                if not swapped:
                    swapped = True
                    link.unlink()
                    link.symlink_to(second, target_is_directory=True)
                return original_create(
                    root_fd, relative, data, created_directories
                )

            with mock.patch.object(store, "_atomic_create_at", side_effect=swap_ancestor):
                with self.assertRaises(UnsafePathError):
                    store.write(
                        [adapter.fetch(ArtifactRef("owner", SLUG), "v1")], output
                    )
            self.assertFalse((first / "bundle").exists())
            self.assertFalse((second / "bundle").exists())

    def test_store_manifest_compare_and_swap_rejects_a_concurrent_edit(self):
        adapter = FakeAdapter()
        store = ArtifactStore()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            store.write([adapter.fetch(ArtifactRef("owner", SLUG), "v1")], output)
            original_replace = store._atomic_replace_at
            lock_path = output / LOCK_NAME

            def racing_replace(root_fd, relative, data, expected):
                lock_path.write_bytes(lock_path.read_bytes() + b" ")
                return original_replace(root_fd, relative, data, expected)

            with mock.patch.object(
                store, "_atomic_replace_at", side_effect=racing_replace
            ):
                with self.assertRaises(CollisionError):
                    store.write(
                        [adapter.fetch(ArtifactRef("owner", SLUG), "v2")], output
                    )
            self.assertTrue(lock_path.read_bytes().endswith(b" "))
            tracked = json.loads(lock_path.read_text())
            self.assertEqual(
                [entry["version_id"] for entry in tracked["versions"]], ["v1"]
            )

    def test_store_path_swap_after_manifest_commit_preserves_moved_bundle(self):
        adapter = FakeAdapter()
        store = ArtifactStore()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            output = base / "bundle"
            moved = base / "moved"
            store.write([adapter.fetch(ArtifactRef("owner", SLUG), "v1")], output)
            original_replace = store._atomic_replace_at
            swapped = False

            def swap_output(root_fd, relative, data, expected):
                nonlocal swapped
                if not swapped:
                    swapped = True
                    output.rename(moved)
                    output.mkdir()
                    (output / "user-owned").write_bytes(b"keep")
                return original_replace(root_fd, relative, data, expected)

            with mock.patch.object(
                store, "_atomic_replace_at", side_effect=swap_output
            ):
                with self.assertRaises(UnsafePathError):
                    store.write(
                        [adapter.fetch(ArtifactRef("owner", SLUG), "v2")], output
                    )
            self.assertEqual((output / "user-owned").read_bytes(), b"keep")
            report = audit_bundle(moved)
            self.assertTrue(report.ok, [issue.to_dict() for issue in report.issues])
            lock = json.loads((moved / LOCK_NAME).read_text())
            self.assertEqual(
                {entry["version_id"] for entry in lock["versions"]}, {"v1", "v2"}
            )

    def test_store_caps_empty_directory_fanout_before_extension(self):
        adapter = FakeAdapter()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            ArtifactStore().write(
                [adapter.fetch(ArtifactRef("owner", SLUG), "v1")], output
            )
            baseline = sum(len(dirs) + len(files) for _, dirs, files in os.walk(output))
            for index in range(3):
                (output / ("empty-%d" % index)).mkdir()
            with mock.patch("artifact_bridge.store.MAX_BUNDLE_ENTRIES", baseline + 2):
                with self.assertRaises(LockfileError):
                    ArtifactStore().write(
                        [adapter.fetch(ArtifactRef("owner", SLUG), "v2")], output
                    )

    def test_concurrent_bundle_extensions_preserve_both_versions(self):
        adapter = FakeAdapter()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            ArtifactStore().write(
                [adapter.fetch(ArtifactRef("owner", SLUG), "v1")], output
            )
            additions = [
                adapter.fetch(ArtifactRef("owner", SLUG), "v2"),
                adapter.fetch(ArtifactRef("owner", SLUG), "v3"),
            ]
            start = threading.Barrier(3)
            failures = []

            def extend(item):
                try:
                    start.wait()
                    ArtifactStore().write([item], output)
                except Exception as exc:
                    failures.append(exc)

            threads = [threading.Thread(target=extend, args=(item,)) for item in additions]
            for thread in threads:
                thread.start()
            start.wait()
            for thread in threads:
                thread.join(5)
                self.assertFalse(thread.is_alive(), "bundle extension deadlocked")
            self.assertEqual(failures, [])
            lock = json.loads((output / LOCK_NAME).read_text())
            self.assertEqual(
                {entry["version_id"] for entry in lock["versions"]},
                {"v1", "v2", "v3"},
            )

    def test_new_bundle_claim_serializes_a_cooperating_extender(self):
        adapter = FakeAdapter()
        first_store = ArtifactStore()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            claimed = threading.Event()
            release = threading.Event()
            original_claim = first_store._claim_output_directory
            failures = []

            def paused_claim(parent_fd, name, display_path):
                directory_fd = original_claim(parent_fd, name, display_path)
                claimed.set()
                if not release.wait(5):
                    os.close(directory_fd)
                    raise RuntimeError("test timed out waiting to release initial writer")
                return directory_fd

            def write_first():
                try:
                    with mock.patch.object(
                        first_store,
                        "_claim_output_directory",
                        side_effect=paused_claim,
                    ):
                        first_store.write(
                            [adapter.fetch(ArtifactRef("owner", SLUG), "v1")],
                            output,
                        )
                except Exception as exc:
                    failures.append(exc)

            def write_second():
                try:
                    ArtifactStore().write(
                        [adapter.fetch(ArtifactRef("owner", SLUG), "v2")], output
                    )
                except Exception as exc:
                    failures.append(exc)

            first = threading.Thread(target=write_first)
            second = threading.Thread(target=write_second)
            first.start()
            self.assertTrue(claimed.wait(5), "initial writer did not claim output")
            second.start()
            release.set()
            first.join(5)
            second.join(5)
            self.assertFalse(first.is_alive(), "initial bundle writer deadlocked")
            self.assertFalse(second.is_alive(), "bundle extender deadlocked")
            self.assertEqual(failures, [])
            lock = json.loads((output / LOCK_NAME).read_text())
            self.assertEqual(
                {entry["version_id"] for entry in lock["versions"]}, {"v1", "v2"}
            )

    def test_parent_lock_serializes_before_the_new_root_lock(self):
        adapter = FakeAdapter()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            before_root_lock = threading.Event()
            release = threading.Event()
            failures = []
            real_flock = fcntl.flock
            first_exclusive_calls = 0

            def paused_flock(fd, operation):
                nonlocal first_exclusive_calls
                if (
                    threading.current_thread().name == "initial-writer"
                    and operation == fcntl.LOCK_EX
                ):
                    first_exclusive_calls += 1
                    if first_exclusive_calls == 2:
                        before_root_lock.set()
                        if not release.wait(5):
                            raise RuntimeError("test timed out before root lock")
                return real_flock(fd, operation)

            def writer(version):
                try:
                    ArtifactStore().write(
                        [adapter.fetch(ArtifactRef("owner", SLUG), version)], output
                    )
                except Exception as exc:
                    failures.append(exc)

            with mock.patch("artifact_bridge.store.fcntl.flock", side_effect=paused_flock):
                first = threading.Thread(
                    target=writer, args=("v1",), name="initial-writer"
                )
                second = threading.Thread(
                    target=writer, args=("v2",), name="extending-writer"
                )
                first.start()
                self.assertTrue(
                    before_root_lock.wait(5), "initial writer did not reach root lock"
                )
                second.start()
                release.set()
                first.join(5)
                second.join(5)
            self.assertFalse(first.is_alive(), "initial writer deadlocked")
            self.assertFalse(second.is_alive(), "extending writer deadlocked")
            self.assertEqual(failures, [])
            lock = json.loads((output / LOCK_NAME).read_text())
            self.assertEqual(
                {entry["version_id"] for entry in lock["versions"]}, {"v1", "v2"}
            )

    def test_store_rejects_foreign_version_identity_in_existing_lock(self):
        adapter = FakeAdapter()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            ArtifactStore().write(
                [adapter.fetch(ArtifactRef("owner", SLUG), "v1")], output
            )
            lock_path = output / LOCK_NAME
            lock = json.loads(lock_path.read_text())
            lock["versions"][0]["provider"] = "compliance"
            lock["versions"][0]["artifact_id"] = OTHER_SLUG
            lock_path.write_text(json.dumps(lock))
            with self.assertRaises(LockfileError):
                ArtifactStore().write(
                    [adapter.fetch(ArtifactRef("owner", SLUG), "v2")], output
                )

    def test_cli_pull_and_cat_are_offline_and_deterministic(self):
        adapter = FakeAdapter()
        client = BridgeClient([adapter])
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            stdout = io.StringIO()
            stderr = io.StringIO()
            status = main(
                ["pull", SLUG, "--version", "v1", "-o", str(output), "--json"],
                client=client,
                stdout=stdout,
                stderr=stderr,
            )
            self.assertEqual(status, 0, stderr.getvalue())
            self.assertEqual(json.loads(stdout.getvalue())["versions"], ["v1"])
            cat_out = io.StringIO()
            self.assertEqual(
                main(
                    ["cat", SLUG, "--version", "v1"],
                    client=client,
                    stdout=cat_out,
                    stderr=stderr,
                ),
                0,
            )
            self.assertEqual(cat_out.getvalue(), "first\nline\n")

    def test_cli_diff_escapes_terminal_control_sequences(self):
        adapter = FakeAdapter()
        stdout = io.StringIO()
        status = main(
            [
                "diff",
                SLUG,
                "--from-version",
                "escape-a",
                "--to-version",
                "escape-b",
            ],
            client=BridgeClient([adapter]),
            stdout=stdout,
            stderr=io.StringIO(),
        )
        self.assertEqual(status, 0)
        self.assertNotIn("\x1b", stdout.getvalue())
        self.assertIn("\\x1b", stdout.getvalue())

    def test_cli_plain_and_json_outputs_escape_c1_terminal_controls(self):
        class C1Metadata(FakeAdapter):
            def _artifact(self, ref):
                artifact = super()._artifact(ref)
                return Artifact(
                    provider=artifact.provider,
                    artifact_id=artifact.artifact_id,
                    title="title\u009b2Jspoof",
                    live_version=artifact.live_version,
                    published_version=artifact.published_version,
                    kind=artifact.kind,
                )

        client = BridgeClient([C1Metadata()])
        plain = io.StringIO()
        self.assertEqual(
            main(
                ["--adapter", "owner", "list"],
                client=client,
                stdout=plain,
                stderr=io.StringIO(),
            ),
            0,
        )
        self.assertNotIn("\u009b", plain.getvalue())
        self.assertIn("\\x9b", plain.getvalue())
        structured = io.StringIO()
        self.assertEqual(
            main(
                ["inspect", SLUG],
                client=client,
                stdout=structured,
                stderr=io.StringIO(),
            ),
            0,
        )
        self.assertNotIn("\u009b", structured.getvalue())
        self.assertIn("\\u009b", structured.getvalue())

    def test_cli_local_audit_constructs_no_remote_adapters(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch(
            "artifact_bridge.cli.OwnerFrameAdapter",
            side_effect=AssertionError("owner adapter should not be constructed"),
        ), mock.patch(
            "artifact_bridge.cli.AnthropicComplianceAdapter",
            side_effect=AssertionError("compliance adapter should not be constructed"),
        ), mock.patch.dict(
            os.environ,
            {"ANTHROPIC_COMPLIANCE_ACCESS_KEY": "bad\nkey"},
        ):
            stdout = io.StringIO()
            stderr = io.StringIO()
            status = main(
                ["audit", str(Path(temporary) / "missing"), "--json"],
                stdout=stdout,
                stderr=stderr,
            )
            self.assertEqual(status, 1)
            self.assertEqual(stderr.getvalue(), "")
            self.assertFalse(json.loads(stdout.getvalue())["ok"])
            plain = io.StringIO()
            status = main(
                ["audit", str(Path(temporary) / "missing")],
                stdout=plain,
                stderr=io.StringIO(),
            )
            self.assertEqual(status, 1)
            self.assertIn("failed:", plain.getvalue())

    def test_cli_json_audit_coalesces_hostile_issue_fanout(self):
        adapter = FakeAdapter()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            ArtifactStore().write(
                [adapter.fetch(ArtifactRef("owner", SLUG), "v1")], output
            )
            lock_path = output / LOCK_NAME
            lock = json.loads(lock_path.read_text())
            lock["artifact"]["metadata"] = {
                "token%05d" % index: "value" for index in range(14000)
            }
            lock_path.write_text(json.dumps(lock))
            stdout = io.StringIO()
            stderr = io.StringIO()
            status = main(
                ["audit", str(output), "--json"],
                stdout=stdout,
                stderr=stderr,
            )
            self.assertEqual(status, 1)
            self.assertEqual(stderr.getvalue(), "")
            report = json.loads(stdout.getvalue())
            self.assertLessEqual(len(report["issues"]), 1024)
            self.assertIn("limit", {issue["code"] for issue in report["issues"]})

    def test_cli_explicit_and_inferred_owner_ignore_malformed_compliance_env(self):
        with mock.patch(
            "artifact_bridge.cli.OwnerFrameAdapter", return_value=FakeAdapter()
        ), mock.patch.dict(
            os.environ,
            {"ANTHROPIC_COMPLIANCE_ACCESS_KEY": "bad\nkey"},
        ):
            for argv in (
                ["--adapter", "owner", "auth", "status", "--json"],
                ["inspect", SLUG],
            ):
                with self.subTest(argv=argv):
                    stdout = io.StringIO()
                    stderr = io.StringIO()
                    status = main(argv, stdout=stdout, stderr=stderr)
                    self.assertEqual(status, 0, stderr.getvalue())

    def test_cli_closes_partially_constructed_adapters_on_failure(self):
        owner = FakeAdapter()
        owner.closed = 0
        owner.close = lambda: setattr(owner, "closed", owner.closed + 1)
        with mock.patch(
            "artifact_bridge.cli.OwnerFrameAdapter", return_value=owner
        ), mock.patch(
            "artifact_bridge.cli.AnthropicComplianceAdapter",
            side_effect=ValueError("malformed compliance credential"),
        ):
            stderr = io.StringIO()
            status = main(
                ["auth", "status", "--json"],
                stdout=io.StringIO(),
                stderr=stderr,
            )
        self.assertEqual(status, 1)
        self.assertEqual(owner.closed, 1)
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_cli_audit_applies_configured_byte_limits(self):
        adapter = FakeAdapter()
        fetched = adapter.fetch(ArtifactRef("owner", SLUG), "v1")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            ArtifactStore().write([fetched], output)
            stdout = io.StringIO()
            status = main(
                ["--max-bytes", "4", "audit", str(output), "--json"],
                client=BridgeClient([adapter]),
                stdout=stdout,
                stderr=io.StringIO(),
            )
            self.assertEqual(status, 1)
            report = json.loads(stdout.getvalue())
            self.assertFalse(report["ok"])
            self.assertIn("limit", {issue["code"] for issue in report["issues"]})

    def test_cli_redacts_credentials_from_errors(self):
        class Failing(FakeAdapter):
            def inspect(self, ref):
                raise AdapterError('server said {"assetToken":"DO-NOT-PRINT"}')

        stderr = io.StringIO()
        status = main(
            ["inspect", SLUG],
            client=BridgeClient([Failing()]),
            stdout=io.StringIO(),
            stderr=stderr,
        )
        self.assertEqual(status, 1)
        self.assertNotIn("DO-NOT-PRINT", stderr.getvalue())
        self.assertIn("[REDACTED]", stderr.getvalue())

    def test_mirror_default_sanitizes_malicious_standard_stable_id(self):
        class MaliciousStandard(FakeAdapter):
            def fetch(self, ref, version):
                fetched = super().fetch(ref, version)
                artifact = Artifact(
                    provider="compliance",
                    artifact_id="../../escaped",
                    title="Untrusted",
                    kind="standard",
                )
                return FetchedArtifact(
                    artifact=artifact,
                    version=ArtifactVersion(
                        "compliance", artifact.artifact_id, fetched.version.version_id
                    ),
                    representations=fetched.representations,
                )

        client = BridgeClient([MaliciousStandard("compliance")])
        original = os.getcwd()
        with tempfile.TemporaryDirectory() as temporary:
            os.chdir(temporary)
            try:
                stdout = io.StringIO()
                stderr = io.StringIO()
                result = main(
                    ["mirror", "claude_artifact_version_01AbCdEf", "--json"],
                    client=client,
                    stdout=stdout,
                    stderr=stderr,
                )
                self.assertEqual(result, 0, stderr.getvalue())
                output = Path(json.loads(stdout.getvalue())["output"])
                self.assertEqual(output.parent, Path("."))
                self.assertNotIn("..", output.name)
                self.assertEqual(output.resolve().parent, Path(temporary).resolve())
                self.assertTrue((output / LOCK_NAME).is_file())
            finally:
                os.chdir(original)


if __name__ == "__main__":
    unittest.main()
