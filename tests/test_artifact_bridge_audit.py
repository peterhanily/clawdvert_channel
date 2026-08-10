import json
import os
import tempfile
import unicodedata
import unittest
from pathlib import Path
from unittest import mock

from artifact_bridge.audit import (
    MAX_AUDIT_JSON_DEPTH,
    MAX_AUDIT_STRUCTURE_NODES,
    MAX_STATIC_INSPECTION_BYTES,
    audit_bundle,
)
from artifact_bridge.errors import LockfileError, ResponseTooLargeError
from artifact_bridge.models import (
    Artifact,
    ArtifactVersion,
    FetchedArtifact,
    Representation,
)
from artifact_bridge.store import (
    DEFAULT_MAX_REPRESENTATION_BYTES,
    LOCK_NAME,
    MAX_LOCK_BYTES,
    ArtifactStore,
)


def fetched(
    version="v1",
    data=b"plain text",
    metadata=None,
    artifact_id="artifact-1",
    title="Fixture",
    suggested_name="artifact.txt",
):
    artifact = Artifact(
        provider="fixture",
        artifact_id=artifact_id,
        title=title,
        metadata=metadata or {},
    )
    artifact_version = ArtifactVersion(
        provider="fixture",
        artifact_id=artifact_id,
        version_id=version,
    )
    return FetchedArtifact(
        artifact=artifact,
        version=artifact_version,
        representations=(
            Representation(
                label="stored",
                media_type="text/plain; charset=utf-8",
                data=data,
                suggested_name=suggested_name,
            ),
        ),
    )


class ArtifactAuditTests(unittest.TestCase):
    def test_clean_bundle_verifies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            ArtifactStore().write([fetched()], root)
            report = audit_bundle(root)
            self.assertTrue(report.ok)
            self.assertEqual(report.representations, 1)
            self.assertEqual(report.issues, ())

    def test_static_indicators_are_warnings_without_executing_content(self):
        content = (
            b'<script>fetch("https://example.test/"); localStorage.x = "y"; '
            b'document.body.innerHTML = "x";</script>'
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            ArtifactStore().write([fetched(data=content)], root)
            report = audit_bundle(root)
            self.assertTrue(report.ok)
            codes = {issue.code for issue in report.issues}
            self.assertTrue({"script", "network-api", "browser-storage", "dom-html-sink"} <= codes)
            self.assertTrue(all(issue.severity == "warning" for issue in report.issues))

    def test_changed_file_and_bearer_shaped_content_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            lock = ArtifactStore().write([fetched(data=b"Bearer abc.def.ghi")], root)
            relative = lock["versions"][0]["representations"][0]["path"]
            target = root / relative
            target.write_bytes(b"Bearer changed.secret.value")
            report = audit_bundle(root)
            self.assertFalse(report.ok)
            codes = {issue.code for issue in report.issues}
            self.assertIn("sha256", codes)
            self.assertIn("content-credential", codes)
            rendered = json.dumps(report.to_dict())
            self.assertNotIn("changed.secret.value", rendered)

    def test_duplicate_casefolded_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            ArtifactStore().write([fetched()], root)
            lock_path = root / LOCK_NAME
            lock = json.loads(lock_path.read_text())
            original = lock["versions"][0]["representations"][0]
            alias = dict(original)
            alias["label"] = "alias"
            alias["path"] = original["path"].upper()
            lock["versions"][0]["representations"].append(alias)
            lock_path.write_text(json.dumps(lock))
            report = audit_bundle(root)
            self.assertFalse(report.ok)
            self.assertIn("duplicate-path", {issue.code for issue in report.issues})

    def test_noncanonical_posix_path_alias_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            ArtifactStore().write([fetched()], root)
            lock_path = root / LOCK_NAME
            lock = json.loads(lock_path.read_text())
            original = lock["versions"][0]["representations"][0]
            alias = dict(original)
            alias["label"] = "alias"
            alias["path"] = "./" + original["path"]
            lock["versions"][0]["representations"].append(alias)
            lock_path.write_text(json.dumps(lock))

            report = audit_bundle(root)

            self.assertFalse(report.ok)
            codes = {issue.code for issue in report.issues}
            self.assertIn("path", codes)
            self.assertIn("duplicate-path", codes)

    def test_float_schema_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            ArtifactStore().write([fetched()], root)
            lock_path = root / LOCK_NAME
            lock = json.loads(lock_path.read_text())
            lock["schema_version"] = 1.0
            lock_path.write_text(json.dumps(lock))

            report = audit_bundle(root)

            self.assertFalse(report.ok)
            self.assertIn("schema", {issue.code for issue in report.issues})

    def test_duplicate_json_object_names_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            ArtifactStore().write([fetched()], root)
            lock_path = root / LOCK_NAME
            text = lock_path.read_text()
            marker = '"path": "'
            start = text.index(marker) + len(marker)
            end = text.index('"', start)
            real_path = text[start:end]
            text = text[: start - len(marker)] + (
                '"path": "../escape",\n          "path": "%s"' % real_path
            ) + text[end + 1 :]
            lock_path.write_text(text)

            report = audit_bundle(root)

            self.assertFalse(report.ok)
            self.assertIn("lock-invalid", {issue.code for issue in report.issues})

    def test_nonfinite_json_number_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            ArtifactStore().write([fetched()], root)
            lock_path = root / LOCK_NAME
            text = lock_path.read_text().replace(
                '"metadata": {},', '"metadata": {"score": NaN},', 1
            )
            lock_path.write_text(text)

            report = audit_bundle(root)

            self.assertFalse(report.ok)
            self.assertIn("lock-invalid", {issue.code for issue in report.issues})

    def test_unicode_normalization_path_alias_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            ArtifactStore().write([fetched()], root)
            lock_path = root / LOCK_NAME
            lock = json.loads(lock_path.read_text())
            original = lock["versions"][0]["representations"][0]
            original_path = Path(original["path"])
            composed_path = original_path.with_name("caf\N{LATIN SMALL LETTER E WITH ACUTE}.txt")
            (root / original_path).rename(root / composed_path)
            original["path"] = composed_path.as_posix()
            alias = dict(original)
            alias["label"] = "alias"
            alias["path"] = unicodedata.normalize("NFD", composed_path.as_posix())
            lock["versions"][0]["representations"].append(alias)
            lock_path.write_text(json.dumps(lock))

            report = audit_bundle(root)

            self.assertFalse(report.ok)
            codes = {issue.code for issue in report.issues}
            self.assertIn("duplicate-path", codes)
            self.assertIn("path", codes)

    def test_deep_lock_returns_a_bounded_failed_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            root.mkdir()
            depth = max(MAX_AUDIT_JSON_DEPTH + 1, 2000)
            raw = (
                '{"schema_version":1,"versions":[],"nested":'
                + "[" * depth
                + "0"
                + "]" * depth
                + "}"
            )
            self.assertLess(len(raw.encode("utf-8")), MAX_LOCK_BYTES)
            (root / LOCK_NAME).write_text(raw)

            report = audit_bundle(root)

            self.assertFalse(report.ok)
            self.assertEqual(report.representations, 0)
            self.assertIn("limit", {issue.code for issue in report.issues})

    def test_lock_structure_traversal_has_a_node_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            root.mkdir()
            lock = {
                "schema_version": 1,
                "versions": [],
                "metadata": [0] * (MAX_AUDIT_STRUCTURE_NODES + 1),
            }
            raw = json.dumps(lock)
            self.assertLess(len(raw.encode("utf-8")), MAX_LOCK_BYTES)
            (root / LOCK_NAME).write_text(raw)

            report = audit_bundle(root)

            self.assertFalse(report.ok)
            self.assertIn("limit", {issue.code for issue in report.issues})

    def test_duplicate_version_ids_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            ArtifactStore().write([fetched()], root)
            lock_path = root / LOCK_NAME
            lock = json.loads(lock_path.read_text())
            duplicate = dict(lock["versions"][0])
            duplicate["representations"] = []
            lock["versions"].append(duplicate)
            lock_path.write_text(json.dumps(lock))

            report = audit_bundle(root)

            self.assertFalse(report.ok)
            self.assertIn("duplicate-version", {issue.code for issue in report.issues})

    def test_artifact_identity_is_required_and_versions_must_match(self):
        mutations = (
            ("missing-artifact", lambda lock: lock.pop("artifact")),
            ("empty-versions", lambda lock: lock.__setitem__("versions", [])),
            (
                "provider-mismatch",
                lambda lock: lock["versions"][0].__setitem__("provider", "other"),
            ),
            (
                "artifact-id-mismatch",
                lambda lock: lock["versions"][0].__setitem__("artifact_id", "other"),
            ),
            (
                "credential-shaped-provider",
                lambda lock: lock["artifact"].__setitem__(
                    "provider", "Bearer abc.def.ghi"
                ),
            ),
        )
        for name, mutate in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "bundle"
                ArtifactStore().write([fetched()], root)
                lock_path = root / LOCK_NAME
                lock = json.loads(lock_path.read_text())
                mutate(lock)
                lock_path.write_text(json.dumps(lock))

                report = audit_bundle(root)

                self.assertFalse(report.ok)
                self.assertIn("schema", {issue.code for issue in report.issues})

    def test_symlinked_parent_is_not_followed(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            lock = ArtifactStore().write([fetched()], root)
            relative = Path(lock["versions"][0]["representations"][0]["path"])
            outside = Path(directory) / "outside"
            outside.mkdir()
            (outside / relative.name).write_bytes((root / relative).read_bytes())
            (root / relative).unlink()
            legacy = root / "legacy"
            legacy.symlink_to(outside, target_is_directory=True)
            lock["versions"][0]["representations"][0]["path"] = (
                "legacy/" + relative.name
            )
            (root / LOCK_NAME).write_text(json.dumps(lock))
            report = audit_bundle(root)
            self.assertFalse(report.ok)
            self.assertIn("path", {issue.code for issue in report.issues})

    def test_sparse_oversize_file_is_not_hashed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            lock = ArtifactStore().write([fetched()], root)
            relative = lock["versions"][0]["representations"][0]["path"]
            with (root / relative).open("r+b") as handle:
                handle.truncate(DEFAULT_MAX_REPRESENTATION_BYTES + 1)
            report = audit_bundle(root)
            self.assertFalse(report.ok)
            self.assertIn("limit", {issue.code for issue in report.issues})

    def test_empty_directories_count_toward_filesystem_entry_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "bundle"
            ArtifactStore().write([fetched()], root)
            baseline = sum(len(dirs) + len(files) for _, dirs, files in os.walk(root))
            for index in range(3):
                (root / ("empty-%d" % index)).mkdir()
            with mock.patch("artifact_bridge.audit.MAX_AUDIT_FILES", baseline + 2):
                report = audit_bundle(root)
            self.assertFalse(report.ok)
            self.assertIn("limit", {issue.code for issue in report.issues})

    def test_audit_byte_limits_are_configurable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "per-representation"
            ArtifactStore().write([fetched(data=b"four")], root)
            report = audit_bundle(
                root,
                max_representation_bytes=3,
                max_total_bytes=100,
            )
            self.assertFalse(report.ok)
            self.assertIn("limit", {issue.code for issue in report.issues})

            total_root = Path(directory) / "total"
            ArtifactStore().write(
                [fetched("v1", b"ab"), fetched("v2", b"cd")],
                total_root,
            )
            report = audit_bundle(
                total_root,
                max_representation_bytes=10,
                max_total_bytes=3,
            )
            self.assertFalse(report.ok)
            self.assertIn("limit", {issue.code for issue in report.issues})

    def test_static_inspection_is_prefix_bounded_and_detects_external_resources(self):
        external = b'<img src="https://example.test/pixel.png">'
        padding_size = MAX_STATIC_INSPECTION_BYTES - len(external)
        repeated_open_tags = (b"<img " * ((padding_size // 5) + 1))[:padding_size]
        content = external + repeated_open_tags + b"<script>alert(1)</script>"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            ArtifactStore().write([fetched(data=content)], root)

            report = audit_bundle(root)

            self.assertTrue(report.ok)
            codes = {issue.code for issue in report.issues}
            self.assertIn("external-resource", codes)
            self.assertIn("static-limit", codes)
            self.assertNotIn("script", codes)

    def test_credential_detection_covers_text_after_static_prefix(self):
        content = (
            b"A" * (MAX_STATIC_INSPECTION_BYTES + 1)
            + b" Bearer abc.def.ghi"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            ArtifactStore().write([fetched(data=content)], root)

            report = audit_bundle(root)

            self.assertFalse(report.ok)
            codes = {issue.code for issue in report.issues}
            self.assertIn("content-credential", codes)
            self.assertIn("static-limit", codes)


class ArtifactStoreBoundsTests(unittest.TestCase):
    def test_existing_and_new_versions_share_one_total_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            store = ArtifactStore(max_representation_bytes=3, max_total_bytes=3)
            store.write([fetched("v1", b"ab")], root)
            with self.assertRaises(ResponseTooLargeError):
                store.write([fetched("v2", b"cd")], root)

    def test_generated_lock_is_bounded_before_output_is_created(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            oversized = "x" * (MAX_LOCK_BYTES + 1024)
            with self.assertRaises(LockfileError):
                ArtifactStore().write([fetched(metadata={"notes": oversized})], root)
            self.assertFalse(root.exists())

    def test_credential_shaped_identity_is_rejected_before_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            with self.assertRaises(LockfileError):
                ArtifactStore().write(
                    [fetched(artifact_id="Bearer abc.def.ghi")],
                    root,
                )
            self.assertFalse(root.exists())

    def test_credential_shaped_filename_is_redacted_before_path_derivation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            secret_name = "report-sk-ant-supersecret.html"
            lock = ArtifactStore().write(
                [fetched(title=secret_name, suggested_name=secret_name)],
                root,
            )
            serialized = json.loads((root / LOCK_NAME).read_text())
            self.assertEqual(lock, serialized)
            path = lock["versions"][0]["representations"][0]["path"]
            self.assertNotIn("supersecret", path)
            self.assertNotIn("sk-ant", path)
            self.assertTrue((root / path).is_file())


if __name__ == "__main__":
    unittest.main()
