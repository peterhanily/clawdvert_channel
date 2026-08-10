"""Offline tests for the official Anthropic Compliance adapter."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
import os
import traceback
import unittest
import urllib.parse
from unittest import mock

from artifact_bridge.adapters.compliance import AnthropicComplianceAdapter
from artifact_bridge.client import BridgeClient
from artifact_bridge.errors import (
    AdapterError,
    AuthenticationError,
    IntegrityError,
    ResponseTooLargeError,
    StaleVersionError,
    TruncatedResponseError,
    VersionNotFoundError,
)
from artifact_bridge.models import ArtifactRef


def _json_response(value, *, status=200, headers=None):
    body = json.dumps(value).encode("utf-8")
    values = {"Content-Type": "application/json"}
    if headers:
        values.update(headers)
    return FakeResponse(body, status=status, headers=values)


class FakeResponse:
    def __init__(self, body=b"", *, status=200, headers=None, final_url=None, read_error=None):
        self.status = status
        self.headers = dict(headers or {})
        self._body = io.BytesIO(body)
        self._final_url = final_url
        self._read_error = read_error
        self.closed = False
        self.read_calls = 0

    def read(self, size=-1):
        self.read_calls += 1
        if self._read_error is not None:
            error, self._read_error = self._read_error, None
            raise error
        return self._body.read(size)

    def getcode(self):
        return self.status

    def geturl(self):
        return self._final_url

    def close(self):
        self.closed = True


class FakeOpener:
    def __init__(self, *actions):
        self.actions = list(actions)
        self.requests = []
        self.timeouts = []

    def open(self, request, timeout=None):
        self.requests.append(request)
        self.timeouts.append(timeout)
        if not self.actions:
            raise AssertionError("unexpected HTTP request: %s" % request.full_url)
        action = self.actions.pop(0)
        if isinstance(action, BaseException):
            raise action
        if action._final_url is None:
            action._final_url = request.full_url
        return action


def _headers(request):
    return {key.lower(): value for key, value in request.header_items()}


def _query(request):
    return urllib.parse.parse_qs(
        urllib.parse.urlsplit(request.full_url).query,
        keep_blank_values=True,
    )


class ComplianceAuthenticationTests(unittest.TestCase):
    def test_only_compliance_environment_key_is_used(self):
        with mock.patch.dict(
            os.environ,
            {"ANTHROPIC_API_KEY": "sk-ant-api03-not-compliance"},
            clear=True,
        ):
            adapter = AnthropicComplianceAdapter(opener=FakeOpener())
            status = adapter.auth_status()
        self.assertFalse(status.authenticated)
        self.assertIsNone(status.source)
        with self.assertRaises(AuthenticationError):
            adapter.list_code_artifact_records()

    def test_injected_key_uses_x_api_key_and_never_authorization(self):
        opener = FakeOpener(_json_response({"data": []}))
        adapter = AnthropicComplianceAdapter(access_key="injected-test-key", opener=opener)

        self.assertEqual(adapter.list_code_artifact_records(), [])

        headers = _headers(opener.requests[0])
        self.assertEqual(headers["x-api-key"], "injected-test-key")
        self.assertNotIn("authorization", headers)
        self.assertEqual(opener.requests[0].get_method(), "GET")
        self.assertEqual(adapter.auth_status().source, "injected")

    def test_origin_is_pinned_to_anthropic_https(self):
        invalid = (
            "http://api.anthropic.com",
            "https://example.com",
            "https://api.anthropic.com.evil.test",
            "https://user@api.anthropic.com",
            "https://api.anthropic.com/v1",
            "https://api.anthropic.com?target=elsewhere",
        )
        for origin in invalid:
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                AnthropicComplianceAdapter(access_key="test", base_url=origin, opener=FakeOpener())

    def test_changed_final_url_is_rejected_as_redirect(self):
        response = _json_response({"data": []})
        response._final_url = "https://example.com/redirected"
        adapter = AnthropicComplianceAdapter(access_key="test", opener=FakeOpener(response))

        with self.assertRaisesRegex(AdapterError, "redirects are not allowed"):
            adapter.list_code_artifact_records()
        self.assertTrue(response.closed)


class CompliancePaginationTests(unittest.TestCase):
    def test_empty_page_with_next_page_is_followed_and_filters_are_exact(self):
        opener = FakeOpener(
            _json_response({"data": [], "has_more": False, "next_page": "opaque+/="}),
            _json_response(
                {
                    "data": [
                        {
                            "id": "cart_01",
                            "published_version_id": "v1",
                            "future_field": {"kept": True},
                        }
                    ]
                }
            ),
        )
        adapter = AnthropicComplianceAdapter(access_key="test", opener=opener)

        records = adapter.list_code_artifact_records(
            limit=100,
            organization_ids=["org_a", "org_b"],
            user_id="user_a",
            updated_at={"gte": "2026-08-01T00:00:00Z"},
            updated_at_lt="2026-08-09T00:00:00Z",
        )

        self.assertEqual([item["id"] for item in records], ["cart_01"])
        self.assertTrue(records[0]["future_field"]["kept"])
        self.assertEqual(len(opener.requests), 2)
        first, second = map(_query, opener.requests)
        self.assertEqual(first["limit"], ["100"])
        self.assertEqual(first["organization_ids[]"], ["org_a", "org_b"])
        self.assertEqual(first["user_ids[]"], ["user_a"])
        self.assertEqual(first["updated_at.gte"], ["2026-08-01T00:00:00Z"])
        self.assertEqual(first["updated_at.lt"], ["2026-08-09T00:00:00Z"])
        self.assertNotIn("page", first)
        self.assertEqual(second["page"], ["opaque+/="])

    def test_model_list_deduplicates_page_overlap(self):
        first = {
            "id": "cart_duplicate",
            "published_version_id": "v1",
            "versions": [{"id": "v1", "name": "First title"}],
        }
        duplicate = dict(first, unexpected="forward compatible")
        second = {"id": "cart_second", "versions": []}
        opener = FakeOpener(
            _json_response({"data": [first], "next_page": "next"}),
            _json_response({"data": [duplicate, second]}),
        )
        adapter = AnthropicComplianceAdapter(access_key="test", opener=opener)

        artifacts = adapter.list_artifacts()

        self.assertEqual([item.artifact_id for item in artifacts], ["cart_duplicate", "cart_second"])
        self.assertEqual(artifacts[0].title, "First title")
        self.assertIsNone(artifacts[0].live_version)
        self.assertEqual(artifacts[0].published_version, "v1")

    def test_repeated_initial_page_token_is_rejected(self):
        opener = FakeOpener(_json_response({"data": [], "next_page": "resume-token"}))
        adapter = AnthropicComplianceAdapter(access_key="test", opener=opener)

        with self.assertRaisesRegex(AdapterError, "repeated a pagination token"):
            adapter.list_code_artifact_records(page="resume-token")

    def test_page_limit_is_capped_at_official_maximum(self):
        adapter = AnthropicComplianceAdapter(access_key="test", opener=FakeOpener())
        for invalid in (0, 101, True, 1.5):
            with self.subTest(limit=invalid), self.assertRaises(ValueError):
                adapter.list_code_artifact_records(limit=invalid)

    def test_unique_unending_page_tokens_are_bounded(self):
        opener = FakeOpener(
            _json_response({"data": [], "next_page": "unique-page-1"}),
            _json_response({"data": [], "next_page": "unique-page-2"}),
            _json_response({"data": [], "next_page": "unique-page-3"}),
        )
        adapter = AnthropicComplianceAdapter(
            access_key="test",
            opener=opener,
            max_pages=3,
        )

        with self.assertRaisesRegex(AdapterError, "configured pagination limit"):
            adapter.list_code_artifact_records()

        self.assertEqual(len(opener.requests), 3)
        self.assertNotIn("page", _query(opener.requests[0]))
        self.assertEqual(_query(opener.requests[1])["page"], ["unique-page-1"])
        self.assertEqual(_query(opener.requests[2])["page"], ["unique-page-2"])

    def test_max_pages_configuration_is_strictly_bounded(self):
        for invalid in (0, -1, 1001, True, 1.5, "3"):
            with self.subTest(max_pages=invalid), self.assertRaises(ValueError):
                AnthropicComplianceAdapter(
                    access_key="test",
                    opener=FakeOpener(),
                    max_pages=invalid,
                )

    def test_page_data_is_a_strict_list_of_records_before_yielding(self):
        invalid_pages = (
            ("missing", {}),
            ("not-a-list", {"data": {"id": "cart_01"}}),
            ("mixed", {"data": [{"id": "cart_01"}, "not-an-object"]}),
            ("missing-id", {"data": [{}]}),
            ("empty-id", {"data": [{"id": ""}]}),
            ("non-string-id", {"data": [{"id": 1}]}),
        )
        for label, payload in invalid_pages:
            with self.subTest(label=label):
                adapter = AnthropicComplianceAdapter(
                    access_key="test",
                    opener=FakeOpener(_json_response(payload)),
                )
                iterator = adapter.iter_code_artifact_records()

                with self.assertRaisesRegex(AdapterError, "data list"):
                    next(iterator)

    def test_page_tokens_have_a_bounded_encoded_size(self):
        oversized = "x" * 8193
        opener = FakeOpener(_json_response({"data": [], "next_page": oversized}))
        adapter = AnthropicComplianceAdapter(access_key="test", opener=opener)

        with self.assertRaisesRegex(AdapterError, "pagination token"):
            adapter.list_code_artifact_records()
        self.assertEqual(len(opener.requests), 1)

        without_request = FakeOpener()
        adapter = AnthropicComplianceAdapter(access_key="test", opener=without_request)
        with self.assertRaisesRegex(ValueError, "page token"):
            adapter.list_code_artifact_records(page=oversized)
        self.assertEqual(without_request.requests, [])


class ComplianceMetadataValidationTests(unittest.TestCase):
    def test_retained_versions_are_a_strict_unique_list(self):
        missing = object()
        invalid_lists = (
            ("missing-list", missing),
            ("not-a-list", {"id": "v1"}),
            ("non-object", [{"id": "v1"}, None]),
            ("missing-id", [{"name": "lost"}]),
            ("empty-id", [{"id": ""}]),
            ("non-string-id", [{"id": 1}]),
            ("duplicate-id", [{"id": "v1"}, {"id": "v1"}]),
        )
        ref = ArtifactRef(provider="compliance", artifact_id="cart_strict_versions")
        for label, versions in invalid_lists:
            with self.subTest(label=label):
                record = {"id": ref.artifact_id}
                if versions is not missing:
                    record["versions"] = versions
                adapter = AnthropicComplianceAdapter(
                    access_key="test",
                    opener=FakeOpener(_json_response({"data": [record]})),
                )

                with self.assertRaisesRegex(AdapterError, "versions"):
                    adapter.versions(ref)

    def test_implicit_bridge_mirror_rejects_an_incomplete_version_list(self):
        artifact_id = "cart_implicit_mirror_strict"
        opener = FakeOpener(
            _json_response(
                {
                    "data": [
                        {
                            "id": artifact_id,
                            "versions": [{"id": "v1"}, {"name": "silently-lost"}],
                        }
                    ]
                }
            ),
            FakeResponse(b"must not be fetched"),
        )
        adapter = AnthropicComplianceAdapter(access_key="test", opener=opener)

        with self.assertRaisesRegex(AdapterError, "versions"):
            BridgeClient([adapter]).mirror(artifact_id)

        self.assertEqual(len(opener.requests), 1)

    def test_code_artifact_and_version_model_metadata_are_sanitized(self):
        secret = "sk-ant-api01-DIRECT_MODEL_SECRET"
        record = {
            "id": "cart_sanitized_metadata",
            "api_key": secret,
            "note": secret,
            "versions": [
                {
                    "id": "v1",
                    "assetToken": secret,
                    "nested": {"private_key": secret},
                }
            ],
        }
        opener = FakeOpener(
            _json_response({"data": [record]}),
            _json_response({"data": [record]}),
        )
        adapter = AnthropicComplianceAdapter(access_key="test", opener=opener)
        ref = ArtifactRef("compliance", record["id"])

        artifact = adapter.inspect(ref)
        version = adapter.versions(ref)[0]

        self.assertNotIn("api_key", artifact.metadata)
        self.assertNotIn("assetToken", artifact.metadata["versions"][0])
        self.assertNotIn("assetToken", version.metadata)
        self.assertNotIn("private_key", version.metadata["nested"])
        self.assertNotIn("DIRECT_MODEL_SECRET", repr(artifact.metadata))
        self.assertNotIn("DIRECT_MODEL_SECRET", repr(version.metadata))


class ComplianceDownloadTests(unittest.TestCase):
    def test_503_is_retried_with_bounded_backoff_then_exact_version_is_returned(self):
        content = b"<!doctype html><title>stored</title>"
        content_md5 = base64.b64encode(hashlib.md5(content).digest()).decode("ascii")
        unavailable = FakeResponse(status=503, headers={"Retry-After": "0"})
        available = FakeResponse(
            content,
            headers={
                "Content-Type": "text/html; charset=utf-8",
                "Content-Length": str(len(content)),
                "Content-MD5": content_md5,
            },
        )
        opener = FakeOpener(unavailable, available)
        sleeps = []
        adapter = AnthropicComplianceAdapter(
            access_key="test",
            opener=opener,
            sleep=sleeps.append,
            max_retries=2,
        )

        result = adapter.download_code_artifact_version("cart_01", "174-v1")

        self.assertEqual(result, content)
        self.assertEqual(sleeps, [0.0])
        self.assertTrue(unavailable.closed)
        self.assertEqual(len(opener.requests), 2)
        path = urllib.parse.urlsplit(opener.requests[-1].full_url).path
        self.assertEqual(path, "/v1/compliance/apps/code/artifacts/cart_01/versions/174-v1")

    def test_content_md5_mismatch_is_never_exposed(self):
        content = b"untrusted until checked"
        wrong_md5 = base64.b64encode(hashlib.md5(b"different").digest()).decode("ascii")
        response = FakeResponse(content, headers={"Content-MD5": wrong_md5})
        adapter = AnthropicComplianceAdapter(access_key="test", opener=FakeOpener(response))

        with self.assertRaises(IntegrityError):
            adapter.download_code_artifact_version("cart_01", "v1")
        self.assertTrue(response.closed)

    def test_short_body_against_content_length_is_typed_truncation(self):
        response = FakeResponse(b"abc", headers={"Content-Length": "8"})
        adapter = AnthropicComplianceAdapter(access_key="test", opener=FakeOpener(response))

        with self.assertRaises(TruncatedResponseError):
            adapter.download_code_artifact_version("cart_01", "v1")
        self.assertTrue(response.closed)

    def test_stream_exception_is_typed_truncation(self):
        response = FakeResponse(read_error=OSError("connection reset"))
        adapter = AnthropicComplianceAdapter(access_key="test", opener=FakeOpener(response))

        with self.assertRaises(TruncatedResponseError):
            adapter.download_code_artifact_version("cart_01", "v1")

    def test_declared_and_streamed_oversize_responses_are_rejected(self):
        declared = FakeResponse(b"", headers={"Content-Length": "5"})
        adapter = AnthropicComplianceAdapter(
            access_key="test",
            opener=FakeOpener(declared),
            max_response_bytes=4,
        )
        with self.assertRaises(ResponseTooLargeError):
            adapter.download_code_artifact_version("cart_01", "v1")
        self.assertEqual(declared.read_calls, 0)

        streamed = FakeResponse(b"12345")
        adapter = AnthropicComplianceAdapter(
            access_key="test",
            opener=FakeOpener(streamed),
            max_response_bytes=4,
        )
        with self.assertRaises(ResponseTooLargeError):
            adapter.download_code_artifact_version("cart_01", "v1")

    def test_version_404_is_a_stale_version_error(self):
        adapter = AnthropicComplianceAdapter(
            access_key="test",
            opener=FakeOpener(FakeResponse(status=404)),
        )
        with self.assertRaises(StaleVersionError):
            adapter.download_code_artifact_version("cart_01", "rotated-out")

    def test_standard_artifact_metadata_and_content_are_exact_and_verified(self):
        content = b"# Exact standard Artifact version\n"
        version_id = "claude_artifact_version_01"
        secret = "sk-ant-api01-STANDARD_MODEL_SECRET"
        metadata = {
            "id": "claude_artifact_01",
            "version_id": version_id,
            "title": "Notes",
            "artifact_type": "text/markdown",
            "created_at": "2026-08-09T10:00:00Z",
            "size_bytes": len(content),
            "md5": hashlib.md5(content).hexdigest(),
            "future_field": "preserved",
            "api_key": secret,
            "nested": {"assetToken": secret},
        }
        opener = FakeOpener(
            _json_response(metadata),
            FakeResponse(content, headers={"Content-Type": "text/markdown"}),
        )
        adapter = AnthropicComplianceAdapter(access_key="test", opener=opener)
        ref = ArtifactRef(
            provider="compliance",
            artifact_id=version_id,
            version=version_id,
            kind="standard",
        )

        fetched = adapter.fetch(ref, version_id)

        self.assertEqual(fetched.artifact.artifact_id, "claude_artifact_01")
        self.assertEqual(fetched.version.version_id, version_id)
        self.assertEqual(fetched.version.metadata["future_field"], "preserved")
        self.assertNotIn("api_key", fetched.artifact.metadata)
        self.assertNotIn("assetToken", fetched.version.metadata["nested"])
        self.assertNotIn("STANDARD_MODEL_SECRET", repr(fetched.artifact.metadata))
        self.assertNotIn("STANDARD_MODEL_SECRET", repr(fetched.version.metadata))
        self.assertEqual(fetched.representations[0].label, "stored")
        self.assertEqual(fetched.representations[0].data, content)
        self.assertEqual(fetched.representations[0].suggested_name, "Notes.md")
        paths = [urllib.parse.urlsplit(req.full_url).path for req in opener.requests]
        self.assertEqual(
            paths,
            [
                "/v1/compliance/apps/artifacts/%s" % version_id,
                "/v1/compliance/apps/artifacts/%s/content" % version_id,
            ],
        )

    def test_standard_metadata_requires_every_exact_integrity_field(self):
        version_id = "claude_artifact_version_strict_fields"
        valid = {
            "id": "claude_artifact_strict_fields",
            "version_id": version_id,
            "md5": hashlib.md5(b"").hexdigest(),
            "size_bytes": 0,
        }
        missing = object()
        invalid_fields = (
            ("missing-id", "id", missing, IntegrityError),
            ("empty-id", "id", "", IntegrityError),
            ("non-string-id", "id", 7, IntegrityError),
            ("missing-version", "version_id", missing, IntegrityError),
            ("empty-version", "version_id", "", IntegrityError),
            ("non-string-version", "version_id", 7, IntegrityError),
            ("mismatched-version", "version_id", version_id + "_other", IntegrityError),
            ("missing-md5", "md5", missing, IntegrityError),
            ("empty-md5", "md5", "", IntegrityError),
            ("uppercase-md5", "md5", valid["md5"].upper(), IntegrityError),
            ("missing-size", "size_bytes", missing, IntegrityError),
            ("negative-size", "size_bytes", -1, IntegrityError),
            ("boolean-size", "size_bytes", True, IntegrityError),
            ("non-integer-size", "size_bytes", "0", IntegrityError),
            ("oversized", "size_bytes", 1025, ResponseTooLargeError),
        )
        ref = ArtifactRef(
            provider="compliance",
            artifact_id=version_id,
            version=version_id,
            kind="standard",
        )
        for label, field, value, error_type in invalid_fields:
            with self.subTest(label=label):
                metadata = dict(valid)
                if value is missing:
                    metadata.pop(field)
                else:
                    metadata[field] = value
                opener = FakeOpener(_json_response(metadata), FakeResponse(b"must not be read"))
                adapter = AnthropicComplianceAdapter(
                    access_key="test",
                    opener=opener,
                    max_response_bytes=1024,
                )

                with self.assertRaises(error_type):
                    adapter.fetch(ref, version_id)

                self.assertEqual(len(opener.requests), 1)

    def test_standard_metadata_digest_is_enforced_against_content(self):
        version_id = "claude_artifact_version_digest_mismatch"
        content = b"untrusted"
        metadata = {
            "id": "claude_artifact_digest_mismatch",
            "version_id": version_id,
            "md5": hashlib.md5(b"different").hexdigest(),
            "size_bytes": len(content),
        }
        response = FakeResponse(content)
        adapter = AnthropicComplianceAdapter(
            access_key="test",
            opener=FakeOpener(_json_response(metadata), response),
        )
        ref = ArtifactRef("compliance", version_id, version_id, kind="standard")

        with self.assertRaises(IntegrityError):
            adapter.fetch(ref, version_id)

        self.assertTrue(response.closed)

    def test_direct_standard_content_download_cannot_skip_metadata_validation(self):
        version_id = "claude_artifact_version_direct_validation"
        incomplete_metadata = {
            "id": "claude_artifact_direct_validation",
            "version_id": version_id,
            "size_bytes": 4,
        }
        opener = FakeOpener(
            _json_response(incomplete_metadata),
            FakeResponse(b"must not be fetched"),
        )
        adapter = AnthropicComplianceAdapter(access_key="test", opener=opener)

        with self.assertRaises(IntegrityError):
            adapter.download_standard_artifact_content(version_id)

        self.assertEqual(len(opener.requests), 1)
        self.assertTrue(
            urllib.parse.urlsplit(opener.requests[0].full_url).path.endswith("/" + version_id)
        )

    def test_bridge_client_preserves_standard_lineage_from_exact_version_ref(self):
        content = b"standard lineage"
        version_id = "claude_artifact_version_bridge01"
        metadata = {
            "id": "claude_artifact_stable01",
            "version_id": version_id,
            "title": "Bridge integration",
            "size_bytes": len(content),
            "md5": hashlib.md5(content).hexdigest(),
        }
        adapter = AnthropicComplianceAdapter(
            access_key="test",
            opener=FakeOpener(_json_response(metadata), FakeResponse(content)),
        )

        fetched = BridgeClient([adapter]).fetch(version_id)

        self.assertEqual(fetched.artifact.artifact_id, "claude_artifact_stable01")
        self.assertEqual(fetched.version.artifact_id, "claude_artifact_stable01")
        self.assertEqual(fetched.version.version_id, version_id)

    def test_bridge_client_routes_official_cart_id_and_opaque_version(self):
        content = b"official Code Artifact bytes"
        opener = FakeOpener(FakeResponse(content))
        adapter = AnthropicComplianceAdapter(access_key="test", opener=opener)

        fetched = BridgeClient([adapter]).fetch(
            "cart_01Tu9VwXyZaBcDeFgHiJkLmN",
            version="1741803761-9f3a",
        )

        self.assertEqual(fetched.artifact.artifact_id, "cart_01Tu9VwXyZaBcDeFgHiJkLmN")
        self.assertEqual(fetched.version.version_id, "1741803761-9f3a")
        self.assertEqual(fetched.representations[0].data, content)

    def test_embedded_exact_version_cannot_be_overridden(self):
        adapter = AnthropicComplianceAdapter(access_key="test", opener=FakeOpener())
        ref = ArtifactRef(
            provider="compliance",
            artifact_id="cart_01",
            version="v1",
            kind="code",
        )
        with self.assertRaises(VersionNotFoundError):
            adapter.fetch(ref, "v2")


class ComplianceCredentialSafetyTests(unittest.TestCase):
    def test_public_code_record_helpers_sanitize_provider_metadata(self):
        secret = "sk-ant-api01-RAW_CODE_HELPER_SECRET"
        record = {
            "id": "cart_public_helper",
            "x-api-key": secret,
            "note": secret,
            "future_field": {"kept": [1, 2, 3]},
            "versions": [{"id": "v1", "assetToken": secret}],
        }
        opener = FakeOpener(
            _json_response({"data": [record]}),
            _json_response({"data": [record]}),
        )
        adapter = AnthropicComplianceAdapter(access_key="test", opener=opener)

        iterated = next(adapter.iter_code_artifact_records())
        listed = adapter.list_code_artifact_records()[0]

        for exposed in (iterated, listed):
            self.assertNotIn("x-api-key", exposed)
            self.assertNotIn("assetToken", exposed["versions"][0])
            self.assertNotIn("RAW_CODE_HELPER_SECRET", repr(exposed))
            self.assertEqual(exposed["future_field"], {"kept": [1, 2, 3]})

    def test_public_standard_metadata_helper_sanitizes_provider_metadata(self):
        content = b"safe"
        version_id = "claude_artifact_version_public_helper"
        secret = "sk-ant-api01-RAW_STANDARD_HELPER_SECRET"
        metadata = {
            "id": "claude_artifact_public_helper",
            "version_id": version_id,
            "md5": hashlib.md5(content).hexdigest(),
            "size_bytes": len(content),
            "x-api-key": secret,
            "nested": {"assetToken": secret},
            "future_field": {"kept": True},
        }
        adapter = AnthropicComplianceAdapter(
            access_key="test",
            opener=FakeOpener(_json_response(metadata)),
        )

        exposed = adapter.get_standard_artifact_metadata(version_id)

        self.assertNotIn("x-api-key", exposed)
        self.assertNotIn("assetToken", exposed["nested"])
        self.assertNotIn("RAW_STANDARD_HELPER_SECRET", repr(exposed))
        self.assertEqual(exposed["future_field"], {"kept": True})
        self.assertEqual(exposed["version_id"], version_id)
        self.assertEqual(exposed["md5"], metadata["md5"])

    def test_suggested_filename_redacts_credential_shaped_title(self):
        name = AnthropicComplianceAdapter._suggested_name(
            "notes-sk-ant-api01-FILENAME_SECRET",
            "claude_artifact_01",
            "text/plain",
        )
        self.assertNotIn("FILENAME_SECRET", name)

    def test_transport_failures_do_not_leak_access_key_or_log(self):
        secret = "sk-ant-api01-SUPER_SECRET_VALUE"
        opener = FakeOpener(OSError("proxy echoed x-api-key=%s" % secret))
        adapter = AnthropicComplianceAdapter(access_key=secret, opener=opener)
        records = []

        class Capture(logging.Handler):
            def emit(self, record):
                records.append(record)

        handler = Capture()
        root = logging.getLogger()
        root.addHandler(handler)
        try:
            with self.assertRaises(AdapterError) as caught:
                adapter.list_code_artifact_records()
        finally:
            root.removeHandler(handler)

        rendered = "".join(
            traceback.format_exception(
                type(caught.exception),
                caught.exception,
                caught.exception.__traceback__,
            )
        )
        self.assertNotIn(secret, str(caught.exception))
        self.assertNotIn(secret, repr(caught.exception))
        self.assertNotIn(secret, rendered)
        self.assertNotIn(secret, repr(adapter))
        self.assertIsNone(caught.exception.__context__)
        self.assertEqual(records, [])

    def test_invalid_json_body_is_not_retained_in_public_error(self):
        secret_body = b'not-json sk-ant-api01-RESPONSE_SECRET'
        adapter = AnthropicComplianceAdapter(
            access_key="test",
            opener=FakeOpener(FakeResponse(secret_body)),
        )

        with self.assertRaises(AdapterError) as caught:
            adapter.list_code_artifact_records()

        self.assertNotIn("RESPONSE_SECRET", str(caught.exception))
        self.assertIsNone(caught.exception.__context__)

    def test_json_structure_scan_ignores_delimiters_inside_strings(self):
        delimiter_text = "[{,:" * 17000
        adapter = AnthropicComplianceAdapter(
            access_key="test",
            opener=FakeOpener(
                _json_response(
                    {"data": [{"id": "cart_string_delimiters", "future": delimiter_text}]}
                )
            ),
        )

        records = adapter.list_code_artifact_records()

        self.assertEqual(records[0]["future"], delimiter_text)

    def test_wide_shallow_json_is_rejected_before_parsing(self):
        response = _json_response({"data": [], "future": [0] * 65536})
        adapter = AnthropicComplianceAdapter(
            access_key="test",
            opener=FakeOpener(response),
        )

        with self.assertRaisesRegex(AdapterError, "invalid JSON") as caught:
            adapter.list_code_artifact_records()

        self.assertIsNone(caught.exception.__context__)
        self.assertTrue(response.closed)

    def test_deep_json_is_rejected_without_leaking_parser_recursion(self):
        secret = "sk-ant-api01-DEEP_RESPONSE_SECRET"
        deep_json = ("[" * 1100 + json.dumps(secret) + "]" * 1100).encode("utf-8")
        response = FakeResponse(deep_json)
        adapter = AnthropicComplianceAdapter(
            access_key="test",
            opener=FakeOpener(response),
        )

        with self.assertRaisesRegex(AdapterError, "invalid JSON") as caught:
            adapter.list_code_artifact_records()

        self.assertLess(len(deep_json), 4096)
        self.assertNotIn("DEEP_RESPONSE_SECRET", str(caught.exception))
        self.assertIsNone(caught.exception.__context__)
        self.assertTrue(response.closed)


if __name__ == "__main__":
    unittest.main()
