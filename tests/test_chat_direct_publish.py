"""Offline tests for the experimental native standard-Artifact adapter."""

from __future__ import annotations

import hashlib
import unittest
from unittest import mock

from clawdvert import chat_direct_publish as native
from clawdvert.frames import FrameError


ORG = "11111111-2222-4333-8444-555555555555"
ARTIFACT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
VERSION = "99999999-8888-4777-8666-555555555555"
MESSAGE = "12345678-1234-4234-8234-123456789abc"
CONVERSATION = "fedcba98-7654-4321-8fed-cba987654321"
PUBLISHED = "abcdefab-cdef-4abc-8def-abcdefabcdef"
DIGEST = "0" * 64
SESSION_REF = "local_87654321-4321-4321-8321-cba987654321"
SOURCE = "<!doctype html><html><body>exact \N{SNOWMAN}</body></html>"


class FakeSession:
    def __init__(self, result):
        self.result = result
        self.expressions = []
        self.closed = False

    def evaluate(self, expression, **_kwargs):
        self.expressions.append(expression)
        return self.result

    def close(self):
        self.closed = True


def publisher():
    return native.NativeShareArtifactPublisher(
        9222,
        expected_email_sha256=DIGEST,
        organization_uuid=ORG,
        native_session_ref=SESSION_REF,
    )


class NativeShareContractTests(unittest.TestCase):
    def test_reference_validation_and_hash_are_deterministic(self):
        self.assertEqual(native.validate_session_ref(SESSION_REF), SESSION_REF)
        self.assertEqual(
            native.hash_session_ref(SESSION_REF),
            hashlib.sha256(SESSION_REF.encode()).hexdigest(),
        )
        for invalid in ("", "../../cookie", "local_bad", "x" * 200, "has space"):
            with self.subTest(invalid=invalid), self.assertRaises(FrameError):
                native.validate_session_ref(invalid)

    def test_constructor_requires_exact_identity_and_org(self):
        with self.assertRaises(FrameError):
            native.NativeShareArtifactPublisher(
                9222,
                expected_email_sha256="person@example.com",
                organization_uuid=ORG,
                native_session_ref=SESSION_REF,
            )
        with self.assertRaises(FrameError):
            native.NativeShareArtifactPublisher(
                9222,
                expected_email_sha256=DIGEST,
                organization_uuid="not-an-org",
                native_session_ref=SESSION_REF,
            )

    def run_result(self, result):
        driver = publisher()
        session = FakeSession(result)
        with mock.patch.object(
            driver, "_create_auth_target", return_value=("controlled-target", session)
        ), mock.patch.object(driver, "_close_target") as closed:
            value = driver.publish(SOURCE, "fixture.html", title="Fixture")
        self.assertTrue(session.closed)
        closed.assert_called_once_with("controlled-target")
        return value, session.expressions

    def test_success_is_bound_to_returned_ids_and_exact_source_hash(self):
        result, expressions = self.run_result(
            {
                "stage": "complete",
                "artifactUuid": ARTIFACT,
                "versionUuid": VERSION,
                "messageUuid": MESSAGE,
                "conversationUuid": CONVERSATION,
            }
        )
        self.assertEqual(result.artifact_uuid, ARTIFACT)
        self.assertEqual(result.version_uuid, VERSION)
        self.assertEqual(result.url, "https://claude.ai/artifacts/" + VERSION)
        self.assertEqual(result.source_sha256, hashlib.sha256(SOURCE.encode()).hexdigest())
        self.assertEqual(len(expressions), 1)
        transcript = expressions[0]
        self.assertIn("/artifacts/share_from_content", transcript)
        self.assertIn("operation:'share'", transcript)
        self.assertIn("source_kind:'cowork'", transcript)
        self.assertIn("memberships.some", transcript)
        self.assertIn("artifact-versions/${versionUuid}/visibility", transcript)
        self.assertIn("anthropic-anonymous-id", transcript)
        self.assertIn("anthropic-device-id", transcript)
        self.assertIn("anthropic-client-platform", transcript)
        self.assertIn("anthropic-client-sha", transcript)
        self.assertIn("anthropic-client-version", transcript)
        self.assertIn("anthropic-client-build", transcript)
        self.assertIn("x-activity-session-id", transcript)
        self.assertIn("if (activityRaw) headers['x-activity-session-id']", transcript)
        self.assertIn("readCookie('ajs_anonymous_id')", transcript)
        self.assertIn("/user_artifacts?limit=${limit}", transcript)
        self.assertIn("Math.min(10000, limit + 30)", transcript)
        self.assertIn("safeText(item.artifact_type)", transcript)
        self.assertNotIn("safeText(item.type)", transcript)
        self.assertIn("`${catalog.chat_conversation_uuid}/versions`", transcript)
        self.assertIn("row.result_state === SOURCE", transcript)
        self.assertNotIn("item?.source ===", transcript)
        self.assertNotIn("/chat/", transcript)
        self.assertNotIn("Input.", transcript)
        self.assertNotIn("/completions", transcript)

    def test_404_is_typed_and_never_retried(self):
        driver = publisher()
        session = FakeSession({"stage": "share_http", "status": 404})
        with mock.patch.object(
            driver, "_create_auth_target", return_value=("controlled-target", session)
        ), mock.patch.object(driver, "_close_target"):
            with self.assertRaises(native.NativeCapabilityUnavailable) as caught:
                driver.publish(SOURCE, "fixture.html")
        self.assertEqual(len(session.expressions), 1)
        self.assertNotIn(SESSION_REF, str(caught.exception))
        self.assertIn("no creation was confirmed", str(caught.exception))

    def test_network_and_malformed_success_are_remote_state_unknown(self):
        for result in (
            {"stage": "share_network"},
            {"stage": "share_http", "status": 503},
            {"stage": "share_malformed"},
            {"stage": "version_verify", "status": 200},
            {"stage": "privacy_mutation", "status": 500},
            None,
        ):
            with self.subTest(result=result):
                driver = publisher()
                session = FakeSession(result)
                with mock.patch.object(
                    driver,
                    "_create_auth_target",
                    return_value=("controlled-target", session),
                ), mock.patch.object(driver, "_close_target"):
                    with self.assertRaises(native.RemoteStateUnknown):
                        driver.publish(SOURCE, "fixture.html")
                self.assertEqual(len(session.expressions), 1)

    def test_post_create_failure_preserves_validated_cleanup_ids(self):
        driver = publisher()
        session = FakeSession(
            {
                "stage": "privacy_mutation",
                "status": 500,
                "artifactUuid": ARTIFACT,
                "versionUuid": VERSION,
                "messageUuid": MESSAGE,
            }
        )
        with mock.patch.object(
            driver, "_create_auth_target", return_value=("controlled-target", session)
        ), mock.patch.object(driver, "_close_target"):
            with self.assertRaises(native.RemoteStateUnknown) as caught:
                driver.publish(SOURCE, "fixture.html")
        self.assertEqual(caught.exception.artifact_uuid, ARTIFACT)
        self.assertEqual(caught.exception.version_uuid, VERSION)
        self.assertIn("artifact=" + ARTIFACT, str(caught.exception))
        self.assertNotIn(SESSION_REF, str(caught.exception))

    def test_unexpected_public_binding_reports_revocation_status(self):
        driver = publisher()
        session = FakeSession(
            {
                "stage": "unexpected_public",
                "artifactUuid": ARTIFACT,
                "versionUuid": VERSION,
                "messageUuid": MESSAGE,
                "conversationUuid": CONVERSATION,
                "publishedUuid": PUBLISHED,
                "revocationConfirmed": True,
            }
        )
        with mock.patch.object(
            driver, "_create_auth_target", return_value=("controlled-target", session)
        ), mock.patch.object(driver, "_close_target"):
            with self.assertRaises(native.RemoteStateUnknown) as caught:
                driver.publish(SOURCE, "fixture.html")
        self.assertEqual(
            caught.exception.published_uuid,
            PUBLISHED,
        )
        self.assertTrue(caught.exception.published_revocation_confirmed)
        self.assertIn("published-revoked=yes", str(caught.exception))

    def test_public_publish_uses_dedicated_contract_and_distinct_public_uuid(self):
        driver = publisher()
        session = FakeSession(
            {
                "stage": "complete",
                "artifactUuid": ARTIFACT,
                "versionUuid": VERSION,
                "messageUuid": MESSAGE,
                "conversationUuid": CONVERSATION,
                "publishedUuid": PUBLISHED,
            }
        )
        with mock.patch.object(
            driver, "_create_auth_target", return_value=("controlled-target", session)
        ), mock.patch.object(driver, "_close_target"):
            result = driver.publish(
                SOURCE, "fixture.html", title="Fixture", public=True
            )
        self.assertTrue(result.public)
        self.assertEqual(result.published_uuid, PUBLISHED)
        self.assertEqual(
            result.url, "https://claude.ai/public/artifacts/" + PUBLISHED
        )
        transcript = session.expressions[0]
        self.assertIn("/publish_artifact", transcript)
        self.assertIn("conversation_uuid:catalog.chat_conversation_uuid", transcript)
        self.assertIn("artifact_identifier:catalog.artifact_identifier", transcript)
        self.assertIn("content:row.result_state", transcript)
        self.assertIn("artifact_version_uuid:binding.versionUuid", transcript)
        self.assertIn("include_deleted_artifacts=", transcript)
        self.assertIn("credentials:'omit'", transcript)
        self.assertIn("published_artifact_deleted_at === null", transcript)
        self.assertNotIn("screenshot:", transcript)
        self.assertEqual(transcript.count("artifacts/share_from_content"), 1)
        self.assertEqual(transcript.count("/publish_artifact"), 1)

    def test_unpublish_is_exact_non_retrying_and_verifies_tombstone(self):
        driver = publisher()
        session = FakeSession(
            {
                "stage": "unpublish_complete",
                "artifactUuid": ARTIFACT,
                "versionUuid": VERSION,
                "messageUuid": MESSAGE,
                "publishedUuid": PUBLISHED,
                "revocationConfirmed": True,
            }
        )
        result = native.NativeShareResult(
            url="https://claude.ai/public/artifacts/" + PUBLISHED,
            artifact_uuid=ARTIFACT,
            version_uuid=VERSION,
            message_uuid=MESSAGE,
            source_sha256=hashlib.sha256(SOURCE.encode()).hexdigest(),
            public=True,
            published_uuid=PUBLISHED,
        )
        with mock.patch.object(
            driver, "_create_auth_target", return_value=("controlled-target", session)
        ), mock.patch.object(driver, "_close_target"):
            self.assertTrue(driver.unpublish(result, SOURCE))
        self.assertEqual(len(session.expressions), 1)
        transcript = session.expressions[0]
        self.assertIn("method:'DELETE', body:'{}'", transcript)
        self.assertIn("verifyActiveZero", transcript)
        self.assertIn("publishedUuid, true", transcript)
        self.assertIn("published_artifact_deleted_at", transcript)

    def test_unpublish_rejects_source_mismatch_before_browser_construction(self):
        driver = publisher()
        result = native.NativeShareResult(
            url="https://claude.ai/public/artifacts/" + PUBLISHED,
            artifact_uuid=ARTIFACT,
            version_uuid=VERSION,
            message_uuid=MESSAGE,
            source_sha256=hashlib.sha256(SOURCE.encode()).hexdigest(),
            public=True,
            published_uuid=PUBLISHED,
        )
        with mock.patch.object(
            driver,
            "_create_auth_target",
            side_effect=AssertionError("source mismatch must fail before Chrome"),
        ):
            with self.assertRaisesRegex(FrameError, "source did not match"):
                driver.unpublish(result, SOURCE + " changed")

    def test_unpublish_malformed_success_is_not_accepted(self):
        driver = publisher()
        session = FakeSession(
            {"stage": "unpublish_complete", "revocationConfirmed": True}
        )
        result = native.NativeShareResult(
            url="https://claude.ai/public/artifacts/" + PUBLISHED,
            artifact_uuid=ARTIFACT,
            version_uuid=VERSION,
            message_uuid=MESSAGE,
            source_sha256=hashlib.sha256(SOURCE.encode()).hexdigest(),
            public=True,
            published_uuid=PUBLISHED,
        )
        with mock.patch.object(
            driver, "_create_auth_target", return_value=("controlled-target", session)
        ), mock.patch.object(driver, "_close_target"):
            with self.assertRaises(native.RemoteStateUnknown):
                driver.unpublish(result, SOURCE)

    def test_invalid_anonymous_cookie_preflight_is_non_mutating(self):
        driver = publisher()
        session = FakeSession({"stage": "preflight_headers"})
        with mock.patch.object(
            driver, "_create_auth_target", return_value=("controlled-target", session)
        ), mock.patch.object(driver, "_close_target"):
            with self.assertRaisesRegex(FrameError, "anonymous browser identifier"):
                driver.publish(SOURCE, "fixture.html")
        transcript = session.expressions[0]
        self.assertLess(
            transcript.index("preflight_headers"),
            transcript.index("artifacts/share_from_content"),
        )

    def test_local_target_cleanup_failure_does_not_mask_completed_binding(self):
        driver = publisher()
        session = FakeSession(
            {
                "stage": "complete",
                "artifactUuid": ARTIFACT,
                "versionUuid": VERSION,
                "messageUuid": MESSAGE,
                "conversationUuid": CONVERSATION,
            }
        )
        with mock.patch.object(
            driver, "_create_auth_target", return_value=("controlled-target", session)
        ), mock.patch.object(
            driver, "_close_target", side_effect=FrameError("close failed")
        ):
            with self.assertRaises(native.RemoteStateUnknown) as caught:
                driver.publish(SOURCE, "fixture.html")
        self.assertEqual(caught.exception.artifact_uuid, ARTIFACT)
        self.assertIn("authentication tab", str(caught.exception))

    def test_malformed_http_status_is_not_echoed(self):
        driver = publisher()
        session = FakeSession(
            {"stage": "share_http", "status": "hostile\nterminal"}
        )
        with mock.patch.object(
            driver, "_create_auth_target", return_value=("controlled-target", session)
        ), mock.patch.object(driver, "_close_target"):
            with self.assertRaises(native.RemoteStateUnknown) as caught:
                driver.publish(SOURCE, "fixture.html")
        self.assertNotIn("hostile", str(caught.exception))

    def test_invalid_target_list_is_rejected(self):
        driver = publisher()
        with mock.patch.object(native, "_localhost_json", return_value=None):
            with self.assertRaisesRegex(FrameError, "invalid target list"):
                driver._target("controlled-target")

    def test_authentication_and_authorization_are_distinct(self):
        for status, phrase in ((401, "authentication"), (403, "authorization")):
            with self.subTest(status=status):
                driver = publisher()
                session = FakeSession({"stage": "share_http", "status": status})
                with mock.patch.object(
                    driver,
                    "_create_auth_target",
                    return_value=("controlled-target", session),
                ), mock.patch.object(driver, "_close_target"):
                    with self.assertRaisesRegex(FrameError, phrase):
                        driver.publish(SOURCE, "fixture.html")

    def test_invalid_input_fails_before_browser_construction(self):
        driver = publisher()
        with mock.patch.object(
            driver,
            "_create_auth_target",
            side_effect=AssertionError("browser must not be constructed"),
        ):
            with self.assertRaises(FrameError):
                driver.publish("", "fixture.html")
            with self.assertRaises(FrameError):
                driver.publish(SOURCE, "../fixture.html")


if __name__ == "__main__":
    unittest.main()
