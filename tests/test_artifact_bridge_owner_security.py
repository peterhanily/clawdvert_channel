"""Owner adapter authentication, completeness, and credential-safety regressions."""

from __future__ import annotations

import io
import json
import traceback
import unittest
from urllib.error import HTTPError
from unittest import mock

from clawdvert import frames

from artifact_bridge.adapters import owner_frame
from artifact_bridge.adapters.owner_frame import OwnerFrameAdapter, _BoundedFrameSession
from artifact_bridge.errors import AdapterError, AuthenticationError, NotFoundError
from artifact_bridge.models import ArtifactRef


PUBLIC_SLUG = "11111111-2222-4333-8444-555555555555"
OWNER_SLUG = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


class JsonResponse:
    def __init__(self, value, *, status=200):
        self.status = status
        self._body = io.BytesIO(json.dumps(value).encode("utf-8"))
        self.closed = False

    def read(self, size=-1):
        return self._body.read(size)

    def getcode(self):
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback_value):
        self.closed = True


class ScriptedSession:
    def __init__(self, boot_actions, versions_action=None):
        self.timeout = 1
        self.token_source = "fixture"
        self.boot_actions = dict(boot_actions)
        self.versions_action = versions_action
        self.requests = []
        self.closed = 0

    @staticmethod
    def _run(action):
        if isinstance(action, BaseException):
            raise action
        return action

    def request(self, method, path, body=None, headers=None, retries=2):
        del body, headers, retries
        self.requests.append((method, path))
        prefix = "/api/frame/versions/"
        if path.startswith(prefix):
            return self._run(self.versions_action)
        slug = path.removeprefix("/api/frame/").split("?", 1)[0]
        return self._run(self.boot_actions[slug])

    def close(self):
        self.closed += 1


class OwnerAuthenticationTests(unittest.TestCase):
    def assert_clean_exception(self, error, secret):
        rendered = "".join(
            traceback.format_exception(type(error), error, error.__traceback__)
        )
        self.assertNotIn(secret, rendered)
        self.assertIsNone(error.__context__)
        self.assertIsNone(error.__cause__)

    def test_auth_status_categorizes_credential_file_without_exposing_path(self):
        local_path = "/Users/private-person/.claude/.credentials.json"
        with mock.patch.object(
            frames,
            "read_token",
            return_value=("OAUTH-SECRET", local_path),
        ):
            status = OwnerFrameAdapter().auth_status()

        self.assertTrue(status.authenticated)
        self.assertEqual(status.source, "Claude credentials file")
        self.assertNotIn("private-person", json.dumps(status.to_dict()))

    def test_caller_session_source_is_never_echoed(self):
        session = ScriptedSession({})
        session.token_source = "/private/caller/credential/location"

        status = OwnerFrameAdapter(session=session).auth_status()

        self.assertEqual(status.source, "caller")
        self.assertNotIn("credential/location", json.dumps(status.to_dict()))

    def test_authenticated_boot_401_fails_without_anonymous_fallback(self):
        oauth_secret = "OAUTH-RAW-SECRET-401"
        session = ScriptedSession(
            {PUBLIC_SLUG: (401, {"oauthToken": oauth_secret}, {})}
        )
        anonymous_calls = []

        def anonymous_opener(request, timeout):
            anonymous_calls.append((request, timeout))
            return JsonResponse({"mode": "public", "ver": "must-not-be-used"})

        adapter = OwnerFrameAdapter(
            session=session,
            anonymous_opener=anonymous_opener,
        )

        with self.assertRaises(AuthenticationError) as caught:
            adapter.inspect(ArtifactRef("owner", PUBLIC_SLUG))

        self.assertEqual(caught.exception.status, 401)
        self.assertEqual(anonymous_calls, [])
        self.assertEqual(session.closed, 1)
        self.assertIsNone(adapter._session)
        self.assert_clean_exception(caught.exception, oauth_secret)

    def test_authenticated_boot_404_probes_public_without_discarding_session(self):
        owner_record = {
            "slug": OWNER_SLUG,
            "title": "Private",
            "live": "owner-v2",
            "perm": {"mode": "owner"},
        }
        session = ScriptedSession(
            {
                PUBLIC_SLUG: (404, {}, {}),
                OWNER_SLUG: (200, owner_record, {}),
            }
        )
        anonymous_calls = []

        def anonymous_opener(request, timeout):
            anonymous_calls.append((request.full_url, timeout))
            return JsonResponse(
                {"kind": "frame", "mode": "public", "ver": "public-v1"}
            )

        adapter = OwnerFrameAdapter(
            session=session,
            anonymous_opener=anonymous_opener,
        )

        public = adapter.inspect(ArtifactRef("owner", PUBLIC_SLUG))
        private = adapter.inspect(ArtifactRef("owner", OWNER_SLUG))

        self.assertEqual(public.published_version, "public-v1")
        self.assertEqual(private.live_version, "owner-v2")
        self.assertEqual(len(anonymous_calls), 1)
        self.assertIs(adapter._session, session)
        self.assertEqual(session.closed, 0)

    def test_boot_mapping_drops_raw_frame_error_context(self):
        oauth_secret = "OAUTH-RAW-SECRET-BOOT"
        session = ScriptedSession(
            {
                OWNER_SLUG: frames.FrameError(
                    "proxy echoed Authorization: Bearer %s" % oauth_secret,
                    status=503,
                )
            }
        )
        adapter = OwnerFrameAdapter(session=session)

        with self.assertRaises(AdapterError) as caught:
            adapter.inspect(ArtifactRef("owner", OWNER_SLUG))

        self.assert_clean_exception(caught.exception, oauth_secret)

    def test_anonymous_http_error_drops_cookie_and_body_context(self):
        secret = "PUBLIC-RESPONSE-COOKIE-SECRET"
        error = HTTPError(
            "https://example.invalid/frame",
            403,
            "forbidden",
            {"Set-Cookie": "session=%s" % secret},
            io.BytesIO(json.dumps({"token": secret}).encode("utf-8")),
        )

        def fail(request, timeout):
            del request, timeout
            raise error

        adapter = OwnerFrameAdapter(anonymous_opener=fail)
        adapter._session_error = RuntimeError("fixture has no OAuth")
        with self.assertRaises(NotFoundError) as caught:
            adapter.inspect(ArtifactRef("owner", PUBLIC_SLUG))

        self.assert_clean_exception(caught.exception, secret)


class OwnerTransportSafetyTests(unittest.TestCase):
    def assert_clean_exception(self, error, secret):
        rendered = "".join(
            traceback.format_exception(type(error), error, error.__traceback__)
        )
        self.assertNotIn(secret, rendered)
        self.assertIsNone(error.__context__)
        self.assertIsNone(error.__cause__)

    def test_bounded_session_drops_oauth_bearing_transport_exception(self):
        oauth_secret = "OAUTH-RAW-SECRET-SESSION"

        class FailingConnection:
            def request(self, method, path, headers=None):
                del method, path, headers
                raise OSError(
                    "proxy echoed Authorization: Bearer %s" % oauth_secret
                )

        session = _BoundedFrameSession(
            token=oauth_secret,
            max_metadata_bytes=1024,
        )
        with mock.patch.object(
            session,
            "_connect",
            return_value=FailingConnection(),
        ):
            with self.assertRaises(frames.FrameError) as caught:
                session.request("GET", "/api/frame/example", retries=0)

        self.assertEqual(session.reconnects, 1)
        self.assert_clean_exception(caught.exception, oauth_secret)

    def test_content_mapping_drops_asset_token_bearing_transport_exception(self):
        asset_secret = "ASSET-RAW-SECRET-CONTENT"

        class FailingConnection:
            def __init__(self):
                self.path = None
                self.closed = False

            def request(self, method, path, headers=None):
                del method, headers
                self.path = path
                raise OSError("failed request path %s" % path)

            def close(self):
                self.closed = True

        connection = FailingConnection()
        adapter = OwnerFrameAdapter()
        with mock.patch.object(
            owner_frame.http.client,
            "HTTPSConnection",
            return_value=connection,
        ):
            with self.assertRaises(AdapterError) as caught:
                adapter._download_content(
                    OWNER_SLUG,
                    "owner-v1",
                    asset_secret,
                    None,
                )

        self.assertIn("__frame_t=", connection.path)
        self.assertTrue(connection.closed)
        self.assert_clean_exception(caught.exception, asset_secret)

    def test_bounded_session_rejects_deep_remote_json_as_typed_error(self):
        body = ("[" * 2000 + "0" + "]" * 2000).encode("utf-8")

        class DeepResponse:
            status = 200
            will_close = True

            def getheaders(self):
                return [("Content-Length", str(len(body)))]

            def read(self, amount=-1):
                return body[:amount]

            def close(self):
                pass

        class DeepConnection:
            def request(self, method, path, headers=None):
                del method, path, headers

            def getresponse(self):
                return DeepResponse()

        session = _BoundedFrameSession(token="fixture", max_metadata_bytes=8192)
        with mock.patch.object(session, "_connect", return_value=DeepConnection()):
            with self.assertRaises(frames.FrameError) as caught:
                session.request("GET", "/api/frame/example", retries=0)

        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)

    def test_anonymous_boot_rejects_deep_remote_json_as_adapter_error(self):
        body = ("[" * 2000 + "0" + "]" * 2000).encode("utf-8")

        class RawResponse:
            status = 200

            def read(self, amount=-1):
                return body[:amount]

            def getcode(self):
                return self.status

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback_value):
                pass

        adapter = OwnerFrameAdapter(
            anonymous_opener=lambda request, timeout: RawResponse()
        )
        adapter._session_error = RuntimeError("fixture has no OAuth")
        with self.assertRaises(AdapterError) as caught:
            adapter.inspect(ArtifactRef("owner", PUBLIC_SLUG))

        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)

    def test_owner_parsers_reject_wide_remote_json_before_loading(self):
        body = ("[" + ",".join("{}" for _ in range(70000)) + "]").encode("utf-8")

        class WideResponse:
            status = 200
            will_close = True

            def getheaders(self):
                return [("Content-Length", str(len(body)))]

            def read(self, amount=-1):
                return body[:amount]

            def getcode(self):
                return self.status

            def close(self):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback_value):
                pass

        class WideConnection:
            def request(self, method, path, headers=None):
                del method, path, headers

            def getresponse(self):
                return WideResponse()

        session = _BoundedFrameSession(token="fixture", max_metadata_bytes=len(body) + 1)
        with mock.patch.object(session, "_connect", return_value=WideConnection()):
            with self.assertRaises(frames.FrameError):
                session.request("GET", "/api/frame/example", retries=0)

        adapter = OwnerFrameAdapter(
            anonymous_opener=lambda request, timeout: WideResponse()
        )
        adapter._session_error = RuntimeError("fixture has no OAuth")
        with self.assertRaises(AdapterError):
            adapter.inspect(ArtifactRef("owner", PUBLIC_SLUG))

    def test_authenticated_session_rejects_invalid_utf8_metadata(self):
        body = b'{"versions":["v\xff"]}'

        class InvalidResponse:
            status = 200
            will_close = True

            def getheaders(self):
                return [("Content-Length", str(len(body)))]

            def read(self, amount=-1):
                return body[:amount]

            def close(self):
                pass

        class InvalidConnection:
            def request(self, method, path, headers=None):
                del method, path, headers

            def getresponse(self):
                return InvalidResponse()

        session = _BoundedFrameSession(token="fixture", max_metadata_bytes=1024)
        with mock.patch.object(session, "_connect", return_value=InvalidConnection()):
            with self.assertRaises(frames.FrameError) as caught:
                session.request("GET", "/api/frame/example", retries=0)
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)


class OwnerListingShapeTests(unittest.TestCase):
    def test_owner_list_rejects_missing_or_malformed_records(self):
        class ListSession:
            timeout = 1
            token_source = "fixture"

            def __init__(self, frames_value):
                self.frames_value = frames_value

            def request(self, method, path, body=None, headers=None, retries=2):
                del method, path, body, headers, retries
                return 200, {"frames": self.frames_value}, {}

            def close(self):
                pass

        for value in ("not-a-list", [{"slug": OWNER_SLUG}, "not-a-record"], [{}]):
            with self.subTest(value=value):
                adapter = OwnerFrameAdapter(session=ListSession(value))
                with self.assertRaises(AdapterError):
                    adapter.list_artifacts()

    def test_owner_list_rejects_a_missing_frames_field(self):
        class MissingFramesSession:
            timeout = 1
            token_source = "fixture"

            def request(self, method, path, body=None, headers=None, retries=2):
                del method, path, body, headers, retries
                return 200, {}, {}

            def close(self):
                pass

        adapter = OwnerFrameAdapter(session=MissingFramesSession())
        with self.assertRaises(AdapterError):
            adapter.list_artifacts()


class OwnerVersionCompletenessTests(unittest.TestCase):
    def _adapter(self, versions_action):
        return OwnerFrameAdapter(
            session=ScriptedSession(
                {
                    OWNER_SLUG: (
                        200,
                        {
                            "slug": OWNER_SLUG,
                            "live": "boot-live",
                            "history": ["boot-history-must-not-mask-failure"],
                        },
                        {},
                    )
                },
                versions_action=versions_action,
            )
        )

    def test_authenticated_versions_exception_is_not_hidden_by_boot_history(self):
        raw_secret = "OAUTH-RAW-SECRET-VERSIONS"
        adapter = self._adapter(
            frames.FrameError(
                "transport echoed Bearer %s" % raw_secret,
                status=None,
            )
        )

        with self.assertRaises(AdapterError) as caught:
            adapter.versions(ArtifactRef("owner", OWNER_SLUG))

        rendered = "".join(
            traceback.format_exception(
                type(caught.exception),
                caught.exception,
                caught.exception.__traceback__,
            )
        )
        self.assertNotIn(raw_secret, rendered)
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)

    def test_authenticated_versions_non_200_is_not_hidden_by_boot_history(self):
        adapter = self._adapter((503, {"history": ["stale"]}, {}))

        with self.assertRaises(AdapterError) as caught:
            adapter.versions(ArtifactRef("owner", OWNER_SLUG))

        self.assertEqual(caught.exception.status, 503)

    def test_authenticated_versions_malformed_data_is_typed_failure(self):
        malformed_actions = (
            (200, "not-a-mapping", {}),
            (200, {"versions": "not-a-list"}, {}),
            (200, {"versions": [{"missing": "version id"}]}, {}),
        )
        for action in malformed_actions:
            with self.subTest(action=action):
                adapter = self._adapter(action)
                with self.assertRaises(AdapterError):
                    adapter.versions(ArtifactRef("owner", OWNER_SLUG))

    def test_authenticated_versions_uses_successful_endpoint_listing(self):
        adapter = self._adapter(
            (
                200,
                {"live": "api-v1", "versions": ["api-v1"]},
                {},
            )
        )

        versions = adapter.versions(ArtifactRef("owner", OWNER_SLUG))

        self.assertEqual([item.version_id for item in versions], ["api-v1"])
        self.assertEqual(versions[0].metadata, {})

    def test_anonymous_versions_are_only_the_public_pin_and_marked_partial(self):
        adapter = OwnerFrameAdapter(
            anonymous_opener=lambda request, timeout: JsonResponse(
                {
                    "kind": "frame",
                    "mode": "public",
                    "ver": "public-v1",
                    "history": ["not-publicly-authoritative"],
                }
            )
        )
        adapter._session_error = RuntimeError("fixture has no OAuth")

        versions = adapter.versions(ArtifactRef("owner", PUBLIC_SLUG))

        self.assertEqual([item.version_id for item in versions], ["public-v1"])
        self.assertEqual(
            versions[0].metadata,
            {
                "listing_completeness": "partial",
                "source": "anonymous_public_boot",
            },
        )


if __name__ == "__main__":
    unittest.main()
