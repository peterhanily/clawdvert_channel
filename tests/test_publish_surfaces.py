"""Offline surface-routing tests for the Claude Artifact publisher."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from clawdvert import chat_direct_publish
from clawdvert import chat_publish
from clawdvert import chat_seeded_publish
from clawdvert import chat_seeded_receipt
from clawdvert import publish
from clawdvert.frames import FrameError


HTML = """<!doctype html>
<html lang="en">
<head>
<title>Exact Fixture</title>
</head>
<body>
ok
</body>
</html>"""


class ChatContractTests(unittest.TestCase):
    def assert_javascript_parses(self, source):
        checked = subprocess.run(
            ["node", "--check"],
            input=source,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_output_path_and_prompt_are_deterministic_and_preserve_source(self):
        output_path = chat_publish.generated_output_path(HTML, "Exact Fixture")
        self.assertEqual(
            output_path,
            "/mnt/user-data/outputs/Exact-Fixture-"
            + hashlib.sha256(HTML.encode()).hexdigest()[:16]
            + ".html",
        )
        self.assertEqual(
            output_path,
            chat_publish.generated_output_path(HTML, "Exact Fixture"),
        )
        prompt = chat_publish.build_prompt(HTML, "Exact Fixture", output_path)
        self.assertIn("--- BEGIN EXACT HTML ---\n" + HTML, prompt)
        self.assertIn("Create exactly one file at " + output_path, prompt)
        self.assertIn("calling create_file exactly once", prompt)
        self.assertIn("call present_files exactly once", prompt)
        self.assertIn("Do not create an Artifact", prompt)
        self.assertEqual(
            prompt,
            chat_publish.build_prompt(HTML, "Exact Fixture", output_path),
        )

    def test_prompt_rejects_an_output_path_escape(self):
        with self.assertRaisesRegex(FrameError, "outputs"):
            chat_publish.build_prompt(
                HTML,
                "Exact Fixture",
                "/mnt/user-data/outputs/../escaped.html",
            )

    def test_human_text_verifier_accepts_measured_legacy_empty_payload(self):
        prompt = "exact submitted prompt"
        messages = [
            {
                "sender": "human",
                "text": "",
                "content": [{"type": "text", "text": prompt}],
            },
            {
                "sender": "human",
                "text": "contradictory legacy text",
                "content": [{"type": "text", "text": prompt}],
            },
            {
                "sender": "human",
                "text": prompt,
                "content": [{"type": "text", "text": "contradictory structured text"}],
            },
            {"sender": "human", "text": "", "content": []},
            {"sender": "human", "content": [{"type": "image"}]},
            {
                "sender": "human",
                "text": 7,
                "content": [{"type": "text", "text": prompt}],
            },
            {
                "sender": "human",
                "content": [
                    {"type": "text", "text": prompt},
                    {"type": "text", "text": prompt},
                ],
            },
        ]
        source = (
            chat_publish._EXACT_HUMAN_TEXT_JS
            + "\nconst messages = "
            + json.dumps(messages)
            + ";\nprocess.stdout.write(JSON.stringify("
            + "messages.map(message => exactHumanText(message))));\n"
        )
        checked = subprocess.run(
            ["node"], input=source, text=True, capture_output=True, check=False
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertEqual(
            json.loads(checked.stdout),
            [prompt, None, None, None, None, None, None],
        )

    def test_source_limit_fails_before_browser_access(self):
        with self.assertRaises(FrameError):
            chat_publish.build_prompt("x" * (chat_publish.MAX_CHAT_SOURCE_CHARS + 1), "x")

    def test_standard_public_url_is_strict_and_distinct_from_code_surface(self):
        raw = "https://claude.ai/public/artifacts/11111111-2222-4333-8444-555555555555"
        self.assertEqual(chat_publish.validate_public_url(raw), raw)
        self.assertEqual(
            chat_publish.validate_public_url(
                raw, "11111111-2222-4333-8444-555555555555"
            ),
            raw,
        )
        with self.assertRaisesRegex(FrameError, "verified publication"):
            chat_publish.validate_public_url(
                raw, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
            )
        with self.assertRaises(FrameError):
            chat_publish.validate_public_url(
                "https://claude.ai/code/artifact/11111111-2222-4333-8444-555555555555"
            )

    def test_identity_gate_requires_hash_and_organization_binding(self):
        with self.assertRaises(FrameError):
            chat_publish.ChatArtifactPublisher(9222, expected_email_sha256="person@example.com")
        digest = hashlib.sha256(b"person@example.com").hexdigest()
        organization_uuid = "11111111-2222-4333-8444-555555555555"
        driver = chat_publish.ChatArtifactPublisher(
            9222,
            expected_email_sha256=digest,
            organization_uuid=organization_uuid,
        )
        self.assertEqual(driver.expected_email_sha256, digest)
        self.assertEqual(driver.organization_uuid, organization_uuid)

    def test_debug_socket_path_is_strict(self):
        with self.assertRaises(FrameError):
            chat_publish._validate_socket_url(
                "ws://127.0.0.1:9222/devtools/not-a-target", 9222, "page"
            )

    def test_exact_file_binding_requires_one_ordered_tool_pair(self):
        organization_uuid = "11111111-2222-4333-8444-555555555555"
        conversation_uuid = "fedcba98-7654-4321-8fed-cba987654321"
        chat_url = "https://claude.ai/chat/" + conversation_uuid
        output_path = chat_publish.generated_output_path(HTML, "Exact Fixture")
        prompt = chat_publish.build_prompt(HTML, "Exact Fixture", output_path)

        class FakeSession:
            def __init__(self):
                self.expressions = []
                self.values = [
                    chat_url,
                    {"ok": True},
                    chat_url,
                    {"ok": True},
                    chat_url,
                    {"ok": True},
                ]

            def evaluate(self, expression, **_kwargs):
                self.expressions.append(expression)
                return self.values.pop(0)

        session = FakeSession()
        driver = chat_publish.ChatArtifactPublisher(
            9222,
            expected_email_sha256="0" * 64,
            organization_uuid=organization_uuid,
        )
        conversation_bound = mock.Mock()
        with mock.patch.object(chat_publish.time, "sleep") as slept:
            binding = driver._wait_for_exact_file(
                session,
                HTML,
                prompt,
                output_path,
                on_conversation_binding=conversation_bound,
            )
        self.assertEqual(
            binding,
            chat_publish.ChatFileBinding(
                chat_url=chat_url,
                organization_uuid=organization_uuid,
                conversation_uuid=conversation_uuid,
                output_path=output_path,
            ),
        )
        self.assertEqual(session.expressions[::2], ["location.href"] * 3)
        conversation_bound.assert_called_once_with(
            chat_publish.ChatConversationBinding(
                chat_url=chat_url,
                organization_uuid=organization_uuid,
                conversation_uuid=conversation_uuid,
            )
        )
        verifiers = session.expressions[1::2]
        self.assertEqual(len(verifiers), 3)
        self.assertTrue(all(expression == verifiers[0] for expression in verifiers))
        self.assertEqual(slept.call_args_list, [mock.call(1.0), mock.call(1.0)])
        transcript = verifiers[0]
        self.assert_javascript_parses(transcript)
        self.assertIn(chat_publish._EXACT_HUMAN_TEXT_JS.strip(), transcript)
        self.assertIn(
            f"/api/organizations/${{ORG}}/chat_conversations/${{CONVERSATION}}",
            transcript,
        )
        self.assertIn("message.content.filter(block => block?.type === 'text')", transcript)
        self.assertIn("tools.length !== 2", transcript)
        self.assertIn("tools[0].block?.name !== 'create_file'", transcript)
        self.assertIn("tools[1].block?.name !== 'present_files'", transcript)
        self.assertIn("create.file_text !== SOURCE", transcript)
        self.assertIn("create.path !== OUTPUT_PATH", transcript)
        self.assertIn("present.filepaths[0] !== OUTPUT_PATH", transcript)

    def artifact_binding(self):
        return chat_publish.ChatArtifactBinding(
            chat_url="https://claude.ai/chat/fedcba98-7654-4321-8fed-cba987654321",
            organization_uuid="11111111-2222-4333-8444-555555555555",
            conversation_uuid="fedcba98-7654-4321-8fed-cba987654321",
            artifact_uuid="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            version_uuid="99999999-8888-4777-8666-555555555555",
            message_uuid="12345678-1234-4234-8234-123456789abc",
            artifact_identifier="exact-fixture",
            artifact_type="text/html",
            code_language="html",
            title="Exact Fixture",
        )

    def test_lifecycle_completion_requires_exact_ids_and_reconciliation_marker(self):
        binding = self.artifact_binding()
        published = "abcdefab-cdef-4abc-8def-abcdefabcdef"
        base = {
            "stage": "unpublish_complete",
            "mutationAttempted": True,
            "artifactUuid": binding.artifact_uuid,
            "versionUuid": binding.version_uuid,
            "messageUuid": binding.message_uuid,
            "conversationUuid": binding.conversation_uuid,
            "publishedUuid": published,
        }
        require = chat_publish.ChatArtifactPublisher._require_lifecycle_completion
        self.assertTrue(
            require(
                base,
                stage="unpublish_complete",
                binding=binding,
                published_uuid=published,
            )
        )
        reconciled = {
            **base,
            "mutationAttempted": False,
            "reconciled": True,
        }
        self.assertTrue(
            require(
                reconciled,
                stage="unpublish_complete",
                binding=binding,
                published_uuid=published,
            )
        )
        self.assertFalse(
            require(
                {**base, "artifactUuid": "11111111-2222-4333-8444-555555555555"},
                stage="unpublish_complete",
                binding=binding,
                published_uuid=published,
            )
        )
        self.assertFalse(
            require(
                {**base, "mutationAttempted": False},
                stage="unpublish_complete",
                binding=binding,
                published_uuid=published,
            )
        )

    def test_lifecycle_browser_transaction_parses_and_has_reconciliation_paths(self):
        binding = self.artifact_binding()

        class FakeSession:
            def __init__(self):
                self.expression = None

            def evaluate(self, expression, **_kwargs):
                self.expression = expression
                return {}

        session = FakeSession()
        driver = chat_publish.ChatArtifactPublisher(
            9222,
            expected_email_sha256="0" * 64,
            organization_uuid=binding.organization_uuid,
        )
        driver._lifecycle_transaction(
            session,
            binding,
            HTML,
            action="delete_conversation",
            published_uuid="abcdefab-cdef-4abc-8def-abcdefabcdef",
            output_path=chat_publish.generated_output_path(HTML, "Exact Fixture"),
            prompt_sha256=hashlib.sha256(
                chat_publish.build_prompt(HTML, "Exact Fixture").encode()
            ).hexdigest(),
        )
        self.assert_javascript_parses(session.expression)
        self.assertIn(chat_publish._EXACT_HUMAN_TEXT_JS.strip(), session.expression)
        self.assertIn("reconciled:true", session.expression)
        self.assertIn("await noActiveBinding()", session.expression)
        self.assertIn("privateSince", session.expression)
        self.assertIn("Date.now() - privateSince >= 30000", session.expression)
        self.assertIn("conversationRows.length !== matches.length", session.expression)
        self.assertEqual(session.expression.count("method:'DELETE'"), 2)

    def test_preconversion_cleanup_is_prompt_bound_and_precedes_artifact_resolution(self):
        organization_uuid = "11111111-2222-4333-8444-555555555555"
        conversation_uuid = "fedcba98-7654-4321-8fed-cba987654321"
        output_path = chat_publish.generated_output_path(HTML, "Exact Fixture")
        prompt = chat_publish.build_prompt(HTML, "Exact Fixture", output_path)
        binding = chat_publish.ChatPreconversionBinding(
            chat_url="https://claude.ai/chat/" + conversation_uuid,
            organization_uuid=organization_uuid,
            conversation_uuid=conversation_uuid,
            output_path=output_path,
            request_title="Exact Fixture",
            source_sha256=hashlib.sha256(HTML.encode()).hexdigest(),
            prompt_sha256=hashlib.sha256(prompt.encode()).hexdigest(),
            receipt_stage="file_bound",
        )

        class FakeSession:
            expression = None

            def evaluate(self, expression, **_kwargs):
                self.expression = expression
                return {}

        session = FakeSession()
        driver = chat_publish.ChatArtifactPublisher(
            9222,
            expected_email_sha256="0" * 64,
            organization_uuid=organization_uuid,
        )
        driver._lifecycle_transaction(
            session,
            binding,
            HTML,
            action="delete_preconversion_conversation",
            published_uuid=None,
            output_path=output_path,
            prompt_sha256=binding.prompt_sha256,
            expected_prompt=prompt,
        )
        self.assert_javascript_parses(session.expression)
        self.assertLess(
            session.expression.index("if (preconversion)"),
            session.expression.index("const catalog = await resolveCatalog()"),
        )
        self.assertIn("await conversationCatalogAbsent()", session.expression)
        self.assertIn("await noActiveBinding()", session.expression)
        self.assertIn("versions.status === 404", session.expression)
        self.assertIn(
            "keysAre(result.value, ['artifact_versions'])", session.expression
        )
        self.assertIn("result.value.artifact_versions.length === 0", session.expression)
        self.assertIn("humanText !== EXPECTED.expectedPrompt", session.expression)
        self.assertIn("EXPECTED.preconversionStage === 'conversation_bound'", session.expression)
        self.assertIn("create.file_text === SOURCE", session.expression)
        self.assertIn("const deleteConversationOnce", session.expression)
        self.assertIn("ACTION === 'reconcile_conversion_pending'", session.expression)
        self.assertIn("currentRows.length !== 1", session.expression)
        self.assertIn("const exactRecoveredState", session.expression)
        self.assertIn("EXPECTED.allowMutation !== true", session.expression)
        self.assertIn("conversion_privacy_retry_blocked", session.expression)
        self.assertEqual(
            session.expression.count(
                "body:JSON.stringify({visibility:'private'})"
            ),
            1,
        )
        self.assertEqual(session.expression.count("method:'DELETE'"), 2)

    def test_preconversion_cleanup_completion_is_strict_and_callback_bound(self):
        organization_uuid = "11111111-2222-4333-8444-555555555555"
        conversation_uuid = "fedcba98-7654-4321-8fed-cba987654321"
        output_path = chat_publish.generated_output_path(HTML, "Exact Fixture")
        prompt = chat_publish.build_prompt(HTML, "Exact Fixture", output_path)
        binding = chat_publish.ChatPreconversionBinding(
            chat_url="https://claude.ai/chat/" + conversation_uuid,
            organization_uuid=organization_uuid,
            conversation_uuid=conversation_uuid,
            output_path=output_path,
            request_title="Exact Fixture",
            source_sha256=hashlib.sha256(HTML.encode()).hexdigest(),
            prompt_sha256=hashlib.sha256(prompt.encode()).hexdigest(),
            receipt_stage="conversation_bound",
        )
        completion = {
            "stage": "preconversion_delete_complete",
            "mutationAttempted": True,
            "conversationUuid": conversation_uuid,
        }
        driver = chat_publish.ChatArtifactPublisher(
            9222,
            expected_email_sha256="0" * 64,
            organization_uuid=organization_uuid,
        )
        recorded = mock.Mock()

        def complete(*_args, **kwargs):
            kwargs["on_result"](completion)
            return completion, False

        with mock.patch.object(
            driver, "_run_lifecycle_transaction", side_effect=complete
        ):
            self.assertTrue(
                driver.delete_preconversion_conversation(
                    binding, HTML, prompt, on_verified=recorded
                )
            )
        recorded.assert_called_once_with()
        self.assertFalse(
            driver._require_preconversion_cleanup_completion(
                {**completion, "artifactUuid": "a"}, binding
            )
        )

    def test_conversion_reconciliation_accepts_rfc_uuidv7_and_strict_metadata(self):
        organization_uuid = "11111111-2222-4333-8444-555555555555"
        conversation_uuid = "fedcba98-7654-4321-8fed-cba987654321"
        output_path = chat_publish.generated_output_path(HTML, "Exact Fixture")
        prompt = chat_publish.build_prompt(HTML, "Exact Fixture", output_path)
        binding = chat_publish.ChatPreconversionBinding(
            chat_url="https://claude.ai/chat/" + conversation_uuid,
            organization_uuid=organization_uuid,
            conversation_uuid=conversation_uuid,
            output_path=output_path,
            request_title="Exact Fixture",
            source_sha256=hashlib.sha256(HTML.encode()).hexdigest(),
            prompt_sha256=hashlib.sha256(prompt.encode()).hexdigest(),
            receipt_stage="conversion_pending",
        )
        completion = {
            "stage": "conversion_reconcile_complete",
            "mutationAttempted": False,
            "reconciled": True,
            "conversationUuid": conversation_uuid,
            "artifactUuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "versionUuid": "99999999-8888-4777-8666-555555555555",
            "messageUuid": "12345678-1234-7234-a234-123456789abc",
            "artifactIdentifier": "exact-fixture",
            "artifactType": "text/html",
            "codeLanguage": "html",
            "title": output_path.rsplit("/", 1)[-1],
            "visibility": "shared",
        }
        result = chat_publish.ChatArtifactPublisher._parse_conversion_reconciliation(
            completion, binding
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.message_uuid, completion["messageUuid"])
        self.assertIsNone(
            chat_publish.ChatArtifactPublisher._parse_conversion_reconciliation(
                {**completion, "visibility": "public"}, binding
            )
        )
        self.assertIsNone(
            chat_publish.ChatArtifactPublisher._parse_conversion_reconciliation(
                {**completion, "extra": True}, binding
            )
        )

    def test_public_reconciliation_is_read_only_exact_and_callback_bound(self):
        binding = self.artifact_binding()
        original = chat_publish.ChatPublishResult(
            url=binding.chat_url,
            chat_url=binding.chat_url,
            artifact_uuid=binding.artifact_uuid,
            version_uuid=binding.version_uuid,
            public=False,
            source_sha256=hashlib.sha256(HTML.encode()).hexdigest(),
            organization_uuid=binding.organization_uuid,
            conversation_uuid=binding.conversation_uuid,
            message_uuid=binding.message_uuid,
            artifact_identifier=binding.artifact_identifier,
            artifact_type=binding.artifact_type,
            code_language=binding.code_language,
            title=binding.title,
        )
        published = "abcdefab-cdef-4abc-8def-abcdefabcdef"
        completion = {
            "stage": "reconcile_complete",
            "publicState": "active",
            "publishedUuid": published,
            "mutationAttempted": False,
            "reconciled": True,
            "artifactUuid": binding.artifact_uuid,
            "versionUuid": binding.version_uuid,
            "messageUuid": binding.message_uuid,
            "conversationUuid": binding.conversation_uuid,
        }
        driver = chat_publish.ChatArtifactPublisher(
            9222,
            expected_email_sha256="0" * 64,
            organization_uuid=binding.organization_uuid,
        )
        recorded = mock.Mock()

        def complete_transaction(*_args, **kwargs):
            kwargs["on_result"](completion)
            return completion, False

        with mock.patch.object(
            driver,
            "_run_lifecycle_transaction",
            side_effect=complete_transaction,
        ) as transaction:
            result = driver.reconcile_public(
                original, HTML, on_reconciled=recorded
            )
        self.assertTrue(result.public)
        self.assertEqual(result.published_uuid, published)
        self.assertEqual(
            result.url, "https://claude.ai/public/artifacts/" + published
        )
        recorded.assert_called_once_with(result)
        self.assertEqual(transaction.call_args.kwargs["action"], "reconcile_public")
        self.assertIsNone(transaction.call_args.kwargs["published_uuid"])
        self.assertIsNone(
            driver._parse_public_reconciliation(
                {**completion, "mutationAttempted": 0},
                original=original,
                binding=binding,
            )
        )
        self.assertIsNone(
            driver._parse_public_reconciliation(
                {
                    **{
                        key: value
                        for key, value in completion.items()
                        if key != "publishedUuid"
                    },
                    "publicState": "private",
                },
                original=original,
                binding=binding,
            )
        )

    def test_lifecycle_receipt_callback_precedes_local_target_cleanup_error(self):
        binding = self.artifact_binding()
        published = "abcdefab-cdef-4abc-8def-abcdefabcdef"
        result = chat_publish.ChatPublishResult(
            url="https://claude.ai/public/artifacts/" + published,
            chat_url=binding.chat_url,
            artifact_uuid=binding.artifact_uuid,
            version_uuid=binding.version_uuid,
            public=True,
            source_sha256=hashlib.sha256(HTML.encode()).hexdigest(),
            published_uuid=published,
            organization_uuid=binding.organization_uuid,
            conversation_uuid=binding.conversation_uuid,
            message_uuid=binding.message_uuid,
            artifact_identifier=binding.artifact_identifier,
            artifact_type=binding.artifact_type,
            code_language=binding.code_language,
            title=binding.title,
        )

        class FakeSession:
            def close(self):
                return None

        completion = {
            "stage": "unpublish_complete",
            "mutationAttempted": True,
            "artifactUuid": binding.artifact_uuid,
            "versionUuid": binding.version_uuid,
            "messageUuid": binding.message_uuid,
            "conversationUuid": binding.conversation_uuid,
            "publishedUuid": published,
        }
        driver = chat_publish.ChatArtifactPublisher(
            9222,
            expected_email_sha256="0" * 64,
            organization_uuid=binding.organization_uuid,
        )
        recorded = mock.Mock()
        with mock.patch.object(
            driver, "_create_chat_target", return_value=("target", FakeSession())
        ), mock.patch.object(
            driver, "_lifecycle_transaction", return_value=completion
        ), mock.patch.object(
            driver, "_close_target", side_effect=FrameError("close failed")
        ), self.assertRaisesRegex(FrameError, "local tab cleanup failed"):
            driver.unpublish(result, HTML, on_verified=recorded)
        recorded.assert_called_once_with()

    def test_conversion_is_one_shot_and_reads_back_exact_conversation_version(self):
        expected = self.artifact_binding()
        output_path = chat_publish.generated_output_path(HTML, "Exact Fixture")
        prompt = chat_publish.build_prompt(HTML, "Exact Fixture", output_path)
        file_binding = chat_publish.ChatFileBinding(
            chat_url=expected.chat_url,
            organization_uuid=expected.organization_uuid,
            conversation_uuid=expected.conversation_uuid,
            output_path=output_path,
        )

        class FakeSession:
            def __init__(self):
                self.expressions = []

            def evaluate(self, expression, **_kwargs):
                self.expressions.append(expression)
                return {
                    "stage": "complete",
                    "organizationUuid": expected.organization_uuid,
                    "conversationUuid": expected.conversation_uuid,
                    "artifactUuid": expected.artifact_uuid,
                    "versionUuid": expected.version_uuid,
                    "messageUuid": expected.message_uuid,
                    "artifactIdentifier": expected.artifact_identifier,
                    "artifactType": expected.artifact_type,
                    "codeLanguage": expected.code_language,
                    "title": expected.title,
                }

        session = FakeSession()
        driver = chat_publish.ChatArtifactPublisher(
            9222,
            expected_email_sha256="0" * 64,
            organization_uuid=expected.organization_uuid,
        )
        binding = driver._convert_file_to_artifact(
            session, file_binding, HTML, prompt
        )
        self.assertEqual(binding, expected)
        transcript = session.expressions[0]
        self.assert_javascript_parses(transcript)
        self.assertIn(chat_publish._EXACT_HUMAN_TEXT_JS.strip(), transcript)
        self.assertEqual(transcript.count("convert-file-to-artifact"), 1)
        self.assertIn("JSON.stringify({path:OUTPUT_PATH, operation:'share'})", transcript)
        self.assertIn("item.chat_conversation_uuid === CONVERSATION", transcript)
        self.assertIn("row.result_state === SOURCE", transcript)
        self.assertIn("Math.min(10000, limit + 30)", transcript)
        self.assertIn("visibility:'private'", transcript)
        self.assertNotIn("share_from_content", transcript)
        self.assertNotIn("/publish_artifact", transcript)

    def test_public_mapping_verifier_binds_distinct_uuid_and_exact_source(self):
        binding = self.artifact_binding()
        published_uuid = "abcdefab-cdef-4abc-8def-abcdefabcdef"

        class FakeSession:
            def __init__(self):
                self.expressions = []

            def evaluate(self, expression, **_kwargs):
                self.expressions.append(expression)
                return {"ok": True}

        session = FakeSession()
        chat_publish.ChatArtifactPublisher(
            9222,
            expected_email_sha256="0" * 64,
            organization_uuid=binding.organization_uuid,
        )._verify_public_mapping(session, binding, HTML, published_uuid)
        self.assertEqual(len(session.expressions), 1)
        transcript = session.expressions[0]
        self.assert_javascript_parses(transcript)
        self.assertIn(published_uuid, transcript)
        self.assertIn(binding.artifact_uuid, transcript)
        self.assertIn(binding.conversation_uuid, transcript)
        self.assertIn("latest_published_artifact_uuid", transcript)
        self.assertIn("include_deleted_artifacts=false", transcript)
        self.assertIn("version.result_state !== expected.source", transcript)
        self.assertIn("version.published_artifact_uuid !== expected.publishedUuid", transcript)
        self.assertIn("credentials:'omit'", transcript)

    def test_direct_publication_is_one_shot_and_uses_verified_provenance(self):
        binding = self.artifact_binding()
        published_uuid = "abcdefab-cdef-4abc-8def-abcdefabcdef"
        public_url = "https://claude.ai/public/artifacts/" + published_uuid

        class FakeSession:
            def __init__(self):
                self.expressions = []

            def evaluate(self, expression, **_kwargs):
                self.expressions.append(expression)
                return {
                    "stage": "published",
                    "mutationAttempted": True,
                    "publishedUuid": published_uuid,
                }

        session = FakeSession()
        driver = chat_publish.ChatArtifactPublisher(
            9222,
            expected_email_sha256="0" * 64,
            organization_uuid=binding.organization_uuid,
        )
        with mock.patch.object(
            driver, "_verify_public_mapping"
        ) as verified, mock.patch.object(
            driver, "_require_identity", return_value="0" * 64
        ), mock.patch.object(driver, "_require_chat_location"):
            self.assertEqual(
                driver._publish_direct(session, binding, HTML, "0" * 64),
                (public_url, published_uuid),
            )
        transcript = session.expressions[0]
        self.assertEqual(transcript.count("/publish_artifact"), 1)
        for field in (
            "title:catalog.title",
            "artifact_type:catalog.artifact_type",
            "code_language:catalog.code_language",
            "message_uuid:version.message_uuid",
            "conversation_uuid:EXPECTED.conversationUuid",
            "artifact_identifier:catalog.artifact_identifier",
            "content:version.result_state",
            "artifact_version_uuid:version.uuid",
        ):
            self.assertIn(field, transcript)
        self.assertNotIn("Publish & copy link", transcript)
        verified.assert_called_once_with(session, binding, HTML, published_uuid)

    def test_private_publish_orchestrates_exact_file_and_conversion(self):
        binding = self.artifact_binding()
        output_path = chat_publish.generated_output_path(HTML, "Exact Fixture")
        prompt = chat_publish.build_prompt(HTML, "Exact Fixture", output_path)
        file_binding = chat_publish.ChatFileBinding(
            chat_url=binding.chat_url,
            organization_uuid=binding.organization_uuid,
            conversation_uuid=binding.conversation_uuid,
            output_path=output_path,
        )

        class FakeSession:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        session = FakeSession()
        driver = chat_publish.ChatArtifactPublisher(
            9222,
            expected_email_sha256="0" * 64,
            organization_uuid=binding.organization_uuid,
        )
        with mock.patch.object(
            driver, "_create_chat_target", return_value=("controlled-target", session)
        ), mock.patch.object(
            driver, "_close_target"
        ) as closed, mock.patch.object(
            driver, "_require_identity", return_value="0" * 64
        ), mock.patch.object(
            driver, "_wait_for_editor"
        ), mock.patch.object(
            driver, "_send_prompt"
        ) as sent, mock.patch.object(
            driver, "_wait_for_exact_file", return_value=file_binding
        ) as waited, mock.patch.object(
            driver, "_convert_file_to_artifact", return_value=binding
        ) as converted, mock.patch.object(
            driver,
            "_publish_direct",
            side_effect=AssertionError("private creation must not publish"),
        ):
            result = driver.publish(HTML, "Exact Fixture")
        self.assertTrue(session.closed)
        closed.assert_called_once_with("controlled-target")
        self.assertEqual(result.url, binding.chat_url)
        self.assertFalse(result.public)
        self.assertIsNone(result.published_uuid)
        sent.assert_called_once_with(session, prompt)
        self.assertEqual(waited.call_args.args, (session, HTML, prompt, output_path))
        self.assertIsNone(waited.call_args.kwargs["on_conversation_binding"])
        self.assertEqual(converted.call_args.args, (session, file_binding, HTML, prompt))
        self.assertIsNone(converted.call_args.kwargs["on_binding"])
        self.assertIsNone(converted.call_args.kwargs["on_published_uuid"])

    def test_public_publish_orchestrates_conversion_then_direct_mapping(self):
        binding = self.artifact_binding()
        published_uuid = "abcdefab-cdef-4abc-8def-abcdefabcdef"
        public_url = "https://claude.ai/public/artifacts/" + published_uuid
        output_path = chat_publish.generated_output_path(HTML, "Exact Fixture")
        prompt = chat_publish.build_prompt(HTML, "Exact Fixture", output_path)
        file_binding = chat_publish.ChatFileBinding(
            chat_url=binding.chat_url,
            organization_uuid=binding.organization_uuid,
            conversation_uuid=binding.conversation_uuid,
            output_path=output_path,
        )

        class FakeSession:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        session = FakeSession()
        driver = chat_publish.ChatArtifactPublisher(
            9222,
            expected_email_sha256="0" * 64,
            organization_uuid=binding.organization_uuid,
        )
        with mock.patch.object(
            driver, "_create_chat_target", return_value=("controlled-target", session)
        ), mock.patch.object(
            driver, "_close_target"
        ) as closed, mock.patch.object(
            driver, "_require_identity", return_value="0" * 64
        ), mock.patch.object(driver, "_wait_for_editor"), mock.patch.object(
            driver, "_send_prompt"
        ), mock.patch.object(
            driver, "_wait_for_exact_file", return_value=file_binding
        ) as waited, mock.patch.object(
            driver, "_convert_file_to_artifact", return_value=binding
        ) as converted, mock.patch.object(
            driver, "_publish_direct", return_value=(public_url, published_uuid)
        ) as published:
            result = driver.publish(HTML, "Exact Fixture", public=True)
        self.assertTrue(session.closed)
        closed.assert_called_once_with("controlled-target")
        self.assertEqual(result.url, public_url)
        self.assertTrue(result.public)
        self.assertEqual(result.published_uuid, published_uuid)
        self.assertNotEqual(result.published_uuid, result.artifact_uuid)
        self.assertEqual(waited.call_args.args, (session, HTML, prompt, output_path))
        self.assertIsNone(waited.call_args.kwargs["on_conversation_binding"])
        self.assertEqual(converted.call_args.args, (session, file_binding, HTML, prompt))
        self.assertIsNone(converted.call_args.kwargs["on_binding"])
        self.assertIsNone(converted.call_args.kwargs["on_published_uuid"])
        self.assertEqual(published.call_args.args, (session, binding, HTML, "0" * 64))
        self.assertIsNone(published.call_args.kwargs["on_published_uuid"])


class PublishCliSurfaceTests(unittest.TestCase):
    ORGANIZATION_UUID = "11111111-2222-4333-8444-555555555555"
    ACCOUNT_EMAIL_SHA256 = "0" * 64
    CONVERSATION_UUID = "fedcba98-7654-4321-8fed-cba987654321"
    ARTIFACT_UUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    VERSION_UUID = "99999999-8888-4777-8666-555555555555"
    MESSAGE_UUID = "12345678-1234-4234-8234-123456789abc"
    PUBLISHED_UUID = "abcdefab-cdef-4abc-8def-abcdefabcdef"

    def html_file(self, directory: str) -> Path:
        path = Path(directory) / "fixture.html"
        path.write_text(HTML, encoding="utf-8")
        return path

    def conversation_contract(self, *, public=True):
        chat_url = "https://claude.ai/chat/" + self.CONVERSATION_UUID
        output_path = chat_publish.generated_output_path(HTML, "Exact Fixture")
        prompt = chat_publish.build_prompt(HTML, "Exact Fixture", output_path)
        conversation_binding = chat_publish.ChatConversationBinding(
            chat_url=chat_url,
            organization_uuid=self.ORGANIZATION_UUID,
            conversation_uuid=self.CONVERSATION_UUID,
        )
        file_binding = chat_publish.ChatFileBinding(
            chat_url=chat_url,
            organization_uuid=self.ORGANIZATION_UUID,
            conversation_uuid=self.CONVERSATION_UUID,
            output_path=output_path,
        )
        artifact_binding = chat_publish.ChatArtifactBinding(
            chat_url=chat_url,
            organization_uuid=self.ORGANIZATION_UUID,
            conversation_uuid=self.CONVERSATION_UUID,
            artifact_uuid=self.ARTIFACT_UUID,
            version_uuid=self.VERSION_UUID,
            message_uuid=self.MESSAGE_UUID,
            artifact_identifier="exact-fixture",
            artifact_type="text/html",
            code_language="html",
            title="Exact Fixture",
        )
        published_uuid = self.PUBLISHED_UUID if public else None
        result = chat_publish.ChatPublishResult(
            url=(
                "https://claude.ai/public/artifacts/" + self.PUBLISHED_UUID
                if public
                else chat_url
            ),
            chat_url=chat_url,
            artifact_uuid=self.ARTIFACT_UUID,
            version_uuid=self.VERSION_UUID,
            public=public,
            source_sha256=hashlib.sha256(HTML.encode()).hexdigest(),
            published_uuid=published_uuid,
            organization_uuid=self.ORGANIZATION_UUID,
            conversation_uuid=self.CONVERSATION_UUID,
            message_uuid=self.MESSAGE_UUID,
            artifact_identifier="exact-fixture",
            artifact_type="text/html",
            code_language="html",
            title="Exact Fixture",
            output_path=output_path,
            prompt_sha256=hashlib.sha256(prompt.encode()).hexdigest(),
        )
        return conversation_binding, file_binding, artifact_binding, result

    def write_conversation_receipt(self, directory: str, *, public=True, name="receipt.jsonl"):
        receipt_path = Path(directory) / name
        conversation_binding, file_binding, artifact_binding, result = (
            self.conversation_contract(public=public)
        )
        journal = publish._ConversationReceiptJournal(
            str(receipt_path),
            organization_uuid=self.ORGANIZATION_UUID,
            account_email_sha256=self.ACCOUNT_EMAIL_SHA256,
            source=HTML,
            output_path=file_binding.output_path,
            request_title="Exact Fixture",
            prompt_sha256=result.prompt_sha256,
            requested_public=public,
        )
        try:
            journal.record_conversation(conversation_binding)
            journal.record_file(file_binding)
            journal.record_conversion_intent()
            journal.record_binding(artifact_binding)
            if public:
                journal.record_published(artifact_binding, self.PUBLISHED_UUID)
            journal.record_complete(result)
        finally:
            journal.close()
        return receipt_path, result

    def write_converted_conversation_receipt(
        self, directory: str, name="receipt.jsonl", *, requested_public=False
    ):
        receipt_path = Path(directory) / name
        conversation_binding, file_binding, artifact_binding, result = (
            self.conversation_contract(public=False)
        )
        journal = publish._ConversationReceiptJournal(
            str(receipt_path),
            organization_uuid=self.ORGANIZATION_UUID,
            account_email_sha256=self.ACCOUNT_EMAIL_SHA256,
            source=HTML,
            output_path=file_binding.output_path,
            request_title="Exact Fixture",
            prompt_sha256=result.prompt_sha256,
            requested_public=requested_public,
        )
        try:
            journal.record_conversation(conversation_binding)
            journal.record_file(file_binding)
            journal.record_conversion_intent()
            journal.record_binding(artifact_binding)
        finally:
            journal.close()
        return receipt_path, result

    def write_partial_conversation_receipt(
        self, directory: str, *, stage="conversation_bound", name="receipt.jsonl"
    ):
        receipt_path = Path(directory) / name
        conversation_binding, file_binding, _artifact_binding, result = (
            self.conversation_contract(public=False)
        )
        journal = publish._ConversationReceiptJournal(
            str(receipt_path),
            organization_uuid=self.ORGANIZATION_UUID,
            account_email_sha256=self.ACCOUNT_EMAIL_SHA256,
            source=HTML,
            output_path=file_binding.output_path,
            request_title="Exact Fixture",
            prompt_sha256=result.prompt_sha256,
            requested_public=False,
        )
        try:
            journal.record_conversation(conversation_binding)
            if stage in {"file_bound", "conversion_pending"}:
                journal.record_file(file_binding)
                if stage == "conversion_pending":
                    journal.record_conversion_intent()
            elif stage != "conversation_bound":
                raise AssertionError("unsupported partial receipt stage")
        finally:
            journal.close()
        return receipt_path

    def seeded_contract(self):
        _conversation, _file, _artifact, seed_result = self.conversation_contract(
            public=True
        )
        seed = chat_seeded_publish.SeedBinding(
            organization_uuid=self.ORGANIZATION_UUID,
            account_email_sha256=self.ACCOUNT_EMAIL_SHA256,
            published_uuid=seed_result.published_uuid,
            conversation_uuid=seed_result.conversation_uuid,
            artifact_uuid=seed_result.artifact_uuid,
            version_uuid=seed_result.version_uuid,
            message_uuid=seed_result.message_uuid,
            artifact_identifier=seed_result.artifact_identifier,
            artifact_type=seed_result.artifact_type,
            code_language=seed_result.code_language,
            title=seed_result.title,
            source=HTML,
            source_sha256=seed_result.source_sha256,
        )
        clone = chat_seeded_publish.SeededCloneBinding(
            seed=seed,
            conversation_uuid="55555555-aaaa-4bbb-8ccc-666666666666",
            artifact_uuid="66666666-aaaa-4bbb-8ccc-777777777777",
            version_uuid="77777777-aaaa-4bbb-8ccc-888888888888",
            message_uuid="88888888-aaaa-4bbb-8ccc-999999999999",
            artifact_identifier="server-issued-clone",
            artifact_type=seed.artifact_type,
            code_language=seed.code_language,
            title=seed.title,
        )
        target = HTML + "\n<!-- seeded target -->\n"
        result = chat_seeded_publish.SeededPublicResult(
            clone=clone,
            published_uuid="99999999-aaaa-4bbb-8ccc-aaaaaaaaaaaa",
            public_source=target,
            public_source_sha256=hashlib.sha256(target.encode()).hexdigest(),
        )
        return seed, clone, result, target

    def write_seeded_receipt(self, directory: str, *, stage="published"):
        seed, clone, result, target = self.seeded_contract()
        path = Path(directory) / "seeded-target.jsonl"
        journal = chat_seeded_receipt.SeededReceiptJournal(
            str(path), seed=seed, target_source=target
        )
        try:
            journal.mark_remix_pending()
            journal.record_clone(clone)
            journal.mark_publish_pending()
            journal.record_published(result)
        finally:
            journal.close()
        if stage != "published":
            lifecycle = chat_seeded_receipt.SeededReceiptLifecycle(
                str(path),
                organization_uuid=self.ORGANIZATION_UUID,
                account_email_sha256=self.ACCOUNT_EMAIL_SHA256,
                seed_source=HTML,
                target_source=target,
            )
            try:
                lifecycle.mark_unpublish_pending(result)
                lifecycle.mark_unpublished()
                if stage == "deleted":
                    lifecycle.mark_delete_pending(lifecycle.result())
                    lifecycle.mark_deleted()
                elif stage != "unpublished":
                    raise AssertionError("unsupported seeded stage")
            finally:
                lifecycle.close()
        return path, result, target

    @staticmethod
    def receipt_records(receipt_path: Path):
        return [
            json.loads(line)
            for line in receipt_path.read_text(encoding="utf-8").splitlines()
        ]

    def test_html_reader_preserves_crlf_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "crlf.html"
            path.write_bytes(b"<!doctype html>\r\n<body>exact</body>\r\n")
            self.assertEqual(
                publish.to_html(str(path)),
                "<!doctype html>\r\n<body>exact</body>\r\n",
            )

    def test_chat_filename_fallback_title_is_receipt_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "my  page.html"
            path.write_text("<!doctype html><p>ok</p>\n", encoding="utf-8")
            receipt_path = Path(directory) / "future.jsonl"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                publish.main(
                    [
                        str(path),
                        "--surface",
                        "chat",
                        "--organization-uuid",
                        self.ORGANIZATION_UUID,
                        "--account-email-sha256",
                        self.ACCOUNT_EMAIL_SHA256,
                        "--receipt",
                        str(receipt_path),
                        "--dry-run",
                    ]
                )
            self.assertIn('"title": "my page"', output.getvalue())

    def test_chat_dry_run_never_constructs_browser_driver(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.html_file(directory)
            receipt_path = Path(directory) / "future-receipt.jsonl"
            output = io.StringIO()
            with mock.patch.object(
                chat_publish.ChatArtifactPublisher,
                "__init__",
                side_effect=AssertionError("browser driver should not be constructed"),
            ), contextlib.redirect_stdout(output):
                publish.main(
                    [
                        str(path),
                        "--surface",
                        "chat",
                        "--organization-uuid",
                        "11111111-2222-4333-8444-555555555555",
                        "--account-email-sha256",
                        "0" * 64,
                        "--receipt",
                        str(receipt_path),
                        "--dry-run",
                        "--public",
                    ]
                )
            self.assertFalse(receipt_path.exists())
        rendered = output.getvalue()
        self.assertIn('"surface": "chat"', rendered)
        self.assertIn('"public": true', rendered)
        self.assertIn('"outputPath": "/mnt/user-data/outputs/', rendered)
        self.assertIn('"sourceSha256":', rendered)
        self.assertNotIn(HTML, rendered)

    def test_chat_dispatches_to_browser_backed_driver(self):
        result = chat_publish.ChatPublishResult(
            url="https://claude.ai/chat/11111111-2222-4333-8444-555555555555",
            chat_url="https://claude.ai/chat/11111111-2222-4333-8444-555555555555",
            artifact_uuid="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            version_uuid="99999999-8888-4777-8666-555555555555",
            public=False,
            source_sha256=hashlib.sha256(HTML.encode()).hexdigest(),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self.html_file(directory)
            receipt_path = Path(directory) / "private-receipt.jsonl"
            output = io.StringIO()
            error = io.StringIO()
            journal = mock.Mock()
            with mock.patch.object(
                chat_publish.ChatArtifactPublisher,
                "publish",
                autospec=True,
                return_value=result,
            ) as called, mock.patch.object(
                publish, "_ConversationReceiptJournal", return_value=journal
            ) as journal_type, contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                publish.main(
                    [
                        str(path),
                        "--surface",
                        "chat",
                        "--browser-port",
                        "9333",
                        "--account-email-sha256",
                        "0" * 64,
                        "--organization-uuid",
                        "11111111-2222-4333-8444-555555555555",
                        "--receipt",
                        str(receipt_path),
                    ]
                )
        self.assertEqual(output.getvalue().strip(), result.url)
        self.assertIn("surface: chat", error.getvalue())
        self.assertTrue(called.called)
        _, source, title = called.call_args.args
        self.assertEqual(source, HTML)
        self.assertEqual(title, "Exact Fixture")
        self.assertFalse(called.call_args.kwargs["public"])
        journal_type.assert_called_once()
        journal.record_complete.assert_called_once_with(result)
        journal.close.assert_called_once_with()
        self.assertEqual(
            called.call_args.args[0].organization_uuid,
            "11111111-2222-4333-8444-555555555555",
        )

    def test_public_conversation_cli_reports_distinct_public_uuid(self):
        published_uuid = "abcdefab-cdef-4abc-8def-abcdefabcdef"
        result = chat_publish.ChatPublishResult(
            url="https://claude.ai/public/artifacts/" + published_uuid,
            chat_url="https://claude.ai/chat/11111111-2222-4333-8444-555555555555",
            artifact_uuid="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            version_uuid="99999999-8888-4777-8666-555555555555",
            public=True,
            source_sha256=hashlib.sha256(HTML.encode()).hexdigest(),
            published_uuid=published_uuid,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self.html_file(directory)
            receipt_path = Path(directory) / "public-receipt.jsonl"
            error = io.StringIO()
            journal = mock.Mock()
            with mock.patch.object(
                chat_publish.ChatArtifactPublisher,
                "publish",
                autospec=True,
                return_value=result,
            ), mock.patch.object(
                publish, "_ConversationReceiptJournal", return_value=journal
            ), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(error):
                publish.main(
                    [
                        str(path),
                        "--surface",
                        "chat",
                        "--public",
                        "--account-email-sha256",
                        "0" * 64,
                        "--organization-uuid",
                        "11111111-2222-4333-8444-555555555555",
                        "--receipt",
                        str(receipt_path),
                    ]
                )
        self.assertIn("artifact: " + result.artifact_uuid, error.getvalue())
        self.assertIn("published: " + published_uuid, error.getvalue())
        self.assertNotEqual(result.artifact_uuid, published_uuid)

    def test_chat_rejects_code_only_lifecycle_options(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.html_file(directory)
            with self.assertRaisesRegex(FrameError, "does not support --slug"):
                publish.main(
                    [str(path), "--surface", "chat", "--slug", "11111111-2222-4333-8444-555555555555"]
                )

    def test_code_rejects_chat_only_driver_options(self):
        with self.assertRaisesRegex(FrameError, "only valid with --surface chat"):
            publish.main(["--browser-port", "9333"])

    def test_code_file_dry_run_loads_no_credentials_or_provider_session(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.html_file(directory)
            output = io.StringIO()
            with mock.patch.object(
                publish.frames,
                "Session",
                side_effect=AssertionError("dry run must not construct a session"),
            ), mock.patch.object(
                publish.frames,
                "verify_exact_published_content",
                side_effect=AssertionError("dry run must not read provider content"),
            ), contextlib.redirect_stdout(output):
                publish.main([str(path), "--dry-run", "--public"])
        rendered = output.getvalue()
        self.assertIn("credentials not loaded", rendered)
        self.assertIn("POST https://api.anthropic.com/api/frame/deploy/direct", rendered)
        self.assertIn("then PATCH", rendered)

    def test_code_delete_dry_run_makes_zero_provider_calls(self):
        slug = "11111111-2222-4333-8444-555555555555"
        output = io.StringIO()
        with mock.patch.object(
            publish.frames,
            "Session",
            side_effect=AssertionError("dry run must not construct a session"),
        ), mock.patch.object(
            publish.frames,
            "delete",
            side_effect=AssertionError("dry run must not delete"),
        ), contextlib.redirect_stdout(output):
            publish.main(["--delete", "--slug", slug, "--dry-run"])
        self.assertIn("DELETE https://api.anthropic.com/api/frame/" + slug, output.getvalue())

    def test_code_audience_only_dry_runs_make_zero_provider_calls(self):
        slug = "11111111-2222-4333-8444-555555555555"
        for audience in ("--public", "--private"):
            with self.subTest(audience=audience):
                output = io.StringIO()
                with mock.patch.object(
                    publish.frames,
                    "Session",
                    side_effect=AssertionError("dry run must not construct a session"),
                ), mock.patch.object(
                    publish.frames,
                    "set_audience",
                    side_effect=AssertionError("dry run must not change audience"),
                ), mock.patch.object(
                    publish,
                    "report_public",
                    side_effect=AssertionError("dry run must not probe public state"),
                ), contextlib.redirect_stdout(output):
                    publish.main([audience, "--slug", slug, "--dry-run"])
                rendered = output.getvalue()
                self.assertIn("GET https://api.anthropic.com/api/frame/" + slug, rendered)
                self.assertIn("then PATCH", rendered)

    def test_code_exact_publish_readback_accepts_only_matching_live_content(self):
        slug = "11111111-2222-4333-8444-555555555555"
        version = "1741803761-9f3a"
        page = publish.frames.compose(HTML)
        session = mock.Mock(timeout=30)
        with mock.patch.object(
            publish.frames,
            "boot",
            return_value={"live": version, "assetToken": "PRIVATE-CAPABILITY"},
        ) as booted, mock.patch.object(
            publish.frames,
            "content",
            return_value="<!-- provider runtime -->\n" + page,
        ) as fetched:
            self.assertTrue(
                publish.frames.verify_exact_published_content(
                    session, slug, version, page
                )
            )
        booted.assert_called_once_with(session, slug)
        fetched.assert_called_once_with(
            session, slug, version, "PRIVATE-CAPABILITY"
        )

    def test_code_exact_publish_readback_accepts_measured_head_runtime_insertion(self):
        slug = "11111111-2222-4333-8444-555555555555"
        version = "1741803761-9f3a"
        page = publish.frames.compose(HTML)
        split = page.index("<head") + len("<head")
        runtime = (
            f'><!-- frame-runtime --><base href="/_f/{version}/">'
            '<script>window.__FRAME_PREAMBLE={"capabilities":{}}</script>'
            '<!-- /frame-runtime --'
        )
        served = page[:split] + runtime + page[split:]
        session = mock.Mock(timeout=30)
        with mock.patch.object(
            publish.frames,
            "boot",
            return_value={"live": version, "assetToken": "PRIVATE-CAPABILITY"},
        ), mock.patch.object(
            publish.frames,
            "content",
            return_value=served,
        ):
            self.assertTrue(
                publish.frames.verify_exact_published_content(
                    session, slug, version, page
                )
            )

    def test_code_exact_publish_readback_rejects_wrong_runtime_version(self):
        slug = "11111111-2222-4333-8444-555555555555"
        version = "1741803761-9f3a"
        page = publish.frames.compose(HTML)
        split = page.index("<head") + len("<head")
        runtime = (
            '><!-- frame-runtime --><base href="/_f/other-version/">'
            '<script>window.__FRAME_PREAMBLE={}</script><!-- /frame-runtime --'
        )
        served = page[:split] + runtime + page[split:]
        session = mock.Mock(timeout=30)
        with mock.patch.object(
            publish.frames,
            "boot",
            return_value={"live": version, "assetToken": "PRIVATE-CAPABILITY"},
        ), mock.patch.object(publish.frames, "content", return_value=served):
            with self.assertRaisesRegex(FrameError, "exact composed page"):
                publish.frames.verify_exact_published_content(
                    session, slug, version, page
                )

    def test_code_exact_publish_readback_rejects_a_different_live_version(self):
        slug = "11111111-2222-4333-8444-555555555555"
        version = "1741803761-9f3a"
        session = mock.Mock(timeout=30)
        with mock.patch.object(
            publish.frames,
            "boot",
            return_value={"live": "1741803762-abcd", "assetToken": "PRIVATE-CAPABILITY"},
        ), mock.patch.object(
            publish.frames,
            "content",
            side_effect=AssertionError("a different live version must not be fetched"),
        ):
            with self.assertRaisesRegex(FrameError, "exact live version"):
                publish.frames.verify_exact_published_content(
                    session, slug, version, publish.frames.compose(HTML)
                )

    def test_code_exact_publish_readback_mismatch_fails_before_audience_change(self):
        slug = "11111111-2222-4333-8444-555555555555"
        version = "1741803761-9f3a"
        session = mock.Mock(timeout=30)
        with tempfile.TemporaryDirectory() as directory:
            path = self.html_file(directory)
            with mock.patch.object(
                publish.frames, "Session", return_value=session
            ), mock.patch.object(
                publish.frames,
                "publish",
                return_value={"slug": slug, "version": version},
            ), mock.patch.object(
                publish.frames,
                "boot",
                return_value={"live": version, "assetToken": "PRIVATE-CAPABILITY"},
            ), mock.patch.object(
                publish.frames,
                "content",
                return_value="different bytes",
            ), mock.patch.object(
                publish.frames,
                "set_audience",
                side_effect=AssertionError("mismatched content must not become public"),
            ):
                with self.assertRaisesRegex(FrameError, "exact composed page"):
                    publish.main([str(path), "--public"])

    def test_code_public_publish_requires_exact_anonymous_readback(self):
        slug = "11111111-2222-4333-8444-555555555555"
        version = "1741803761-9f3a"
        session = mock.Mock(timeout=30)
        with tempfile.TemporaryDirectory() as directory:
            path = self.html_file(directory)
            with mock.patch.object(
                publish.frames, "Session", return_value=session
            ), mock.patch.object(
                publish.frames,
                "publish",
                return_value={"slug": slug, "version": version},
            ), mock.patch.object(
                publish.frames,
                "verify_exact_published_content",
                return_value=True,
            ) as owner_verified, mock.patch.object(
                publish.frames,
                "set_audience",
                return_value=version,
            ) as audience_changed, mock.patch.object(
                publish.frames,
                "verify_exact_public_content",
                return_value=True,
            ) as public_verified, mock.patch.object(
                publish,
                "report_public",
                return_value=None,
            ), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                io.StringIO()
            ):
                publish.main([str(path), "--public"])

        expected_page = publish.frames.compose(HTML)
        owner_verified.assert_called_once_with(
            session, slug, version, expected_page
        )
        audience_changed.assert_called_once_with(
            session, slug, "public", on_wait=mock.ANY
        )
        public_verified.assert_called_once_with(slug, version, expected_page)

    def test_live_chat_requires_account_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.html_file(directory)
            with self.assertRaisesRegex(FrameError, "require --account-email-sha256"):
                publish.main(
                    [
                        str(path),
                        "--surface",
                        "chat",
                        "--organization-uuid",
                        "11111111-2222-4333-8444-555555555555",
                    ]
                )

    def test_conversation_chat_requires_receipt_after_identity_bindings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.html_file(directory)
            with mock.patch.object(
                chat_publish.ChatArtifactPublisher,
                "__init__",
                side_effect=AssertionError("receipt validation must precede browser access"),
            ), self.assertRaisesRegex(FrameError, "require --receipt"):
                publish.main(
                    [
                        str(path),
                        "--surface",
                        "chat",
                        "--account-email-sha256",
                        "0" * 64,
                        "--organization-uuid",
                        "11111111-2222-4333-8444-555555555555",
                    ]
                )

    def test_conversation_chat_requires_organization_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.html_file(directory)
            with self.assertRaisesRegex(FrameError, "requires --organization-uuid"):
                publish.main([str(path), "--surface", "chat", "--dry-run"])

    def test_conversation_chat_rejects_obsolete_preview_acknowledgement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.html_file(directory)
            with self.assertRaisesRegex(FrameError, "obsolete"):
                publish.main(
                    [
                        str(path),
                        "--surface",
                        "chat",
                        "--organization-uuid",
                        "11111111-2222-4333-8444-555555555555",
                        "--acknowledge-chat-preview-executes",
                        "--dry-run",
                    ]
                )

    def test_conversation_public_create_writes_owner_only_readable_receipt(self):
        conversation_binding, file_binding, artifact_binding, result = (
            self.conversation_contract(public=True)
        )

        def complete_publish(_driver, source, title, **options):
            self.assertEqual((source, title), (HTML, "Exact Fixture"))
            options["on_conversation_binding"](conversation_binding)
            options["on_file_binding"](file_binding)
            options["on_conversion_intent"]()
            options["on_binding"](artifact_binding)
            options["on_published_uuid"](artifact_binding, self.PUBLISHED_UUID)
            return result

        with tempfile.TemporaryDirectory() as directory:
            path = self.html_file(directory)
            receipt_path = Path(directory) / "public-receipt.jsonl"
            with mock.patch.object(
                chat_publish.ChatArtifactPublisher,
                "publish",
                autospec=True,
                side_effect=complete_publish,
            ), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                io.StringIO()
            ):
                publish.main(
                    [
                        str(path),
                        "--surface",
                        "chat",
                        "--public",
                        "--account-email-sha256",
                        self.ACCOUNT_EMAIL_SHA256,
                        "--organization-uuid",
                        self.ORGANIZATION_UUID,
                        "--receipt",
                        str(receipt_path),
                    ]
                )

            self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)
            records = self.receipt_records(receipt_path)
            self.assertEqual(
                [record["stage"] for record in records],
                [
                    "prepared",
                    "conversation_bound",
                    "file_bound",
                    "conversion_pending",
                    "converted",
                    "public_bound",
                    "published",
                ],
            )
            self.assertTrue(
                all(set(record) == publish._CONVERSATION_RECEIPT_KEYS for record in records)
            )
            lifecycle = publish._ConversationReceiptLifecycle(
                str(receipt_path),
                organization_uuid=self.ORGANIZATION_UUID,
                account_email_sha256=self.ACCOUNT_EMAIL_SHA256,
                source=HTML,
            )
            try:
                self.assertEqual(lifecycle.stage, "published")
                self.assertEqual(lifecycle.result(), result)
            finally:
                lifecycle.close()

            receipt_path.chmod(0o644)
            with self.assertRaisesRegex(FrameError, "mode 0600"):
                publish._ConversationReceiptLifecycle(
                    str(receipt_path),
                    organization_uuid=self.ORGANIZATION_UUID,
                    account_email_sha256=self.ACCOUNT_EMAIL_SHA256,
                    source=HTML,
                )

    def test_conversation_private_routes_public_receipt_to_unpublish_and_marks_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.html_file(directory)
            receipt_path, expected = self.write_conversation_receipt(
                directory, public=True
            )
            output = io.StringIO()

            def verify_unpublish(_driver, result, source, *, on_verified=None):
                self.assertEqual((result, source), (expected, HTML))
                self.assertIsNotNone(on_verified)
                on_verified()
                return True

            with mock.patch.object(
                chat_publish.ChatArtifactPublisher,
                "unpublish",
                autospec=True,
                side_effect=verify_unpublish,
            ) as unpublished, mock.patch.object(
                chat_publish.ChatArtifactPublisher,
                "delete_conversation",
                side_effect=AssertionError("--private must not delete the conversation"),
            ), contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                publish.main(
                    [
                        str(path),
                        "--surface",
                        "chat",
                        "--private",
                        "--account-email-sha256",
                        self.ACCOUNT_EMAIL_SHA256,
                        "--organization-uuid",
                        self.ORGANIZATION_UUID,
                        "--receipt",
                        str(receipt_path),
                    ]
                )

            self.assertEqual(output.getvalue().strip(), expected.chat_url)
            self.assertEqual(unpublished.call_args.args[1:], (expected, HTML))
            self.assertEqual(
                [record["stage"] for record in self.receipt_records(receipt_path)][-2:],
                ["published", "unpublished"],
            )

    def test_converted_receipt_records_active_private_and_tombstone_reconciliation(self):
        cases = (
            ("active", True, False, ["public_bound"]),
            ("private", False, False, ["private"]),
            ("deleted", False, True, ["public_bound", "unpublished"]),
        )
        for label, public, deleted, expected_tail in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                receipt_path, private_result = self.write_converted_conversation_receipt(
                    directory, requested_public=public or deleted
                )
                if public:
                    result = chat_publish.ChatPublishResult(
                        **{
                            **private_result.__dict__,
                            "url": "https://claude.ai/public/artifacts/"
                            + self.PUBLISHED_UUID,
                            "public": True,
                            "published_uuid": self.PUBLISHED_UUID,
                        }
                    )
                elif deleted:
                    result = chat_publish.ChatPublishResult(
                        **{
                            **private_result.__dict__,
                            "published_uuid": self.PUBLISHED_UUID,
                            "published_deleted": True,
                        }
                    )
                else:
                    result = private_result
                lifecycle = publish._ConversationReceiptLifecycle(
                    str(receipt_path),
                    organization_uuid=self.ORGANIZATION_UUID,
                    account_email_sha256=self.ACCOUNT_EMAIL_SHA256,
                    source=HTML,
                )
                try:
                    lifecycle.record_reconciled(result)
                    self.assertEqual(lifecycle.result(), result)
                finally:
                    lifecycle.close()
                stages = [
                    record["stage"] for record in self.receipt_records(receipt_path)
                ]
                self.assertEqual(stages[-len(expected_tail) :], expected_tail)

    def test_public_intent_receipt_never_infers_private_from_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt_path, private_result = self.write_converted_conversation_receipt(
                directory, requested_public=True
            )
            lifecycle = publish._ConversationReceiptLifecycle(
                str(receipt_path),
                organization_uuid=self.ORGANIZATION_UUID,
                account_email_sha256=self.ACCOUNT_EMAIL_SHA256,
                source=HTML,
            )
            try:
                with self.assertRaisesRegex(FrameError, "cannot infer private"):
                    lifecycle.record_reconciled(private_result)
                with self.assertRaisesRegex(FrameError, "cannot infer private"):
                    lifecycle.mark("private")
                self.assertEqual(lifecycle.stage, "converted")
            finally:
                lifecycle.close()

    def test_partial_receipts_can_be_durably_marked_deleted_without_artifact_ids(self):
        for stage in ("conversation_bound", "file_bound"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                receipt_path = self.write_partial_conversation_receipt(
                    directory, stage=stage
                )
                lifecycle = publish._ConversationReceiptLifecycle(
                    str(receipt_path),
                    organization_uuid=self.ORGANIZATION_UUID,
                    account_email_sha256=self.ACCOUNT_EMAIL_SHA256,
                    source=HTML,
                )
                try:
                    binding = lifecycle.preconversion_binding()
                    self.assertEqual(binding.receipt_stage, stage)
                    self.assertEqual(binding.conversation_uuid, self.CONVERSATION_UUID)
                    lifecycle.mark_preconversion_deleted(binding)
                finally:
                    lifecycle.close()
                records = self.receipt_records(receipt_path)
                self.assertEqual(records[-1]["stage"], "deleted")
                self.assertTrue(
                    all(
                        records[-1][field] is None
                        for field in (
                            "artifact_uuid",
                            "version_uuid",
                            "message_uuid",
                            "published_uuid",
                        )
                    )
                )
                reloaded = publish._ConversationReceiptLifecycle(
                    str(receipt_path),
                    organization_uuid=self.ORGANIZATION_UUID,
                    account_email_sha256=self.ACCOUNT_EMAIL_SHA256,
                    source=HTML,
                )
                try:
                    self.assertEqual(reloaded.stage, "deleted")
                    with self.assertRaisesRegex(FrameError, "no exact converted"):
                        reloaded.result()
                finally:
                    reloaded.close()

    def test_partial_delete_cli_routes_exact_binding_and_marks_receipt(self):
        for stage in ("conversation_bound", "file_bound"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                path = self.html_file(directory)
                receipt_path = self.write_partial_conversation_receipt(
                    directory, stage=stage
                )
                output = io.StringIO()

                def delete_partial(
                    _driver, binding, source, prompt, *, on_verified=None
                ):
                    self.assertEqual(binding.receipt_stage, stage)
                    self.assertEqual(binding.conversation_uuid, self.CONVERSATION_UUID)
                    self.assertEqual(source, HTML)
                    self.assertEqual(
                        prompt,
                        chat_publish.build_prompt(
                            HTML, "Exact Fixture", binding.output_path
                        ),
                    )
                    on_verified()
                    return True

                with mock.patch.object(
                    chat_publish.ChatArtifactPublisher,
                    "delete_preconversion_conversation",
                    autospec=True,
                    side_effect=delete_partial,
                ) as deleted, mock.patch.object(
                    chat_publish.ChatArtifactPublisher,
                    "delete_conversation",
                    side_effect=AssertionError("partial cleanup must not need Artifact IDs"),
                ), contextlib.redirect_stdout(output), contextlib.redirect_stderr(
                    io.StringIO()
                ):
                    publish.main(
                        [
                            str(path),
                            "--surface",
                            "chat",
                            "--delete",
                            "--account-email-sha256",
                            self.ACCOUNT_EMAIL_SHA256,
                            "--organization-uuid",
                            self.ORGANIZATION_UUID,
                            "--receipt",
                            str(receipt_path),
                        ]
                    )
                self.assertEqual(
                    output.getvalue().strip(),
                    "https://claude.ai/chat/" + self.CONVERSATION_UUID,
                )
                self.assertEqual(deleted.call_count, 1)
                self.assertEqual(self.receipt_records(receipt_path)[-1]["stage"], "deleted")

    def test_conversion_pending_delete_recovers_ids_privacy_then_deletes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.html_file(directory)
            receipt_path = self.write_partial_conversation_receipt(
                directory, stage="conversion_pending"
            )
            _conversation, _file, _artifact, base = self.conversation_contract(
                public=False
            )
            recovered = chat_publish.ChatPublishResult(
                **{
                    **base.__dict__,
                    "message_uuid": "12345678-1234-7234-a234-123456789abc",
                    "title": base.output_path.rsplit("/", 1)[-1],
                }
            )
            calls = []

            def reconcile(_driver, binding, source, prompt, *, on_reconciled=None):
                calls.append("reconcile")
                self.assertEqual(binding.receipt_stage, "conversion_pending")
                self.assertEqual(source, HTML)
                self.assertEqual(hashlib.sha256(prompt.encode()).hexdigest(), binding.prompt_sha256)
                on_reconciled(recovered)
                return recovered

            def privacy(
                _driver,
                result,
                source,
                prompt,
                request_title,
                *,
                allow_mutation=False,
                on_verified=None,
            ):
                calls.append("privacy")
                self.assertEqual((result, source), (recovered, HTML))
                self.assertEqual(request_title, "Exact Fixture")
                self.assertTrue(allow_mutation)
                self.assertEqual(hashlib.sha256(prompt.encode()).hexdigest(), result.prompt_sha256)
                on_verified()
                return True

            def delete(_driver, result, source, *, on_verified=None):
                calls.append("delete")
                self.assertEqual((result, source), (recovered, HTML))
                on_verified()
                return True

            with mock.patch.object(
                chat_publish.ChatArtifactPublisher,
                "reconcile_conversion_pending",
                autospec=True,
                side_effect=reconcile,
            ), mock.patch.object(
                chat_publish.ChatArtifactPublisher,
                "complete_conversion_privacy",
                autospec=True,
                side_effect=privacy,
            ), mock.patch.object(
                chat_publish.ChatArtifactPublisher,
                "delete_conversation",
                autospec=True,
                side_effect=delete,
            ), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                io.StringIO()
            ):
                publish.main(
                    [
                        str(path),
                        "--surface",
                        "chat",
                        "--delete",
                        "--account-email-sha256",
                        self.ACCOUNT_EMAIL_SHA256,
                        "--organization-uuid",
                        self.ORGANIZATION_UUID,
                        "--receipt",
                        str(receipt_path),
                    ]
                )
            self.assertEqual(calls, ["reconcile", "privacy", "delete"])
            self.assertEqual(
                [record["stage"] for record in self.receipt_records(receipt_path)][-4:],
                ["conversion_bound", "privacy_pending", "private", "deleted"],
            )
            self.assertEqual(
                self.receipt_records(receipt_path)[-1]["message_uuid"],
                recovered.message_uuid,
            )

    def test_partial_delete_dry_run_does_not_construct_driver_or_change_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.html_file(directory)
            receipt_path = self.write_partial_conversation_receipt(directory)
            before = receipt_path.read_bytes()
            output = io.StringIO()
            with mock.patch.object(
                chat_publish.ChatArtifactPublisher,
                "__init__",
                side_effect=AssertionError("dry run must not construct a browser driver"),
            ), contextlib.redirect_stdout(output):
                publish.main(
                    [
                        str(path),
                        "--surface",
                        "chat",
                        "--delete",
                        "--dry-run",
                        "--account-email-sha256",
                        self.ACCOUNT_EMAIL_SHA256,
                        "--organization-uuid",
                        self.ORGANIZATION_UUID,
                        "--receipt",
                        str(receipt_path),
                    ]
                )
            plan = json.loads(output.getvalue().split("\n\n", 1)[1])
            self.assertEqual(plan["operation"], ["delete_preconversion_conversation"])
            self.assertEqual(plan["conversationUuid"], self.CONVERSATION_UUID)
            self.assertNotIn("artifactUuid", plan)
            self.assertEqual(receipt_path.read_bytes(), before)

    def test_conversation_delete_reconciles_converted_public_receipt_first(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.html_file(directory)
            receipt_path, private_result = self.write_converted_conversation_receipt(
                directory, requested_public=True
            )
            public_result = chat_publish.ChatPublishResult(
                **{
                    **private_result.__dict__,
                    "url": "https://claude.ai/public/artifacts/"
                    + self.PUBLISHED_UUID,
                    "public": True,
                    "published_uuid": self.PUBLISHED_UUID,
                }
            )
            calls = []

            def reconcile(_driver, result, source, *, on_reconciled=None):
                calls.append("reconcile")
                self.assertEqual((result, source), (private_result, HTML))
                on_reconciled(public_result)
                return public_result

            def unpublish(_driver, result, source, *, on_verified=None):
                calls.append("unpublish")
                self.assertTrue(result.public)
                on_verified()
                return True

            def delete(_driver, result, source, *, on_verified=None):
                calls.append("delete")
                self.assertFalse(result.public)
                self.assertTrue(result.published_deleted)
                on_verified()
                return True

            with mock.patch.object(
                chat_publish.ChatArtifactPublisher,
                "reconcile_public",
                autospec=True,
                side_effect=reconcile,
            ), mock.patch.object(
                chat_publish.ChatArtifactPublisher,
                "unpublish",
                autospec=True,
                side_effect=unpublish,
            ), mock.patch.object(
                chat_publish.ChatArtifactPublisher,
                "delete_conversation",
                autospec=True,
                side_effect=delete,
            ), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                io.StringIO()
            ):
                publish.main(
                    [
                        str(path),
                        "--surface",
                        "chat",
                        "--delete",
                        "--account-email-sha256",
                        self.ACCOUNT_EMAIL_SHA256,
                        "--organization-uuid",
                        self.ORGANIZATION_UUID,
                        "--receipt",
                        str(receipt_path),
                    ]
                )

            self.assertEqual(calls, ["reconcile", "unpublish", "delete"])
            self.assertEqual(
                [record["stage"] for record in self.receipt_records(receipt_path)][-3:],
                ["public_bound", "unpublished", "deleted"],
            )

    def test_conversation_receipt_lock_blocks_concurrent_lifecycle(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt_path, _result = self.write_conversation_receipt(
                directory, public=True
            )
            first = publish._ConversationReceiptLifecycle(
                str(receipt_path),
                organization_uuid=self.ORGANIZATION_UUID,
                account_email_sha256=self.ACCOUNT_EMAIL_SHA256,
                source=HTML,
            )
            try:
                with self.assertRaisesRegex(FrameError, "opened safely"):
                    publish._ConversationReceiptLifecycle(
                        str(receipt_path),
                        organization_uuid=self.ORGANIZATION_UUID,
                        account_email_sha256=self.ACCOUNT_EMAIL_SHA256,
                        source=HTML,
                    )
            finally:
                first.close()

    def test_conversation_receipt_recovers_only_a_partial_trailing_record(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt_path, expected = self.write_conversation_receipt(
                directory, public=True
            )
            with receipt_path.open("ab") as handle:
                handle.write(b'{"stage":')
            lifecycle = publish._ConversationReceiptLifecycle(
                str(receipt_path),
                organization_uuid=self.ORGANIZATION_UUID,
                account_email_sha256=self.ACCOUNT_EMAIL_SHA256,
                source=HTML,
            )
            try:
                self.assertEqual(lifecycle.stage, "published")
                self.assertEqual(lifecycle.result(), expected)
            finally:
                lifecycle.close()
            self.assertTrue(receipt_path.read_bytes().endswith(b"\n"))

    def test_conversation_delete_unpublishes_public_receipt_then_deletes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.html_file(directory)
            receipt_path, expected = self.write_conversation_receipt(
                directory, public=True
            )
            calls = []

            def unpublish(_driver, result, source, *, on_verified=None):
                calls.append(("unpublish", result, source))
                self.assertIsNotNone(on_verified)
                on_verified()
                return True

            def delete_conversation(_driver, result, source, *, on_verified=None):
                calls.append(("delete", result, source))
                self.assertIsNotNone(on_verified)
                on_verified()
                return True

            with mock.patch.object(
                chat_publish.ChatArtifactPublisher,
                "unpublish",
                autospec=True,
                side_effect=unpublish,
            ), mock.patch.object(
                chat_publish.ChatArtifactPublisher,
                "delete_conversation",
                autospec=True,
                side_effect=delete_conversation,
            ), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                io.StringIO()
            ):
                publish.main(
                    [
                        str(path),
                        "--surface",
                        "chat",
                        "--delete",
                        "--account-email-sha256",
                        self.ACCOUNT_EMAIL_SHA256,
                        "--organization-uuid",
                        self.ORGANIZATION_UUID,
                        "--receipt",
                        str(receipt_path),
                    ]
                )

            self.assertEqual([name for name, _result, _source in calls], ["unpublish", "delete"])
            self.assertEqual(calls[0][1:], (expected, HTML))
            self.assertFalse(calls[1][1].public)
            self.assertTrue(calls[1][1].published_deleted)
            self.assertEqual(calls[1][1].published_uuid, self.PUBLISHED_UUID)
            self.assertEqual(calls[1][2], HTML)
            self.assertEqual(
                [record["stage"] for record in self.receipt_records(receipt_path)][-3:],
                ["published", "unpublished", "deleted"],
            )

    def test_conversation_lifecycle_dry_run_plans_without_driver_or_stage_change(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.html_file(directory)
            receipt_path, _result = self.write_conversation_receipt(
                directory, public=True
            )
            before = receipt_path.read_bytes()
            output = io.StringIO()
            with mock.patch.object(
                chat_publish.ChatArtifactPublisher,
                "__init__",
                side_effect=AssertionError("dry run must not construct a browser driver"),
            ), contextlib.redirect_stdout(output):
                publish.main(
                    [
                        str(path),
                        "--surface",
                        "chat",
                        "--delete",
                        "--dry-run",
                        "--account-email-sha256",
                        self.ACCOUNT_EMAIL_SHA256,
                        "--organization-uuid",
                        self.ORGANIZATION_UUID,
                        "--receipt",
                        str(receipt_path),
                    ]
                )

            plan = json.loads(output.getvalue().split("\n\n", 1)[1])
            self.assertEqual(plan["operation"], ["unpublish", "delete_conversation"])
            self.assertEqual(plan["receiptStage"], "published")
            self.assertEqual(receipt_path.read_bytes(), before)

    def test_conversation_receipt_rejects_org_account_and_source_mismatches_before_driver(self):
        cases = (
            (
                "organization",
                "22222222-2222-4222-8222-222222222222",
                self.ACCOUNT_EMAIL_SHA256,
                HTML,
                "different organization",
            ),
            (
                "account",
                self.ORGANIZATION_UUID,
                "1" * 64,
                HTML,
                "different account binding",
            ),
            (
                "source",
                self.ORGANIZATION_UUID,
                self.ACCOUNT_EMAIL_SHA256,
                HTML.replace("\nok\n", "\nchanged\n"),
                "does not match the input source",
            ),
        )
        for label, organization_uuid, account_digest, source, message in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                path = self.html_file(directory)
                receipt_path, _result = self.write_conversation_receipt(
                    directory, public=True
                )
                path.write_text(source, encoding="utf-8")
                with mock.patch.object(
                    chat_publish.ChatArtifactPublisher,
                    "__init__",
                    side_effect=AssertionError("receipt mismatch must precede browser access"),
                ), self.assertRaisesRegex(FrameError, message):
                    publish.main(
                        [
                            str(path),
                            "--surface",
                            "chat",
                            "--private",
                            "--account-email-sha256",
                            account_digest,
                            "--organization-uuid",
                            organization_uuid,
                            "--receipt",
                            str(receipt_path),
                        ]
                    )

    def test_seeded_public_dry_run_binds_seed_without_browser_or_receipt_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            target_path = self.html_file(directory)
            seed_path = Path(directory) / "seed.html"
            seed_path.write_text(HTML, encoding="utf-8")
            seed_receipt, _seed_result = self.write_conversation_receipt(
                directory, public=True, name="seed-receipt.jsonl"
            )
            target = HTML + "\n<!-- seeded target -->\n"
            target_path.write_text(target, encoding="utf-8")
            target_receipt = Path(directory) / "target-receipt.jsonl"
            output = io.StringIO()
            with mock.patch.object(
                chat_seeded_publish.SeededPublicArtifactPublisher,
                "__init__",
                side_effect=AssertionError("dry run must not construct a driver"),
            ), contextlib.redirect_stdout(output):
                publish.main(
                    [
                        str(target_path), "--surface", "chat", "--chat-adapter",
                        "seeded-public", "--public", "--seed-file", str(seed_path),
                        "--seed-receipt", str(seed_receipt), "--receipt",
                        str(target_receipt), "--organization-uuid",
                        self.ORGANIZATION_UUID, "--account-email-sha256",
                        self.ACCOUNT_EMAIL_SHA256,
                        "--acknowledge-experimental-seeded-public", "--dry-run",
                    ]
                )
            self.assertFalse(target_receipt.exists())
        rendered = output.getvalue()
        self.assertIn('"adapter": "seeded-public"', rendered)
        self.assertIn('"seedPreserved": true', rendered)
        self.assertIn(hashlib.sha256(target.encode()).hexdigest(), rendered)
        self.assertNotIn("seeded target", rendered)

    def test_seeded_public_dispatches_without_conversation_or_native_fallback(self):
        seed, clone, result, target = self.seeded_contract()
        with tempfile.TemporaryDirectory() as directory:
            target_path = Path(directory) / "target.html"
            target_path.write_text(target, encoding="utf-8")
            seed_path = Path(directory) / "seed.html"
            seed_path.write_text(HTML, encoding="utf-8")
            seed_receipt, _seed_result = self.write_conversation_receipt(
                directory, public=True, name="seed-receipt.jsonl"
            )
            target_receipt = Path(directory) / "target-receipt.jsonl"

            def create(_driver, actual_seed, actual_target, **callbacks):
                self.assertEqual(actual_seed, seed)
                self.assertEqual(actual_target, target)
                self.assertIn("on_publish_rejected", callbacks)
                callbacks["on_remix_intent"]({"operation": "remix"})
                callbacks["on_clone_bound"](clone)
                callbacks["on_publish_intent"]({"operation": "publish"})
                callbacks["on_public_bound"](result)
                callbacks["on_published"](result)
                return result

            output, error = io.StringIO(), io.StringIO()
            with mock.patch.object(
                chat_seeded_publish.SeededPublicArtifactPublisher,
                "create_and_publish",
                autospec=True,
                side_effect=create,
            ) as called, mock.patch.object(
                chat_publish.ChatArtifactPublisher,
                "__init__",
                side_effect=AssertionError("conversation fallback is forbidden"),
            ), mock.patch.object(
                chat_direct_publish.NativeShareArtifactPublisher,
                "__init__",
                side_effect=AssertionError("native fallback is forbidden"),
            ), contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                publish.main(
                    [
                        str(target_path), "--surface", "chat", "--chat-adapter",
                        "seeded-public", "--public", "--seed-file", str(seed_path),
                        "--seed-receipt", str(seed_receipt), "--receipt",
                        str(target_receipt), "--organization-uuid",
                        self.ORGANIZATION_UUID, "--account-email-sha256",
                        self.ACCOUNT_EMAIL_SHA256,
                        "--acknowledge-experimental-seeded-public",
                    ]
                )
            records = self.receipt_records(target_receipt)
        self.assertTrue(called.called)
        self.assertEqual(output.getvalue().strip(), result.url)
        self.assertIn("model-turn: none", error.getvalue())
        self.assertEqual(records[-1]["stage"], "published")

    def test_seeded_rejected_publish_retains_clone_without_retry_and_can_delete(self):
        seed, clone, _result, target = self.seeded_contract()
        with tempfile.TemporaryDirectory() as directory:
            target_path = Path(directory) / "target.html"
            target_path.write_text(target, encoding="utf-8")
            seed_path = Path(directory) / "seed.html"
            seed_path.write_text(HTML, encoding="utf-8")
            seed_receipt, _seed_result = self.write_conversation_receipt(
                directory, public=True, name="seed-receipt.jsonl"
            )
            target_receipt = Path(directory) / "rejected-target.jsonl"
            public_args = [
                str(target_path), "--surface", "chat", "--chat-adapter",
                "seeded-public", "--public", "--seed-file", str(seed_path),
                "--seed-receipt", str(seed_receipt), "--receipt",
                str(target_receipt), "--organization-uuid",
                self.ORGANIZATION_UUID, "--account-email-sha256",
                self.ACCOUNT_EMAIL_SHA256,
                "--acknowledge-experimental-seeded-public",
            ]

            def reject(_driver, actual_seed, actual_target, **callbacks):
                self.assertEqual((actual_seed, actual_target), (seed, target))
                callbacks["on_remix_intent"]({"operation": "remix"})
                callbacks["on_clone_bound"](clone)
                callbacks["on_publish_intent"]({"operation": "publish"})
                callbacks["on_publish_rejected"]()
                raise chat_seeded_publish.SeededCapabilityUnavailable(
                    "publication was rejected; private clone retained"
                )

            with mock.patch.object(
                chat_seeded_publish.SeededPublicArtifactPublisher,
                "create_and_publish",
                autospec=True,
                side_effect=reject,
            ), self.assertRaisesRegex(
                chat_seeded_publish.SeededCapabilityUnavailable,
                "private clone retained",
            ):
                publish.main(public_args)
            rejected = self.receipt_records(target_receipt)[-1]
            self.assertEqual(rejected["stage"], "publish_rejected")
            self.assertIsNone(rejected["published_uuid"])

            with mock.patch.object(
                chat_seeded_publish.SeededPublicArtifactPublisher,
                "__init__",
                side_effect=AssertionError("rejected publication must not retry"),
            ), self.assertRaisesRegex(
                FrameError, "definitively rejected.*private clone is retained"
            ):
                publish.main(public_args)

            public_plan = io.StringIO()
            with mock.patch.object(
                chat_seeded_publish.SeededPublicArtifactPublisher,
                "__init__",
                side_effect=AssertionError("dry run must not construct a driver"),
            ), contextlib.redirect_stdout(public_plan):
                publish.main(public_args + ["--dry-run"])
            self.assertIn('"no_publish_retry"', public_plan.getvalue())
            self.assertIn('"private_clone_retained"', public_plan.getvalue())

            private_args = [
                str(target_path), "--surface", "chat", "--chat-adapter",
                "seeded-public", "--private", "--seed-file", str(seed_path),
                "--receipt", str(target_receipt), "--organization-uuid",
                self.ORGANIZATION_UUID, "--account-email-sha256",
                self.ACCOUNT_EMAIL_SHA256,
            ]
            private_plan = io.StringIO()
            with mock.patch.object(
                chat_seeded_publish.SeededPublicArtifactPublisher,
                "__init__",
                side_effect=AssertionError("dry run must not construct a driver"),
            ), contextlib.redirect_stdout(private_plan):
                publish.main(private_args + ["--dry-run"])
            self.assertIn('"retain_private_clone"', private_plan.getvalue())

            private_output = io.StringIO()
            with mock.patch.object(
                chat_seeded_publish.SeededPublicArtifactPublisher,
                "delete_private_clone",
                side_effect=AssertionError("--private must retain the rejected clone"),
            ), contextlib.redirect_stdout(private_output), contextlib.redirect_stderr(
                io.StringIO()
            ):
                publish.main(private_args)
            self.assertEqual(private_output.getvalue().strip(), clone.chat_url)
            self.assertEqual(
                self.receipt_records(target_receipt)[-1]["stage"],
                "publish_rejected",
            )

            def delete_private(
                _driver, actual_clone, actual_target, *, on_intent, on_verified
            ):
                self.assertEqual((actual_clone, actual_target), (clone, target))
                on_intent({"operation": "delete_private"})
                on_verified()
                return True

            with mock.patch.object(
                chat_seeded_publish.SeededPublicArtifactPublisher,
                "delete_private_clone",
                autospec=True,
                side_effect=delete_private,
            ) as removed, mock.patch.object(
                chat_seeded_publish.SeededPublicArtifactPublisher,
                "delete_container",
                side_effect=AssertionError("rejected clone has no public state"),
            ):
                publish.main([
                    str(target_path), "--surface", "chat", "--chat-adapter",
                    "seeded-public", "--delete", "--seed-file", str(seed_path),
                    "--receipt", str(target_receipt), "--organization-uuid",
                    self.ORGANIZATION_UUID, "--account-email-sha256",
                    self.ACCOUNT_EMAIL_SHA256,
                ])
            self.assertTrue(removed.called)
            final = self.receipt_records(target_receipt)[-1]
            self.assertEqual(final["stage"], "deleted")
            self.assertIsNone(final["published_uuid"])

    def test_seeded_private_and_delete_follow_exact_receipt_lifecycle(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt_path, result, target = self.write_seeded_receipt(directory)
            target_path = Path(directory) / "target.html"
            target_path.write_text(target, encoding="utf-8")
            seed_path = Path(directory) / "seed.html"
            seed_path.write_text(HTML, encoding="utf-8")

            def unpublish(_driver, value, *, on_intent=None, on_verified=None):
                self.assertEqual(value, result)
                on_intent({"operation": "unpublish"})
                on_verified()
                return chat_seeded_publish.SeededPublicResult(
                    clone=value.clone,
                    published_uuid=value.published_uuid,
                    public_source=value.public_source,
                    public_source_sha256=value.public_source_sha256,
                    published_deleted=True,
                )

            with mock.patch.object(
                chat_seeded_publish.SeededPublicArtifactPublisher,
                "unpublish",
                autospec=True,
                side_effect=unpublish,
            ) as called:
                publish.main(
                    [
                        str(target_path), "--surface", "chat", "--chat-adapter",
                        "seeded-public", "--private", "--seed-file", str(seed_path),
                        "--receipt", str(receipt_path), "--organization-uuid",
                        self.ORGANIZATION_UUID, "--account-email-sha256",
                        self.ACCOUNT_EMAIL_SHA256,
                    ]
                )
            self.assertTrue(called.called)
            self.assertEqual(self.receipt_records(receipt_path)[-1]["stage"], "unpublished")

            def delete(_driver, value, *, on_intent=None, on_verified=None):
                self.assertTrue(value.published_deleted)
                on_intent({"operation": "delete"})
                on_verified()
                return True

            with mock.patch.object(
                chat_seeded_publish.SeededPublicArtifactPublisher,
                "delete_container",
                autospec=True,
                side_effect=delete,
            ) as removed:
                publish.main(
                    [
                        str(target_path), "--surface", "chat", "--chat-adapter",
                        "seeded-public", "--delete", "--seed-file", str(seed_path),
                        "--receipt", str(receipt_path), "--organization-uuid",
                        self.ORGANIZATION_UUID, "--account-email-sha256",
                        self.ACCOUNT_EMAIL_SHA256,
                    ]
                )
            self.assertTrue(removed.called)
            self.assertEqual(self.receipt_records(receipt_path)[-1]["stage"], "deleted")

    def test_seeded_private_clone_delete_never_fabricates_public_state(self):
        seed, clone, _result, target = self.seeded_contract()
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = Path(directory) / "private-clone.jsonl"
            journal = chat_seeded_receipt.SeededReceiptJournal(
                str(receipt_path), seed=seed, target_source=target
            )
            try:
                journal.mark_remix_pending()
                journal.record_clone(clone)
            finally:
                journal.close()
            target_path = Path(directory) / "target.html"
            target_path.write_text(target, encoding="utf-8")
            seed_path = Path(directory) / "seed.html"
            seed_path.write_text(HTML, encoding="utf-8")

            def delete_private(
                _driver, actual_clone, actual_target, *, on_intent, on_verified
            ):
                self.assertEqual(actual_clone, clone)
                self.assertEqual(actual_target, target)
                on_intent({"operation": "delete_private"})
                on_verified()
                return True

            with mock.patch.object(
                chat_seeded_publish.SeededPublicArtifactPublisher,
                "delete_private_clone",
                autospec=True,
                side_effect=delete_private,
            ) as removed, mock.patch.object(
                chat_seeded_publish.SeededPublicArtifactPublisher,
                "delete_container",
                side_effect=AssertionError("public delete must not be used"),
            ):
                publish.main([
                    str(target_path), "--surface", "chat", "--chat-adapter",
                    "seeded-public", "--delete", "--seed-file", str(seed_path),
                    "--receipt", str(receipt_path), "--organization-uuid",
                    self.ORGANIZATION_UUID, "--account-email-sha256",
                    self.ACCOUNT_EMAIL_SHA256,
                ])
            self.assertTrue(removed.called)
            final = self.receipt_records(receipt_path)[-1]
            self.assertEqual(final["stage"], "deleted")
            self.assertIsNone(final["published_uuid"])

    def test_seeded_publish_pending_is_get_reconciled_before_unpublish(self):
        seed, clone, result, target = self.seeded_contract()
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = Path(directory) / "publish-pending.jsonl"
            journal = chat_seeded_receipt.SeededReceiptJournal(
                str(receipt_path), seed=seed, target_source=target
            )
            try:
                journal.mark_remix_pending()
                journal.record_clone(clone)
                journal.mark_publish_pending()
            finally:
                journal.close()
            target_path = Path(directory) / "target.html"
            target_path.write_text(target, encoding="utf-8")
            seed_path = Path(directory) / "seed.html"
            seed_path.write_text(HTML, encoding="utf-8")
            calls = []

            def reconcile(
                _driver, actual_clone, actual_target, *, on_public_bound,
                on_published, on_unpublished
            ):
                calls.append("reconcile")
                self.assertEqual((actual_clone, actual_target), (clone, target))
                on_public_bound(result)
                on_published(result)
                return result

            def unpublish(_driver, value, *, on_intent, on_verified):
                calls.append("unpublish")
                on_intent({"operation": "unpublish"})
                on_verified()
                return chat_seeded_publish.SeededPublicResult(
                    clone=value.clone,
                    published_uuid=value.published_uuid,
                    public_source=value.public_source,
                    public_source_sha256=value.public_source_sha256,
                    published_deleted=True,
                )

            with mock.patch.object(
                chat_seeded_publish.SeededPublicArtifactPublisher,
                "reconcile_publish",
                autospec=True,
                side_effect=reconcile,
            ), mock.patch.object(
                chat_seeded_publish.SeededPublicArtifactPublisher,
                "unpublish",
                autospec=True,
                side_effect=unpublish,
            ):
                publish.main([
                    str(target_path), "--surface", "chat", "--chat-adapter",
                    "seeded-public", "--private", "--seed-file", str(seed_path),
                    "--receipt", str(receipt_path), "--organization-uuid",
                    self.ORGANIZATION_UUID, "--account-email-sha256",
                    self.ACCOUNT_EMAIL_SHA256,
                ])
            self.assertEqual(calls, ["reconcile", "unpublish"])
            self.assertEqual(
                self.receipt_records(receipt_path)[-1]["stage"], "unpublished"
            )

    def test_seeded_public_resume_never_claims_success_before_published_stage(self):
        seed, clone, result, target = self.seeded_contract()
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = Path(directory) / "publish-pending.jsonl"
            journal = chat_seeded_receipt.SeededReceiptJournal(
                str(receipt_path), seed=seed, target_source=target
            )
            try:
                journal.mark_remix_pending()
                journal.record_clone(clone)
                journal.mark_publish_pending()
            finally:
                journal.close()
            target_path = Path(directory) / "target.html"
            target_path.write_text(target, encoding="utf-8")
            seed_path = Path(directory) / "seed.html"
            seed_path.write_text(HTML, encoding="utf-8")
            seed_receipt, _seed_result = self.write_conversation_receipt(
                directory, public=True, name="seed-receipt.jsonl"
            )

            def reconcile(
                _driver, _clone, _target, *, on_public_bound,
                on_published, on_unpublished
            ):
                on_public_bound(result)
                return result

            output = io.StringIO()
            with mock.patch.object(
                chat_seeded_publish.SeededPublicArtifactPublisher,
                "reconcile_publish",
                autospec=True,
                side_effect=reconcile,
            ), contextlib.redirect_stdout(output), self.assertRaisesRegex(
                chat_seeded_publish.SeededRemoteStateUnknown,
                "not verified",
            ):
                publish.main([
                    str(target_path), "--surface", "chat", "--chat-adapter",
                    "seeded-public", "--public", "--seed-file", str(seed_path),
                    "--seed-receipt", str(seed_receipt), "--receipt",
                    str(receipt_path), "--organization-uuid",
                    self.ORGANIZATION_UUID, "--account-email-sha256",
                    self.ACCOUNT_EMAIL_SHA256,
                    "--acknowledge-experimental-seeded-public",
                ])
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(
                self.receipt_records(receipt_path)[-1]["stage"], "public_bound"
            )

    def test_seeded_dry_runs_never_repair_partial_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            target_path = self.html_file(directory)
            seed_path = Path(directory) / "seed.html"
            seed_path.write_text(HTML, encoding="utf-8")
            seed_receipt, _seed_result = self.write_conversation_receipt(
                directory, public=True, name="seed-receipt.jsonl"
            )
            with seed_receipt.open("ab") as handle:
                handle.write(b'{"partial-seed":')
            seed_before = seed_receipt.read_bytes()
            target_receipt = Path(directory) / "target-receipt.jsonl"
            with mock.patch.object(
                chat_seeded_publish.SeededPublicArtifactPublisher,
                "__init__",
                side_effect=AssertionError("dry run must not construct a driver"),
            ), contextlib.redirect_stdout(io.StringIO()):
                publish.main([
                    str(target_path), "--surface", "chat", "--chat-adapter",
                    "seeded-public", "--public", "--seed-file", str(seed_path),
                    "--seed-receipt", str(seed_receipt), "--receipt",
                    str(target_receipt), "--organization-uuid",
                    self.ORGANIZATION_UUID, "--account-email-sha256",
                    self.ACCOUNT_EMAIL_SHA256,
                    "--acknowledge-experimental-seeded-public", "--dry-run",
                ])
            self.assertEqual(seed_receipt.read_bytes(), seed_before)
            self.assertFalse(target_receipt.exists())

    def test_seeded_public_requires_explicit_public_ack_and_distinct_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self.html_file(directory)
            seed = Path(directory) / "seed.html"
            seed.write_text(HTML, encoding="utf-8")
            common = [
                str(target), "--surface", "chat", "--chat-adapter", "seeded-public",
                "--public", "--seed-file", str(seed), "--organization-uuid",
                self.ORGANIZATION_UUID, "--account-email-sha256",
                self.ACCOUNT_EMAIL_SHA256,
            ]
            with self.assertRaisesRegex(FrameError, "acknowledge"):
                publish.main(common + ["--seed-receipt", "seed.jsonl", "--receipt", "out.jsonl"])
            with self.assertRaisesRegex(FrameError, "different files"):
                publish.main(common + [
                    "--acknowledge-experimental-seeded-public",
                    "--seed-receipt", "same.jsonl", "--receipt", "same.jsonl",
                ])

    def native_ref_file(self, directory: str) -> Path:
        path = Path(directory) / "native-session-ref"
        path.write_text(
            "local_87654321-4321-4321-8321-cba987654321\n", encoding="utf-8"
        )
        path.chmod(0o600)
        return path

    def test_native_share_dry_run_is_hash_only_and_constructs_no_browser(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.html_file(directory)
            ref_path = self.native_ref_file(directory)
            output = io.StringIO()
            with mock.patch.object(
                chat_direct_publish.NativeShareArtifactPublisher,
                "__init__",
                side_effect=AssertionError("browser driver should not be constructed"),
            ), contextlib.redirect_stdout(output):
                publish.main(
                    [
                        str(path),
                        "--surface",
                        "chat",
                        "--chat-adapter",
                        "native-share",
                        "--organization-uuid",
                        "11111111-2222-4333-8444-555555555555",
                        "--native-session-ref-file",
                        str(ref_path),
                        "--dry-run",
                    ]
                )
        rendered = output.getvalue()
        self.assertIn('"adapter": "native-share"', rendered)
        self.assertIn('"nativeSessionRefSha256":', rendered)
        self.assertNotIn("local_87654321", rendered)

    def test_native_share_dispatches_without_conversation_fallback(self):
        result = chat_direct_publish.NativeShareResult(
            url="https://claude.ai/artifacts/99999999-8888-4777-8666-555555555555",
            artifact_uuid="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            version_uuid="99999999-8888-4777-8666-555555555555",
            message_uuid="12345678-1234-4234-8234-123456789abc",
            source_sha256=hashlib.sha256(HTML.encode()).hexdigest(),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self.html_file(directory)
            ref_path = self.native_ref_file(directory)
            output = io.StringIO()
            error = io.StringIO()
            with mock.patch.object(
                chat_direct_publish.NativeShareArtifactPublisher,
                "publish",
                autospec=True,
                return_value=result,
            ) as called, mock.patch.object(
                chat_publish.ChatArtifactPublisher,
                "__init__",
                side_effect=AssertionError("conversation adapter must not be used"),
            ), contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                publish.main(
                    [
                        str(path),
                        "--surface",
                        "chat",
                        "--chat-adapter",
                        "native-share",
                        "--browser-port",
                        "9333",
                        "--account-email-sha256",
                        "0" * 64,
                        "--organization-uuid",
                        "11111111-2222-4333-8444-555555555555",
                        "--native-session-ref-file",
                        str(ref_path),
                    ]
                )
        self.assertEqual(output.getvalue().strip(), result.url)
        self.assertIn("adapter: native-share", error.getvalue())
        self.assertTrue(called.called)
        self.assertEqual(called.call_args.kwargs["public"], False)

    def test_native_share_public_writes_exact_owner_only_receipt(self):
        published = "abcdefab-cdef-4abc-8def-abcdefabcdef"
        result = chat_direct_publish.NativeShareResult(
            url="https://claude.ai/public/artifacts/" + published,
            artifact_uuid="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            version_uuid="99999999-8888-4777-8666-555555555555",
            message_uuid="12345678-1234-4234-8234-123456789abc",
            source_sha256=hashlib.sha256(HTML.encode()).hexdigest(),
            public=True,
            published_uuid=published,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self.html_file(directory)
            ref_path = self.native_ref_file(directory)
            receipt_path = Path(directory) / "public-receipt.json"
            output = io.StringIO()
            error = io.StringIO()
            with mock.patch.object(
                chat_direct_publish.NativeShareArtifactPublisher,
                "publish",
                autospec=True,
                return_value=result,
            ) as called, contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                publish.main(
                    [
                        str(path),
                        "--surface",
                        "chat",
                        "--chat-adapter",
                        "native-share",
                        "--public",
                        "--browser-port",
                        "9333",
                        "--account-email-sha256",
                        "0" * 64,
                        "--organization-uuid",
                        "11111111-2222-4333-8444-555555555555",
                        "--native-session-ref-file",
                        str(ref_path),
                        "--receipt",
                        str(receipt_path),
                    ]
                )
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)
        self.assertEqual(output.getvalue().strip(), result.url)
        self.assertIn("published: " + published, error.getvalue())
        self.assertEqual(receipt["schema"], publish.NATIVE_RECEIPT_SCHEMA)
        self.assertEqual(receipt["published_uuid"], published)
        self.assertEqual(receipt["source_sha256"], result.source_sha256)
        self.assertTrue(called.call_args.kwargs["public"])

    def test_native_share_private_consumes_receipt_and_verifies_unpublish(self):
        published = "abcdefab-cdef-4abc-8def-abcdefabcdef"
        result = chat_direct_publish.NativeShareResult(
            url="https://claude.ai/public/artifacts/" + published,
            artifact_uuid="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            version_uuid="99999999-8888-4777-8666-555555555555",
            message_uuid="12345678-1234-4234-8234-123456789abc",
            source_sha256=hashlib.sha256(HTML.encode()).hexdigest(),
            public=True,
            published_uuid=published,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self.html_file(directory)
            ref_path = self.native_ref_file(directory)
            receipt_path = Path(directory) / "public-receipt.json"
            publish._write_native_receipt(
                str(receipt_path),
                "11111111-2222-4333-8444-555555555555",
                result,
            )
            output = io.StringIO()
            error = io.StringIO()
            with mock.patch.object(
                chat_direct_publish.NativeShareArtifactPublisher,
                "unpublish",
                autospec=True,
                return_value=True,
            ) as called, contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                publish.main(
                    [
                        str(path),
                        "--surface",
                        "chat",
                        "--chat-adapter",
                        "native-share",
                        "--private",
                        "--browser-port",
                        "9333",
                        "--account-email-sha256",
                        "0" * 64,
                        "--organization-uuid",
                        "11111111-2222-4333-8444-555555555555",
                        "--native-session-ref-file",
                        str(ref_path),
                        "--receipt",
                        str(receipt_path),
                    ]
                )
        self.assertEqual(output.getvalue().strip(), result.url)
        self.assertIn("tombstone: verified", error.getvalue())
        self.assertEqual(called.call_args.args[1].published_uuid, published)
        self.assertEqual(called.call_args.args[2], HTML)

    def test_native_share_public_dry_run_never_creates_receipt_or_browser(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.html_file(directory)
            ref_path = self.native_ref_file(directory)
            receipt_path = Path(directory) / "future-receipt.json"
            output = io.StringIO()
            with mock.patch.object(
                chat_direct_publish.NativeShareArtifactPublisher,
                "__init__",
                side_effect=AssertionError("dry run must not construct a browser"),
            ), contextlib.redirect_stdout(output):
                publish.main(
                    [
                        str(path), "--surface", "chat", "--chat-adapter", "native-share",
                        "--public", "--organization-uuid",
                        "11111111-2222-4333-8444-555555555555",
                        "--native-session-ref-file", str(ref_path),
                        "--receipt", str(receipt_path), "--dry-run",
                    ]
                )
            self.assertFalse(receipt_path.exists())
        self.assertIn('"public": true', output.getvalue())

    def test_native_share_existing_receipt_blocks_before_browser_construction(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.html_file(directory)
            ref_path = self.native_ref_file(directory)
            receipt_path = Path(directory) / "existing-receipt.json"
            receipt_path.write_text("do not overwrite\n", encoding="utf-8")
            with mock.patch.object(
                chat_direct_publish.NativeShareArtifactPublisher,
                "__init__",
                side_effect=AssertionError("receipt preflight must precede browser access"),
            ), self.assertRaisesRegex(FrameError, "already exists"):
                publish.main(
                    [
                        str(path), "--surface", "chat", "--chat-adapter", "native-share",
                        "--public", "--organization-uuid",
                        "11111111-2222-4333-8444-555555555555",
                        "--native-session-ref-file", str(ref_path),
                        "--receipt", str(receipt_path),
                        "--account-email-sha256", "0" * 64,
                    ]
                )
            self.assertEqual(
                receipt_path.read_text(encoding="utf-8"), "do not overwrite\n"
            )

    def test_native_share_rejects_insecure_ref_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.html_file(directory)
            ref_path = self.native_ref_file(directory)
            ref_path.chmod(0o644)
            with self.assertRaisesRegex(FrameError, "mode 0600"):
                publish.main(
                    [
                        str(path),
                        "--surface",
                        "chat",
                        "--chat-adapter",
                        "native-share",
                        "--organization-uuid",
                        "11111111-2222-4333-8444-555555555555",
                        "--native-session-ref-file",
                        str(ref_path),
                        "--dry-run",
                    ]
                )

    def test_native_share_dry_run_uses_live_request_validators(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.html_file(directory)
            ref_path = self.native_ref_file(directory)
            with self.assertRaisesRegex(FrameError, "browser-port"):
                publish.main(
                    [
                        str(path),
                        "--surface",
                        "chat",
                        "--chat-adapter",
                        "native-share",
                        "--browser-port",
                        "70000",
                        "--organization-uuid",
                        "11111111-2222-4333-8444-555555555555",
                        "--native-session-ref-file",
                        str(ref_path),
                        "--dry-run",
                    ]
                )


if __name__ == "__main__":
    unittest.main()
