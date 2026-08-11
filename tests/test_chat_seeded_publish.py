"""Offline contract tests for model-free seeded Standard Artifact publication."""

from __future__ import annotations

import hashlib
import subprocess
import unittest
from unittest import mock

from clawdvert import chat_seeded_publish as seeded
from clawdvert.frames import FrameError


ORG = "11111111-2222-4333-8444-555555555555"
SEED_PUBLIC = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
SEED_CONVERSATION = "11111111-aaaa-4bbb-8ccc-222222222222"
SEED_ARTIFACT = "22222222-aaaa-4bbb-8ccc-333333333333"
SEED_VERSION = "33333333-aaaa-4bbb-8ccc-444444444444"
SEED_MESSAGE = "44444444-aaaa-4bbb-8ccc-555555555555"
CLONE_CONVERSATION = "55555555-aaaa-4bbb-8ccc-666666666666"
CLONE_ARTIFACT = "66666666-aaaa-4bbb-8ccc-777777777777"
CLONE_VERSION = "77777777-aaaa-4bbb-8ccc-888888888888"
CLONE_MESSAGE = "88888888-aaaa-4bbb-8ccc-999999999999"
TARGET_PUBLIC = "99999999-aaaa-4bbb-8ccc-aaaaaaaaaaaa"
OBSERVED_PUBLIC = "aaaaaaaa-1111-4111-8111-bbbbbbbbbbbb"
ACCOUNT = "0" * 64
SEED_SOURCE = "<!doctype html><title>Seed</title><p>seed</p>"
TARGET_SOURCE = "<!doctype html><title>Target</title><p>target</p>"


def seed_binding() -> seeded.SeedBinding:
    return seeded.SeedBinding(
        organization_uuid=ORG,
        account_email_sha256=ACCOUNT,
        published_uuid=SEED_PUBLIC,
        conversation_uuid=SEED_CONVERSATION,
        artifact_uuid=SEED_ARTIFACT,
        version_uuid=SEED_VERSION,
        message_uuid=SEED_MESSAGE,
        artifact_identifier="seed-identifier",
        artifact_type="text/html",
        code_language=None,
        title="Seed",
        source=SEED_SOURCE,
        source_sha256=hashlib.sha256(SEED_SOURCE.encode()).hexdigest(),
    )


def clone_binding() -> seeded.SeededCloneBinding:
    return seeded.SeededCloneBinding(
        seed=seed_binding(),
        conversation_uuid=CLONE_CONVERSATION,
        artifact_uuid=CLONE_ARTIFACT,
        version_uuid=CLONE_VERSION,
        message_uuid=CLONE_MESSAGE,
        artifact_identifier="server-issued-clone-identifier",
        artifact_type="text/html",
        code_language=None,
        title="Seed",
    )


def public_result(*, deleted: bool = False) -> seeded.SeededPublicResult:
    return seeded.SeededPublicResult(
        clone=clone_binding(),
        published_uuid=TARGET_PUBLIC,
        public_source=TARGET_SOURCE,
        public_source_sha256=hashlib.sha256(TARGET_SOURCE.encode()).hexdigest(),
        published_deleted=deleted,
    )


def clone_phase(stage: str = "remix_bound") -> dict:
    return {
        "stage": stage,
        "mutationAttempted": stage != "clone_private_verified",
        "ids": {
            "cloneConversationUuid": CLONE_CONVERSATION,
            "cloneArtifactUuid": CLONE_ARTIFACT,
            "cloneVersionUuid": CLONE_VERSION,
            "cloneMessageUuid": CLONE_MESSAGE,
        },
        "metadata": {
            "artifactIdentifier": "server-issued-clone-identifier",
            "artifactType": "text/html",
            "codeLanguage": None,
            "title": "Seed",
        },
        "seedVerified": True,
    }


def published_phase(stage: str = "published") -> dict:
    value = clone_phase(stage)
    value["ids"]["publishedUuid"] = TARGET_PUBLIC
    value.update(
        {"ownerBound": True, "publicReadVerified": True, "seedVerified": True}
    )
    return value


class SeededContractTests(unittest.TestCase):
    def publisher(self) -> seeded.SeededPublicArtifactPublisher:
        return seeded.SeededPublicArtifactPublisher(
            9222,
            expected_email_sha256=ACCOUNT,
            organization_uuid=ORG,
        )

    def test_result_models_public_private_divergence_and_server_identifier(self):
        result = public_result()
        self.assertTrue(result.content_diverges)
        self.assertNotEqual(
            result.clone.artifact_identifier,
            result.clone.seed.artifact_identifier,
        )
        self.assertEqual(result.private_source_sha256, result.clone.seed.source_sha256)
        self.assertEqual(
            result.url,
            "https://claude.ai/public/artifacts/" + TARGET_PUBLIC,
        )

    def test_clone_and_public_ids_can_never_overlap_seed(self):
        with self.assertRaisesRegex(FrameError, "seed identifier"):
            seeded.SeededCloneBinding(
                seed=seed_binding(),
                conversation_uuid=SEED_CONVERSATION,
                artifact_uuid=CLONE_ARTIFACT,
                version_uuid=CLONE_VERSION,
                message_uuid=CLONE_MESSAGE,
                artifact_identifier="different",
                artifact_type="text/html",
                code_language=None,
                title="Seed",
            )
        with self.assertRaisesRegex(FrameError, "overlaps provenance"):
            seeded.SeededPublicResult(
                clone=clone_binding(),
                published_uuid=SEED_PUBLIC,
                public_source=TARGET_SOURCE,
                public_source_sha256=hashlib.sha256(
                    TARGET_SOURCE.encode()
                ).hexdigest(),
            )
        for overlap in (
            SEED_CONVERSATION, SEED_ARTIFACT, SEED_VERSION, SEED_MESSAGE,
            CLONE_CONVERSATION, CLONE_ARTIFACT, CLONE_VERSION, CLONE_MESSAGE,
        ):
            with self.subTest(overlap=overlap), self.assertRaisesRegex(
                FrameError, "overlaps provenance"
            ):
                seeded.SeededPublicResult(
                    clone=clone_binding(),
                    published_uuid=overlap,
                    public_source=TARGET_SOURCE,
                    public_source_sha256=hashlib.sha256(
                        TARGET_SOURCE.encode()
                    ).hexdigest(),
                )

    def test_embedded_transaction_parses_and_contains_only_direct_api_actions(self):
        parsed = subprocess.run(
            ["node", "--check"],
            input=seeded._TRANSACTION_JS,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(parsed.returncode, 0, parsed.stderr)
        source = seeded._TRANSACTION_JS
        self.assertIn("/remixv2", source)
        self.assertIn("/publish_artifact", source)
        self.assertIn("published_artifacts/${publicId}", source)
        self.assertIn("chat_conversations/", source)
        self.assertIn("result_state === SEED_SOURCE", source)
        self.assertIn("content:TARGET_SOURCE", source)
        self.assertIn("[400, 401, 403, 404, 409, 413, 422]", source)
        self.assertNotIn("response.status >= 400", source)
        self.assertNotIn("Input.", source)
        self.assertNotIn("/completions", source)
        self.assertNotIn("window.open", source)

    def test_create_callback_order_is_intent_clone_intent_public(self):
        driver = self.publisher()
        phases = [
            {
                "stage": "seed_verified",
                "mutationAttempted": False,
                "ids": {},
                "metadata": None,
                "seedVerified": True,
            },
            clone_phase(),
            clone_phase("clone_private_verified") | {"mutationAttempted": False},
            published_phase(),
        ]
        events = []
        with mock.patch.object(
            driver, "_run_controlled", side_effect=lambda operation: operation(object())
        ), mock.patch.object(driver, "_evaluate", side_effect=phases):
            result = driver.create_and_publish(
                seed_binding(),
                TARGET_SOURCE,
                on_remix_intent=lambda _value: events.append("remix_intent"),
                on_clone_bound=lambda _value: events.append("clone_bound"),
                on_publish_intent=lambda _value: events.append("publish_intent"),
                on_public_bound=lambda _value: events.append("public_bound"),
                on_published=lambda _value: events.append("published"),
            )
        self.assertEqual(
            events,
            [
                "remix_intent",
                "clone_bound",
                "publish_intent",
                "public_bound",
                "published",
            ],
        )
        self.assertEqual(result.published_uuid, TARGET_PUBLIC)

    def test_seed_preflight_rejection_precedes_mutation_callback(self):
        driver = self.publisher()
        events = []
        with mock.patch.object(
            driver, "_run_controlled", side_effect=lambda operation: operation(object())
        ), mock.patch.object(
            driver,
            "_evaluate",
            return_value={
                "stage": "seed_mismatch",
                "mutationAttempted": False,
                "ids": {},
                "metadata": None,
            },
        ), self.assertRaises(seeded.SeededCapabilityUnavailable):
            driver.create_and_publish(
                seed_binding(),
                TARGET_SOURCE,
                on_remix_intent=lambda _value: events.append("mutation"),
            )
        self.assertEqual(events, [])

    def test_non_bound_remix_never_grants_clone_cleanup_authority(self):
        driver = self.publisher()
        conflicting = clone_phase("remix_preexisting_response")
        events = []
        with mock.patch.object(
            driver, "_run_controlled", side_effect=lambda operation: operation(object())
        ), mock.patch.object(
            driver,
            "_evaluate",
            side_effect=[
                {"stage":"seed_verified", "mutationAttempted":False,
                 "ids":{}, "metadata":None, "seedVerified":True},
                conflicting,
            ],
        ), self.assertRaises(seeded.SeededRemoteStateUnknown) as caught:
            driver.create_and_publish(
                seed_binding(), TARGET_SOURCE,
                on_clone_bound=lambda _value: events.append("clone_bound"),
            )
        self.assertEqual(events, [])
        self.assertIsNone(caught.exception.clone)
        self.assertIsNone(caught.exception.clone_conversation_uuid)

    def test_only_new_exact_clone_with_seed_postflight_failure_is_reconcilable(self):
        driver = self.publisher()
        phase = clone_phase("remix_seed_unverified")
        with mock.patch.object(
            driver, "_run_controlled", side_effect=lambda operation: operation(object())
        ), mock.patch.object(
            driver,
            "_evaluate",
            side_effect=[
                {"stage":"seed_verified", "mutationAttempted":False,
                 "ids":{}, "metadata":None, "seedVerified":True},
                phase,
            ],
        ), self.assertRaises(seeded.SeededRemoteStateUnknown) as caught:
            driver.create_and_publish(seed_binding(), TARGET_SOURCE)
        self.assertEqual(
            caught.exception.clone_conversation_uuid, CLONE_CONVERSATION
        )

    def test_new_response_conversation_survives_catalog_propagation_delay(self):
        driver = self.publisher()
        phase = {
            "stage": "remix_response_unresolved",
            "mutationAttempted": True,
            "ids": {"cloneConversationUuid": CLONE_CONVERSATION},
            "metadata": None,
        }
        with mock.patch.object(
            driver, "_run_controlled", side_effect=lambda operation: operation(object())
        ), mock.patch.object(
            driver,
            "_evaluate",
            side_effect=[
                {"stage":"seed_verified", "mutationAttempted":False,
                 "ids":{}, "metadata":None, "seedVerified":True},
                phase,
            ],
        ), self.assertRaises(seeded.SeededRemoteStateUnknown) as caught:
            driver.create_and_publish(seed_binding(), TARGET_SOURCE)
        self.assertEqual(
            caught.exception.clone_conversation_uuid, CLONE_CONVERSATION
        )

    def test_publish_unknown_preserves_exact_clone_and_public_observation(self):
        driver = self.publisher()
        phases = [
            {"stage":"seed_verified", "mutationAttempted":False,
             "ids":{}, "metadata":None, "seedVerified":True},
            clone_phase(),
            clone_phase("clone_private_verified") | {"mutationAttempted": False},
            published_phase("publish_readback_mismatch"),
        ]
        with mock.patch.object(
            driver, "_run_controlled", side_effect=lambda operation: operation(object())
        ), mock.patch.object(driver, "_evaluate", side_effect=phases), self.assertRaises(
            seeded.SeededRemoteStateUnknown
        ) as caught:
            driver.create_and_publish(seed_binding(), TARGET_SOURCE)
        self.assertEqual(caught.exception.clone, clone_binding())
        self.assertEqual(caught.exception.published_uuid, TARGET_PUBLIC)

    def test_clean_publish_rejection_is_durable_and_retains_private_clone(self):
        driver = self.publisher()
        phases = [
            {"stage":"seed_verified", "mutationAttempted":False,
             "ids":{}, "metadata":None, "seedVerified":True},
            clone_phase(),
            clone_phase("clone_private_verified") | {"mutationAttempted": False},
            clone_phase("publish_rejected") | {
                "mutationAttempted": True, "seedVerified": True
            },
        ]
        events = []
        with mock.patch.object(
            driver, "_run_controlled", side_effect=lambda operation: operation(object())
        ), mock.patch.object(driver, "_evaluate", side_effect=phases), self.assertRaisesRegex(
            seeded.SeededCapabilityUnavailable, "private clone was retained"
        ):
            driver.create_and_publish(
                seed_binding(), TARGET_SOURCE,
                on_clone_bound=lambda _value: events.append("clone_bound"),
                on_publish_rejected=lambda: events.append("publish_rejected"),
            )
        self.assertEqual(events, ["clone_bound", "publish_rejected"])

    def test_response_public_uuid_is_distinct_from_owner_bound_uuid(self):
        driver = self.publisher()
        phase = published_phase("publish_response_mismatch")
        phase["observedPublishedUuid"] = OBSERVED_PUBLIC
        phases = [
            {"stage":"seed_verified", "mutationAttempted":False,
             "ids":{}, "metadata":None, "seedVerified":True},
            clone_phase(),
            clone_phase("clone_private_verified") | {"mutationAttempted": False},
            phase,
        ]
        bound = []
        with mock.patch.object(
            driver, "_run_controlled", side_effect=lambda operation: operation(object())
        ), mock.patch.object(driver, "_evaluate", side_effect=phases), self.assertRaises(
            seeded.SeededRemoteStateUnknown
        ) as caught:
            driver.create_and_publish(
                seed_binding(), TARGET_SOURCE, on_public_bound=bound.append
            )
        self.assertEqual(bound[0].published_uuid, TARGET_PUBLIC)
        self.assertEqual(caught.exception.published_uuid, TARGET_PUBLIC)
        self.assertEqual(caught.exception.observed_published_uuid, OBSERVED_PUBLIC)

    def test_owner_bound_public_mismatch_is_journaled_and_cleanup_authorized(self):
        driver = self.publisher()
        phases = [
            {"stage":"seed_verified", "mutationAttempted":False,
             "ids":{}, "metadata":None, "seedVerified":True},
            clone_phase(),
            clone_phase("clone_private_verified") | {"mutationAttempted": False},
            published_phase("publish_public_mismatch")
            | {"publicReadVerified": False},
        ]
        bound = []
        with mock.patch.object(
            driver, "_run_controlled", side_effect=lambda operation: operation(object())
        ), mock.patch.object(driver, "_evaluate", side_effect=phases), self.assertRaises(
            seeded.SeededRemoteStateUnknown
        ):
            driver.create_and_publish(
                seed_binding(), TARGET_SOURCE, on_public_bound=bound.append
            )
        self.assertEqual(len(bound), 1)
        self.assertFalse(bound[0].public_verified)
        cleanup = [
            {"stage":"public_owner_verified", "mutationAttempted":False,
             "ids":{"publishedUuid":TARGET_PUBLIC}, "metadata":None,
             "ownerBound":True, "publicReadVerified":False, "seedVerified":True},
            {"stage":"unpublished", "mutationAttempted":True,
             "ids":{"publishedUuid":TARGET_PUBLIC}, "metadata":None,
             "tombstoneVerified":True, "seedVerified":True},
        ]
        with mock.patch.object(
            driver, "_run_controlled", side_effect=lambda operation: operation(object())
        ), mock.patch.object(driver, "_evaluate", side_effect=cleanup):
            self.assertTrue(driver.unpublish(bound[0]).published_deleted)

    def test_get_only_reconciliation_and_private_clone_delete(self):
        driver = self.publisher()
        reconciled = published_phase()
        reconciled["mutationAttempted"] = False
        callbacks = []
        with mock.patch.object(
            driver, "_run_controlled", side_effect=lambda operation: operation(object())
        ), mock.patch.object(driver, "_evaluate", return_value=reconciled) as evaluate:
            result = driver.reconcile_publish(
                clone_binding(), TARGET_SOURCE,
                on_public_bound=lambda _value: callbacks.append("bound"),
                on_published=lambda _value: callbacks.append("published"),
            )
        self.assertEqual(callbacks, ["bound", "published"])
        self.assertEqual(evaluate.call_args.args[1], "reconcile_publish")
        self.assertFalse(reconciled["mutationAttempted"])
        private_delete = [
            clone_phase("private_clone_verified") | {"mutationAttempted":False},
            clone_phase("deleted") | {
                "mutationAttempted":True, "containerDeleted":True
            },
        ]
        events = []
        with mock.patch.object(
            driver, "_run_controlled", side_effect=lambda operation: operation(object())
        ), mock.patch.object(driver, "_evaluate", side_effect=private_delete):
            self.assertTrue(driver.delete_private_clone(
                clone_binding(), TARGET_SOURCE,
                on_intent=lambda _value: events.append("intent"),
                on_verified=lambda: events.append("deleted"),
            ))
        self.assertEqual(events, ["intent", "deleted"])

    def test_unpublish_and_delete_callbacks_follow_verified_preflights(self):
        driver = self.publisher()
        result = public_result()
        unpublish_phases = [
            {"stage":"public_owner_verified", "mutationAttempted":False,
             "ids":{"publishedUuid":TARGET_PUBLIC}, "metadata":None,
             "ownerBound":True, "publicReadVerified":True, "seedVerified":True},
            {"stage":"unpublished", "mutationAttempted":True,
             "ids":{"publishedUuid":TARGET_PUBLIC}, "metadata":None,
             "tombstoneVerified":True, "seedVerified":True},
        ]
        events = []
        with mock.patch.object(
            driver, "_run_controlled", side_effect=lambda operation: operation(object())
        ), mock.patch.object(driver, "_evaluate", side_effect=unpublish_phases):
            deleted = driver.unpublish(
                result,
                on_intent=lambda _value: events.append("unpublish_intent"),
                on_verified=lambda: events.append("unpublished"),
            )
        self.assertTrue(deleted.published_deleted)
        delete_phases = [
            {"stage":"tombstone_verified", "mutationAttempted":False,
             "ids":{"publishedUuid":TARGET_PUBLIC}, "metadata":None,
             "tombstoneVerified":True, "seedVerified":True},
            {"stage":"deleted", "mutationAttempted":True,
             "ids":{"publishedUuid":TARGET_PUBLIC}, "metadata":None,
             "containerDeleted":True, "seedVerified":True},
        ]
        with mock.patch.object(
            driver, "_run_controlled", side_effect=lambda operation: operation(object())
        ), mock.patch.object(driver, "_evaluate", side_effect=delete_phases):
            self.assertTrue(driver.delete_container(
                deleted,
                on_intent=lambda _value: events.append("delete_intent"),
                on_verified=lambda: events.append("deleted"),
            ))
        self.assertEqual(
            events,
            ["unpublish_intent", "unpublished", "delete_intent", "deleted"],
        )


if __name__ == "__main__":
    unittest.main()
