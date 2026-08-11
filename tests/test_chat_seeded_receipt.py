"""Offline filesystem tests for seeded-public lifecycle receipts."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from clawdvert import chat_seeded_receipt as receipts
from clawdvert import chat_seeded_publish as seeded
from clawdvert import publish
from clawdvert.frames import FrameError


ORG = "11111111-2222-4333-8444-555555555555"
ACCOUNT = "0" * 64
SEED_SOURCE = "<!doctype html><title>Seed</title><p>seed-only-marker</p>"
TARGET_SOURCE = "<!doctype html><title>Target</title><p>target-only-marker</p>"


def seed_binding() -> seeded.SeedBinding:
    return seeded.SeedBinding(
        organization_uuid=ORG,
        account_email_sha256=ACCOUNT,
        published_uuid="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        conversation_uuid="11111111-aaaa-4bbb-8ccc-222222222222",
        artifact_uuid="22222222-aaaa-4bbb-8ccc-333333333333",
        version_uuid="33333333-aaaa-4bbb-8ccc-444444444444",
        message_uuid="44444444-aaaa-4bbb-8ccc-555555555555",
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
        conversation_uuid="55555555-aaaa-4bbb-8ccc-666666666666",
        artifact_uuid="66666666-aaaa-4bbb-8ccc-777777777777",
        version_uuid="77777777-aaaa-4bbb-8ccc-888888888888",
        message_uuid="88888888-aaaa-4bbb-8ccc-999999999999",
        artifact_identifier="server-issued-clone",
        artifact_type="text/html",
        code_language=None,
        title="Seed",
    )


def result(
    *, deleted: bool = False, verified: bool = True
) -> seeded.SeededPublicResult:
    return seeded.SeededPublicResult(
        clone=clone_binding(),
        published_uuid="99999999-aaaa-4bbb-8ccc-aaaaaaaaaaaa",
        public_source=TARGET_SOURCE,
        public_source_sha256=hashlib.sha256(TARGET_SOURCE.encode()).hexdigest(),
        public_verified=verified,
        published_deleted=deleted,
    )


class SeededReceiptTests(unittest.TestCase):
    def write_published(self, path: Path) -> None:
        journal = receipts.SeededReceiptJournal(
            str(path), seed=seed_binding(), target_source=TARGET_SOURCE
        )
        try:
            journal.mark_remix_pending()
            journal.record_clone(clone_binding())
            journal.mark_publish_pending()
            journal.record_public_bound(result(verified=False))
            journal.mark_published(result())
        finally:
            journal.close()

    def test_journal_is_mode_0600_append_only_and_contains_no_source(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "seeded.jsonl"
            self.write_published(path)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            records = [json.loads(line) for line in path.read_text().splitlines()]
        self.assertEqual(
            [item["stage"] for item in records],
            [
                "prepared", "remix_pending", "clone_bound", "publish_pending",
                "public_bound", "published",
            ],
        )
        raw = "\n".join(json.dumps(item) for item in records)
        self.assertNotIn("seed-only-marker", raw)
        self.assertNotIn("target-only-marker", raw)
        self.assertEqual(records[-1]["clone_artifact_identifier"], "server-issued-clone")

    def test_lifecycle_reconstructs_exact_result_and_advances_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "seeded.jsonl"
            self.write_published(path)
            lifecycle = receipts.SeededReceiptLifecycle(
                str(path),
                organization_uuid=ORG,
                account_email_sha256=ACCOUNT,
                seed_source=SEED_SOURCE,
                target_source=TARGET_SOURCE,
            )
            try:
                bound = lifecycle.result()
                self.assertEqual(bound, result())
                lifecycle.mark_unpublish_pending(bound)
                lifecycle.mark_unpublished()
                tombstone = lifecycle.result()
                self.assertTrue(tombstone.published_deleted)
                lifecycle.mark_delete_pending(tombstone)
                lifecycle.mark_deleted()
                self.assertEqual(lifecycle.stage, "deleted")
            finally:
                lifecycle.close()
            final = json.loads(path.read_text().splitlines()[-1])
        self.assertEqual(final["stage"], "deleted")

    def test_public_bound_is_durable_before_anonymous_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "seeded.jsonl"
            journal = receipts.SeededReceiptJournal(
                str(path), seed=seed_binding(), target_source=TARGET_SOURCE
            )
            try:
                journal.mark_remix_pending()
                journal.record_clone(clone_binding())
                journal.mark_publish_pending()
                journal.record_public_bound(result(verified=False))
            finally:
                journal.close()
            lifecycle = receipts.SeededReceiptLifecycle(
                str(path), organization_uuid=ORG,
                account_email_sha256=ACCOUNT, seed_source=SEED_SOURCE,
                target_source=TARGET_SOURCE,
            )
            try:
                self.assertEqual(lifecycle.stage, "public_bound")
                self.assertFalse(lifecycle.result().public_verified)
                lifecycle.mark_published(result())
                self.assertEqual(lifecycle.stage, "published")
                self.assertTrue(lifecycle.result().public_verified)
            finally:
                lifecycle.close()

    def test_private_clone_delete_round_trips_without_public_uuid(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "seeded.jsonl"
            journal = receipts.SeededReceiptJournal(
                str(path), seed=seed_binding(), target_source=TARGET_SOURCE
            )
            try:
                journal.mark_remix_pending()
                journal.record_clone(clone_binding())
            finally:
                journal.close()
            lifecycle = receipts.SeededReceiptLifecycle(
                str(path), organization_uuid=ORG,
                account_email_sha256=ACCOUNT, seed_source=SEED_SOURCE,
                target_source=TARGET_SOURCE,
            )
            try:
                lifecycle.mark_delete_pending()
                lifecycle.mark_deleted()
            finally:
                lifecycle.close()
            reopened = receipts.SeededReceiptLifecycle(
                str(path), organization_uuid=ORG,
                account_email_sha256=ACCOUNT, seed_source=SEED_SOURCE,
                target_source=TARGET_SOURCE,
            )
            try:
                self.assertEqual(reopened.stage, "deleted")
                self.assertFalse(reopened.has_public_binding)
                self.assertEqual(reopened.clone_binding(), clone_binding())
                with self.assertRaisesRegex(FrameError, "no exact public binding"):
                    reopened.result()
            finally:
                reopened.close()

    def test_publish_rejection_retains_clone_and_allows_private_delete(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rejected.jsonl"
            journal = receipts.SeededReceiptJournal(
                str(path), seed=seed_binding(), target_source=TARGET_SOURCE
            )
            try:
                journal.mark_remix_pending()
                journal.record_clone(clone_binding())
                journal.mark_publish_pending()
                journal.record_publish_rejected()
                self.assertEqual(journal.stage, "publish_rejected")
                self.assertEqual(journal.clone_binding(), clone_binding())
            finally:
                journal.close()

            lifecycle = receipts.SeededReceiptLifecycle(
                str(path), organization_uuid=ORG,
                account_email_sha256=ACCOUNT, seed_source=SEED_SOURCE,
                target_source=TARGET_SOURCE,
            )
            try:
                self.assertEqual(lifecycle.stage, "publish_rejected")
                self.assertFalse(lifecycle.has_public_binding)
                self.assertEqual(lifecycle.clone_binding(), clone_binding())
                with self.assertRaisesRegex(FrameError, "no exact public binding"):
                    lifecycle.result()
                lifecycle.mark_delete_pending()
                lifecycle.mark_deleted()
            finally:
                lifecycle.close()

            final = json.loads(path.read_text().splitlines()[-1])
            self.assertEqual(final["stage"], "deleted")
            self.assertIsNone(final["published_uuid"])
            self.assertIsNone(final["public_url"])

    def test_response_observations_are_durable_but_not_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "seeded.jsonl"
            journal = receipts.SeededReceiptJournal(
                str(path), seed=seed_binding(), target_source=TARGET_SOURCE
            )
            try:
                self.assertEqual(journal.stage, "prepared")
            finally:
                journal.close()
            lifecycle = receipts.SeededReceiptLifecycle(
                str(path), organization_uuid=ORG,
                account_email_sha256=ACCOUNT, seed_source=SEED_SOURCE,
                target_source=TARGET_SOURCE,
            )
            try:
                lifecycle.mark_remix_pending()
                lifecycle.record_observations(
                    clone_conversation_uuid=clone_binding().conversation_uuid
                )
                lifecycle.record_clone(clone_binding())
                lifecycle.mark_publish_pending()
                response_observation = "bbbbbbbb-1111-4111-8111-cccccccccccc"
                lifecycle.record_observations(
                    published_uuid=response_observation
                )
                self.assertEqual(
                    lifecycle.observed_clone_conversation_uuid,
                    clone_binding().conversation_uuid,
                )
                self.assertEqual(
                    lifecycle.observed_published_uuid, response_observation
                )
                self.assertFalse(lifecycle.has_public_binding)
                with self.assertRaisesRegex(FrameError, "no exact public binding"):
                    lifecycle.result()
                lifecycle.record_public_bound(result(verified=False))
            finally:
                lifecycle.close()
            reopened = receipts.SeededReceiptLifecycle(
                str(path), organization_uuid=ORG,
                account_email_sha256=ACCOUNT, seed_source=SEED_SOURCE,
                target_source=TARGET_SOURCE,
            )
            try:
                self.assertEqual(reopened.result().published_uuid, result().published_uuid)
                self.assertEqual(
                    reopened.observed_published_uuid, response_observation
                )
            finally:
                reopened.close()

    def test_partial_tail_dry_run_is_byte_for_byte_non_mutating(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt_path = root / "seeded.jsonl"
            self.write_published(receipt_path)
            with receipt_path.open("ab") as handle:
                handle.write(b'{"partial":')
            before = receipt_path.read_bytes()
            seed_path = root / "seed.html"
            target_path = root / "target.html"
            seed_path.write_text(SEED_SOURCE, encoding="utf-8")
            target_path.write_text(TARGET_SOURCE, encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                publish.main(
                    [
                        str(target_path), "--surface", "chat", "--chat-adapter",
                        "seeded-public", "--private", "--seed-file", str(seed_path),
                        "--receipt", str(receipt_path), "--organization-uuid", ORG,
                        "--account-email-sha256", ACCOUNT, "--dry-run",
                    ]
                )
            self.assertEqual(receipt_path.read_bytes(), before)
            self.assertIn("DRY RUN", output.getvalue())

    def test_partial_tail_requires_explicit_repair_before_append(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "seeded.jsonl"
            self.write_published(path)
            with path.open("ab") as handle:
                handle.write(b"{")
            lifecycle = receipts.SeededReceiptLifecycle(
                str(path), organization_uuid=ORG,
                account_email_sha256=ACCOUNT, seed_source=SEED_SOURCE,
                target_source=TARGET_SOURCE,
            )
            try:
                self.assertTrue(lifecycle.has_partial_tail)
                with self.assertRaisesRegex(FrameError, "partial trailing record"):
                    lifecycle.mark_unpublish_pending(lifecycle.result())
                lifecycle.repair_partial_tail()
                lifecycle.mark_unpublish_pending(lifecycle.result())
            finally:
                lifecycle.close()
            self.assertTrue(path.read_bytes().endswith(b"\n"))

    def test_source_org_and_account_mismatch_fail_before_lifecycle_use(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "seeded.jsonl"
            self.write_published(path)
            cases = (
                ("wrong source", ORG, ACCOUNT, TARGET_SOURCE + "x"),
                ("another org", "aaaaaaaa-2222-4333-8444-555555555555", ACCOUNT, TARGET_SOURCE),
                ("another account", ORG, "1" * 64, TARGET_SOURCE),
            )
            for _label, org, account, target in cases:
                with self.subTest(_label), self.assertRaises(FrameError):
                    receipts.SeededReceiptLifecycle(
                        str(path),
                        organization_uuid=org,
                        account_email_sha256=account,
                        seed_source=SEED_SOURCE,
                        target_source=target,
                    )

    def test_existing_path_symlink_and_insecure_mode_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            existing = root / "existing.jsonl"
            existing.write_text("x")
            with self.assertRaisesRegex(FrameError, "already exists"):
                receipts.validate_new_receipt(str(existing))
            link = root / "link.jsonl"
            os.symlink(existing, link)
            with self.assertRaises(FrameError):
                receipts.SeededReceiptLifecycle(
                    str(link),
                    organization_uuid=ORG,
                    account_email_sha256=ACCOUNT,
                    seed_source=SEED_SOURCE,
                    target_source=TARGET_SOURCE,
                )
            published = root / "published.jsonl"
            self.write_published(published)
            published.chmod(0o644)
            with self.assertRaisesRegex(FrameError, "mode-0600"):
                receipts.SeededReceiptLifecycle(
                    str(published),
                    organization_uuid=ORG,
                    account_email_sha256=ACCOUNT,
                    seed_source=SEED_SOURCE,
                    target_source=TARGET_SOURCE,
                )
            if getattr(os, "O_NOFOLLOW", 0):
                real_parent = root / "real-parent"
                real_parent.mkdir()
                linked_parent = root / "linked-parent"
                os.symlink(real_parent, linked_parent)
                with self.assertRaisesRegex(FrameError, "directory is unavailable"):
                    receipts.validate_new_receipt(
                        str(linked_parent / "new-receipt.jsonl")
                    )


if __name__ == "__main__":
    unittest.main()
