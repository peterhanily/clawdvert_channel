import json
import os
import stat
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from unittest import mock

from artifactfs.core import snapshot_directory
from artifactfs.transaction import (
    JOURNAL_FORMAT,
    InvalidTransitionError,
    JournalCapacityError,
    JournalCorruptionError,
    JournalSecurityError,
    RecoveryClassification,
    TransactionJournal,
    TransactionRecord,
    TransactionStage,
    parse_transaction_records,
)


SLUG = "11111111-1111-4111-8111-111111111111"
COMMIT = "22222222-2222-4222-8222-222222222222"
BASE_VERSION = "provider-version-1"
RESPONSE_VERSION = "provider-version-2"
SNAPSHOT_SHA = "a" * 64


class ArtifactFSTransactionTests(unittest.TestCase):
    def secure_tempdir(self):
        # macOS exposes its default temporary directory through /var, a system
        # symlink. TransactionJournal deliberately rejects linked components.
        return tempfile.TemporaryDirectory(dir=os.getcwd())

    def prepared(self, **changes):
        values = {
            "slug": SLUG,
            "base_version": BASE_VERSION,
            "target_snapshot_sha": SNAPSHOT_SHA,
            "commit_uuid": COMMIT,
        }
        values.update(changes)
        return TransactionRecord.prepared(**values)

    def write_raw_journal(self, path, data):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(descriptor, data)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def test_complete_lifecycle_is_fsynced_mode_0600_and_secret_free(self):
        with self.secure_tempdir() as root:
            path = os.path.join(root, "transactions.jsonl")
            journal = TransactionJournal(path)
            prepared = self.prepared()

            with mock.patch(
                "artifactfs.transaction.os.fsync", wraps=os.fsync
            ) as fsync:
                state = journal.append(prepared)
                self.assertTrue(state.safe_to_dispatch)
                self.assertGreaterEqual(fsync.call_count, 2)  # file and new dirent

            details = os.lstat(path)
            self.assertTrue(stat.S_ISREG(details.st_mode))
            self.assertEqual(stat.S_IMODE(details.st_mode), 0o600)

            dispatched = prepared.advance(TransactionStage.DISPATCHED)
            response = dispatched.advance(
                TransactionStage.RESPONSE_BOUND,
                provider_response_version=RESPONSE_VERSION,
            )
            verified = response.advance(TransactionStage.READBACK_VERIFIED)
            checkpointed = verified.advance(TransactionStage.CHECKPOINTED)
            for record in (dispatched, response, verified, checkpointed):
                journal.append(record)

            records = journal.read_records()
            state = journal.state(COMMIT)
            self.assertEqual(
                [item.stage for item in records],
                [
                    TransactionStage.PREPARED,
                    TransactionStage.DISPATCHED,
                    TransactionStage.RESPONSE_BOUND,
                    TransactionStage.READBACK_VERIFIED,
                    TransactionStage.CHECKPOINTED,
                ],
            )
            self.assertIsNotNone(state)
            self.assertEqual(state.record_count, 5)
            self.assertIs(state.recovery, RecoveryClassification.COMPLETE)

            with open(path, "rb") as handle:
                raw = handle.read()
            self.assertNotIn(b"content", raw)
            self.assertNotIn(b"token", raw.lower())
            for line in raw.splitlines():
                value = json.loads(line)
                self.assertEqual(value["format"], JOURNAL_FORMAT)
                self.assertEqual(
                    set(value),
                    {
                        "format",
                        "stage",
                        "slug",
                        "base_version",
                        "commit_uuid",
                        "target_snapshot_sha",
                        "provider_response_version",
                    },
                )

    def test_snapshot_sha_property_is_the_transaction_digest_type(self):
        with self.secure_tempdir() as root:
            workspace = os.path.join(root, "workspace")
            os.mkdir(workspace)
            with open(os.path.join(workspace, "hello.txt"), "wb") as handle:
                handle.write(b"hello\n")
            snapshot = snapshot_directory(workspace)

        record = self.prepared(target_snapshot_sha=snapshot.sha256)
        self.assertEqual(record.target_snapshot_sha, snapshot.sha256)
        self.assertEqual(len(record.target_snapshot_sha), 64)

    def test_only_prepared_is_safe_to_dispatch_after_recovery(self):
        prepared = self.prepared()
        stages = [
            prepared,
            prepared.advance(TransactionStage.DISPATCHED),
        ]
        stages.append(
            stages[-1].advance(
                TransactionStage.RESPONSE_BOUND,
                provider_response_version=RESPONSE_VERSION,
            )
        )
        stages.append(stages[-1].advance(TransactionStage.READBACK_VERIFIED))
        stages.append(stages[-1].advance(TransactionStage.CHECKPOINTED))

        expected = [
            RecoveryClassification.SAFE_TO_DISPATCH,
            RecoveryClassification.READ_ONLY_RECONCILIATION_REQUIRED,
            RecoveryClassification.READ_ONLY_RECONCILIATION_REQUIRED,
            RecoveryClassification.READ_ONLY_RECONCILIATION_REQUIRED,
            RecoveryClassification.COMPLETE,
        ]
        for count, classification in enumerate(expected, 1):
            with self.subTest(count=count):
                state = parse_transaction_records(stages[:count])[COMMIT]
                self.assertIs(state.recovery, classification)
                self.assertEqual(
                    state.safe_to_dispatch,
                    classification is RecoveryClassification.SAFE_TO_DISPATCH,
                )

    def test_provider_conflict_is_an_explicit_terminal_branch(self):
        prepared = self.prepared()
        dispatched = prepared.advance(TransactionStage.DISPATCHED)
        conflict = dispatched.advance(
            TransactionStage.CONFLICTED,
            provider_response_version="new-live-version",
        )
        state = parse_transaction_records((prepared, dispatched, conflict))[COMMIT]

        self.assertTrue(state.conflicted)
        self.assertFalse(state.safe_to_dispatch)
        self.assertIs(
            state.recovery,
            RecoveryClassification.CONFLICT_REQUIRES_RESOLUTION,
        )
        with self.assertRaises(InvalidTransitionError):
            conflict.advance(TransactionStage.CHECKPOINTED)
        with self.assertRaisesRegex(ValueError, "different live version"):
            dispatched.advance(
                TransactionStage.CONFLICTED,
                provider_response_version=BASE_VERSION,
            )

    def test_invalid_or_mutated_histories_fail_closed_before_append(self):
        prepared = self.prepared()
        dispatched = prepared.advance(TransactionStage.DISPATCHED)
        skipped = TransactionRecord(
            stage=TransactionStage.READBACK_VERIFIED,
            slug=SLUG,
            base_version=BASE_VERSION,
            commit_uuid=COMMIT,
            target_snapshot_sha=SNAPSHOT_SHA,
            provider_response_version=RESPONSE_VERSION,
        )
        changed_target = TransactionRecord(
            stage=TransactionStage.RESPONSE_BOUND,
            slug=SLUG,
            base_version=BASE_VERSION,
            commit_uuid=COMMIT,
            target_snapshot_sha="b" * 64,
            provider_response_version=RESPONSE_VERSION,
        )
        histories = (
            (dispatched,),
            (prepared, dispatched, skipped),
            (prepared, dispatched, changed_target),
        )
        for records in histories:
            with self.subTest(records=records), self.assertRaises(
                JournalCorruptionError
            ):
                parse_transaction_records(records)

        with self.secure_tempdir() as root:
            path = os.path.join(root, "transactions.jsonl")
            journal = TransactionJournal(path)
            journal.append(prepared)
            size_before = os.path.getsize(path)
            with self.assertRaises(JournalCorruptionError):
                journal.append(skipped)
            self.assertEqual(os.path.getsize(path), size_before)

    def test_fixed_schema_duplicate_keys_and_truncation_fail_closed(self):
        valid = self.prepared().to_dict()
        extra = dict(valid)
        extra["accessToken"] = "must-not-be-accepted"
        duplicate = (
            '{"format":"%s","format":"%s"}\n'
            % (JOURNAL_FORMAT, JOURNAL_FORMAT)
        ).encode("ascii")
        cases = (
            json.dumps(extra, sort_keys=True, separators=(",", ":")).encode("ascii")
            + b"\n",
            duplicate,
            json.dumps(valid, sort_keys=True, separators=(",", ":")).encode("ascii"),
        )

        for index, raw in enumerate(cases):
            with self.subTest(index=index), self.secure_tempdir() as root:
                path = os.path.join(root, "transactions.jsonl")
                self.write_raw_journal(path, raw)
                with self.assertRaises(JournalCorruptionError):
                    TransactionJournal(path).read_records()

    def test_journal_rejects_unsafe_modes_links_and_owner_mismatch(self):
        with self.secure_tempdir() as root:
            path = os.path.join(root, "transactions.jsonl")
            journal = TransactionJournal(path)
            journal.append(self.prepared())
            os.chmod(path, 0o644)
            with self.assertRaisesRegex(JournalSecurityError, "0600"):
                journal.read_records()

        with self.secure_tempdir() as root:
            target = os.path.join(root, "target")
            self.write_raw_journal(target, b"")
            linked = os.path.join(root, "transactions.jsonl")
            os.symlink(target, linked)
            with self.assertRaises(JournalSecurityError):
                TransactionJournal(linked).append(self.prepared())

        with self.secure_tempdir() as root:
            real = os.path.join(root, "real")
            os.mkdir(real, 0o700)
            alias = os.path.join(root, "alias")
            os.symlink(real, alias)
            linked_path = os.path.join(alias, "transactions.jsonl")
            with self.assertRaisesRegex(JournalSecurityError, "linked directory"):
                TransactionJournal(linked_path).append(self.prepared())

        with self.secure_tempdir() as root:
            path = os.path.join(root, "transactions.jsonl")
            journal = TransactionJournal(path)
            journal.append(self.prepared())
            hardlink = os.path.join(root, "hardlink.jsonl")
            os.link(path, hardlink)
            with self.assertRaisesRegex(JournalSecurityError, "hard-linked"):
                journal.read_records()

        with self.secure_tempdir() as root:
            path = os.path.join(root, "transactions.jsonl")
            with mock.patch(
                "artifactfs.transaction.os.geteuid", return_value=os.geteuid() + 1
            ):
                with self.assertRaisesRegex(JournalSecurityError, "parent"):
                    TransactionJournal(path).append(self.prepared())

    def test_writer_uses_append_flag_and_advisory_exclusive_lock(self):
        with self.secure_tempdir() as root:
            path = os.path.join(root, "transactions.jsonl")
            real_open = os.open
            real_flock = __import__("fcntl").flock
            with mock.patch(
                "artifactfs.transaction.os.open", wraps=real_open
            ) as opened, mock.patch(
                "artifactfs.transaction.fcntl.flock", wraps=real_flock
            ) as flocked:
                TransactionJournal(path).append(self.prepared())

            flags = [
                call.args[1]
                for call in opened.call_args_list
                if len(call.args) >= 2 and isinstance(call.args[1], int)
            ]
            self.assertTrue(any(value & os.O_APPEND for value in flags))
            operations = [call.args[1] for call in flocked.call_args_list]
            self.assertIn(__import__("fcntl").LOCK_EX, operations)
            self.assertIn(__import__("fcntl").LOCK_UN, operations)

    def test_concurrent_journal_replacement_is_detected_before_append(self):
        with self.secure_tempdir() as root:
            path = os.path.join(root, "transactions.jsonl")
            moved = os.path.join(root, "moved.jsonl")
            journal = TransactionJournal(path)
            prepared = self.prepared()
            journal.append(prepared)

            from artifactfs import transaction

            real_read = transaction._read_records_fd

            def read_then_replace(descriptor):
                records = real_read(descriptor)
                os.rename(path, moved)
                self.write_raw_journal(path, b"")
                return records

            with mock.patch(
                "artifactfs.transaction._read_records_fd",
                side_effect=read_then_replace,
            ):
                with self.assertRaisesRegex(JournalSecurityError, "replaced"):
                    journal.append(prepared.advance(TransactionStage.DISPATCHED))

            self.assertEqual(os.path.getsize(path), 0)
            self.assertEqual(
                TransactionJournal(moved).read_records(),
                (prepared,),
            )

    def test_journal_byte_and_record_bounds_fail_before_append(self):
        with self.secure_tempdir() as root:
            path = os.path.join(root, "transactions.jsonl")
            journal = TransactionJournal(path)
            prepared = self.prepared()
            journal.append(prepared)
            size = os.path.getsize(path)
            dispatched = prepared.advance(TransactionStage.DISPATCHED)

            with mock.patch(
                "artifactfs.transaction.MAX_JOURNAL_BYTES", size
            ), self.assertRaisesRegex(JournalCapacityError, "byte limit"):
                journal.append(dispatched)
            self.assertEqual(os.path.getsize(path), size)

            with mock.patch(
                "artifactfs.transaction.MAX_JOURNAL_RECORDS", 1
            ), self.assertRaisesRegex(JournalCapacityError, "record limit"):
                journal.append(dispatched)
            self.assertEqual(os.path.getsize(path), size)

    def test_records_and_parsed_state_are_immutable(self):
        record = self.prepared()
        with self.assertRaises(FrozenInstanceError):
            record.slug = "33333333-3333-4333-8333-333333333333"
        states = parse_transaction_records((record,))
        with self.assertRaises(TypeError):
            states[COMMIT] = states[COMMIT]

    def test_identifiers_and_snapshot_digest_are_strict(self):
        invalid = (
            {"slug": "../artifact"},
            {"commit_uuid": "not-a-uuid"},
            {"commit_uuid": ""},
            {"base_version": "contains space"},
            {"target_snapshot_sha": "A" * 64},
            {"target_snapshot_sha": "0" * 63},
        )
        for values in invalid:
            with self.subTest(values=values), self.assertRaises(
                (TypeError, ValueError)
            ):
                self.prepared(**values)


if __name__ == "__main__":
    unittest.main()
