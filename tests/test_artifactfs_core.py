import base64
import hashlib
import json
import os
import tempfile
import unittest
from unittest import mock

from artifactfs import core
from artifactfs import (
    SnapshotError,
    SnapshotLimits,
    decode_snapshot,
    encode_snapshot,
    snapshot_directory,
    validate_relative_path,
)
from artifactfs.mount import ArtifactFuseOperations


class ArtifactFSSnapshotTests(unittest.TestCase):
    def make_tree(self, root):
        os.mkdir(os.path.join(root, "docs"))
        with open(os.path.join(root, "docs", "readme.txt"), "wb") as handle:
            handle.write(b"hello\n")
        with open(os.path.join(root, "binary.bin"), "wb") as handle:
            handle.write(bytes(range(256)))
        script = os.path.join(root, "run.sh")
        with open(script, "wb") as handle:
            handle.write(b"#!/bin/sh\nexit 0\n")
        os.chmod(script, 0o755)

    def test_directory_round_trip_is_deterministic_and_mount_compatible(self):
        with tempfile.TemporaryDirectory() as root:
            self.make_tree(root)
            first = snapshot_directory(root)
            second = snapshot_directory(root)

        encoded = encode_snapshot(first)
        decoded = decode_snapshot(encoded)
        self.assertEqual(encoded, encode_snapshot(second))
        self.assertEqual(encoded, encode_snapshot(decoded))
        self.assertEqual(first.version, decoded.version)
        self.assertEqual(decoded.read_file("binary.bin"), bytes(range(256)))
        self.assertEqual(decoded.get("run.sh").mode, 0o755)
        self.assertEqual(
            [entry.path for entry in decoded.iterdir(".")],
            ["binary.bin", "docs", "run.sh"],
        )

        operations = ArtifactFuseOperations(decoded, version=decoded.version)
        self.assertEqual(operations.read("/docs/readme.txt", 5, 0, 0), b"hello")
        self.assertEqual(
            [row[0] for row in operations.readdir("/", 0)],
            [".", "..", "binary.bin", "docs", "run.sh"],
        )

    def test_empty_directories_are_explicit(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "a", "empty"))
            snapshot = snapshot_directory(root)
        decoded = decode_snapshot(encode_snapshot(snapshot))
        self.assertEqual(decoded.get("a/empty").kind, "directory")
        self.assertEqual(decoded.iterdir("a/empty"), ())

    def test_root_sorts_before_valid_punctuation_filenames(self):
        with tempfile.TemporaryDirectory() as root:
            for name in ("!bang", "-file"):
                with open(os.path.join(root, name), "wb") as handle:
                    handle.write(name.encode("ascii"))
            snapshot = snapshot_directory(root)
        decoded = decode_snapshot(encode_snapshot(snapshot))
        self.assertEqual(decoded.read_file("!bang"), b"!bang")
        self.assertEqual(decoded.read_file("-file"), b"-file")

    def test_rejects_links_devices_and_reserved_control_directory(self):
        with tempfile.TemporaryDirectory() as root:
            os.symlink("missing", os.path.join(root, "link"))
            with self.assertRaisesRegex(SnapshotError, "symbolic"):
                snapshot_directory(root)
        with tempfile.TemporaryDirectory() as root:
            os.mkdir(os.path.join(root, ".artifactfs"))
            with self.assertRaisesRegex(SnapshotError, "reserved"):
                snapshot_directory(root)

    def test_rejects_unsafe_and_collision_paths(self):
        for value in ("/abs", "../escape", "a//b", "a/./b", "a\\b", "a\x00b"):
            with self.subTest(value=value), self.assertRaises(SnapshotError):
                validate_relative_path(value)
        self.assertEqual(validate_relative_path("cafe\u0301.txt"), "café.txt")

        def wire_file(path, data):
            return {
                "data": base64.b64encode(data).decode("ascii"),
                "kind": "file",
                "mode": 0o644,
                "path": path,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }

        collision = {
            "entries": [
                {"kind": "directory", "mode": 0o755, "path": "."},
                wire_file("Name", b"a"),
                wire_file("name", b"b"),
            ],
            "format": "artifactfs.snapshot.v1",
        }
        raw = json.dumps(collision, sort_keys=True, separators=(",", ":"))
        with self.assertRaisesRegex(SnapshotError, "case-fold"):
            decode_snapshot(raw)

    def test_limits_are_enforced_before_serialization(self):
        limits = SnapshotLimits(
            max_entries=2,
            max_total_bytes=3,
            max_file_bytes=3,
            max_serialized_bytes=4096,
            max_path_bytes=64,
            max_component_bytes=32,
        )
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "file"), "wb") as handle:
                handle.write(b"four")
            with self.assertRaisesRegex(SnapshotError, "byte limit"):
                snapshot_directory(root, limits=limits)

    def test_rejects_group_or_world_writable_source_entries(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "shared.txt")
            with open(path, "wb") as handle:
                handle.write(b"shared")
            os.chmod(path, 0o666)
            with self.assertRaisesRegex(SnapshotError, "owner-controlled"):
                snapshot_directory(root)

    def test_corruption_duplicate_keys_and_noncanonical_json_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "file"), "wb") as handle:
                handle.write(b"safe")
            encoded = encode_snapshot(snapshot_directory(root))

        value = json.loads(encoded)
        value["entries"][1]["sha256"] = "0" * 64
        corrupt = json.dumps(value, sort_keys=True, separators=(",", ":"))
        with self.assertRaisesRegex(SnapshotError, "integrity"):
            decode_snapshot(corrupt)

        duplicate = encoded[:-1] + ',"format":"artifactfs.snapshot.v1"}'
        with self.assertRaisesRegex(SnapshotError, "strict JSON"):
            decode_snapshot(duplicate)

        pretty = json.dumps(json.loads(encoded), indent=2, sort_keys=True)
        with self.assertRaisesRegex(SnapshotError, "canonical"):
            decode_snapshot(pretty)

    def test_directory_replacement_cannot_escape_the_pinned_root(self):
        with tempfile.TemporaryDirectory() as parent:
            root = os.path.join(parent, "root")
            outside = os.path.join(parent, "outside")
            os.mkdir(root)
            os.mkdir(outside)
            os.mkdir(os.path.join(root, "sub"))
            with open(os.path.join(root, "sub", "inside.txt"), "wb") as handle:
                handle.write(b"INSIDE")
            with open(os.path.join(outside, "secret.txt"), "wb") as handle:
                handle.write(b"OUTSIDE")

            original = core._open_child_directory
            swapped = False

            def replace_before_open(parent_fd, name, initial):
                nonlocal swapped
                if name == "sub" and not swapped:
                    swapped = True
                    os.rename(os.path.join(root, "sub"), os.path.join(root, "old"))
                    os.symlink(outside, os.path.join(root, "sub"))
                return original(parent_fd, name, initial)

            with mock.patch.object(
                core, "_open_child_directory", side_effect=replace_before_open
            ):
                with self.assertRaisesRegex(SnapshotError, "changed"):
                    snapshot_directory(root)

    def test_json_structure_and_integer_tokens_are_bounded_before_parse(self):
        too_many_nodes = (
            '{"entries":[' + ",".join("[]" for _ in range(100))
            + '],"format":"artifactfs.snapshot.v1"}'
        )
        with self.assertRaisesRegex(SnapshotError, "strict JSON"):
            decode_snapshot(too_many_nodes, limits=SnapshotLimits(max_entries=1))

        huge_integer = (
            '{"entries":[{"kind":"directory","mode":'
            + ("9" * 10_000)
            + ',"path":"."}],"format":"artifactfs.snapshot.v1"}'
        )
        with self.assertRaisesRegex(SnapshotError, "strict JSON"):
            decode_snapshot(huge_integer)


if __name__ == "__main__":
    unittest.main()
