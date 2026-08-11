import errno
import os
import stat
import unittest
from dataclasses import dataclass
from unittest import mock

from artifact_bridge.models import (
    Artifact,
    ArtifactVersion,
    FetchedArtifact,
    Representation,
)
from artifactfs.mount import (
    ArtifactFuseOperations,
    FuseUnavailableError,
    deterministic_inode,
    mount_snapshot,
)
from artifactfs.provider import ServedArtifactSnapshot


@dataclass(frozen=True)
class FakeEntry:
    path: str
    kind: str
    data: bytes = b""
    inode_id: int = None

    @property
    def size(self):
        return len(self.data)


class FakeSnapshot:
    def __init__(self, version=7):
        self.version = version
        self.entries = {
            ".": FakeEntry(".", "directory", inode_id=1),
            "z.txt": FakeEntry("z.txt", "file", b"last"),
            "docs": FakeEntry("docs", "directory"),
            "docs/readme.md": FakeEntry(
                "docs/readme.md", "file", b"immutable snapshot\n", inode_id=99
            ),
            "alpha.txt": FakeEntry("alpha.txt", "file", b"first"),
        }

    def get(self, path):
        try:
            return self.entries[path]
        except KeyError as exc:
            raise FileNotFoundError(path) from exc

    def iterdir(self, path="."):
        entry = self.get(path)
        if entry.kind != "directory":
            raise NotADirectoryError(path)
        # Deliberately return insertion order; the adapter owns determinism.
        children = []
        for candidate in self.entries.values():
            if candidate.path == ".":
                continue
            parent = candidate.path.rsplit("/", 1)[0] if "/" in candidate.path else "."
            if parent == path:
                children.append(candidate)
        return tuple(children)

    def read_file(self, path):
        entry = self.get(path)
        if entry.kind == "directory":
            raise IsADirectoryError(path)
        return entry.data


class ArtifactFuseOperationsTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = FakeSnapshot()
        self.operations = ArtifactFuseOperations(self.snapshot, version=7)

    def assert_errno(self, expected, callback, *args):
        with self.assertRaises(OSError) as caught:
            callback(*args)
        self.assertEqual(caught.exception.errno, expected)

    def readdir_names(self, path):
        rows = self.operations.readdir(path, 0)
        self.assertTrue(all(len(row) == 3 for row in rows))
        self.assertTrue(all(row[1]["st_ino"] > 0 for row in rows))
        return [row[0] for row in rows]

    def test_getattr_uses_owner_only_read_permissions_and_stable_inodes(self):
        root = self.operations.getattr("/")
        regular = self.operations.getattr("/alpha.txt")
        explicit = self.operations.getattr("/docs/readme.md")

        self.assertTrue(stat.S_ISDIR(root["st_mode"]))
        self.assertEqual(stat.S_IMODE(root["st_mode"]), 0o500)
        self.assertTrue(stat.S_ISREG(regular["st_mode"]))
        self.assertEqual(stat.S_IMODE(regular["st_mode"]), 0o400)
        self.assertEqual(root["st_ino"], 1)
        self.assertEqual(explicit["st_ino"], 99)
        self.assertEqual(regular["st_size"], 5)

        second = ArtifactFuseOperations(FakeSnapshot(version=7))
        self.assertEqual(
            regular["st_ino"], second.getattr("/alpha.txt")["st_ino"]
        )
        self.assertNotEqual(
            regular["st_ino"],
            ArtifactFuseOperations(FakeSnapshot(version=8)).getattr("/alpha.txt")[
                "st_ino"
            ],
        )

    def test_inode_fallback_is_repeatable_nonzero_and_root_is_reserved(self):
        self.assertEqual(deterministic_inode(42, "."), 1)
        inode = deterministic_inode(42, "nested/file.txt")
        self.assertGreater(inode, 1)
        self.assertEqual(inode, deterministic_inode(42, "nested/file.txt"))
        self.assertNotEqual(inode, deterministic_inode(43, "nested/file.txt"))

    def test_readdir_is_sorted_and_read_honors_offset_and_size(self):
        self.assertEqual(
            self.readdir_names("/"),
            [".", "..", "alpha.txt", "docs", "z.txt"],
        )
        self.assertEqual(
            self.readdir_names("/docs"), [".", "..", "readme.md"]
        )
        self.assertEqual(self.operations.read("/docs/readme.md", 8, 10, 0), b"snapshot")
        self.assertEqual(self.operations.read("/alpha.txt", 4, 99, 0), b"")

    def test_missing_wrong_type_and_noncanonical_paths_map_to_errno(self):
        self.assert_errno(errno.ENOENT, self.operations.getattr, "/missing")
        self.assert_errno(errno.ENOTDIR, self.operations.readdir, "/alpha.txt", 0)
        self.assert_errno(errno.EISDIR, self.operations.read, "/docs", 1, 0, 0)
        self.assert_errno(errno.EINVAL, self.operations.getattr, "/../alpha.txt")
        self.assert_errno(errno.EINVAL, self.operations.getattr, "alpha.txt")

    def test_read_only_open_access_and_mutation_callbacks(self):
        self.assertEqual(self.operations.open("/alpha.txt", os.O_RDONLY), 0)
        self.assert_errno(errno.EROFS, self.operations.open, "/alpha.txt", os.O_WRONLY)
        self.assert_errno(
            errno.EROFS, self.operations.open, "/alpha.txt", os.O_RDONLY | os.O_TRUNC
        )
        self.assert_errno(errno.EROFS, self.operations.access, "/alpha.txt", os.W_OK)
        self.assert_errno(errno.EACCES, self.operations.access, "/alpha.txt", os.X_OK)
        self.assertEqual(self.operations.access("/docs", os.R_OK | os.X_OK), 0)

        mutators = (
            "chmod",
            "chown",
            "create",
            "fallocate",
            "link",
            "mkdir",
            "mknod",
            "removexattr",
            "rename",
            "rmdir",
            "setxattr",
            "symlink",
            "truncate",
            "unlink",
            "utimens",
            "write",
        )
        for name in mutators:
            with self.subTest(operation=name):
                self.assert_errno(errno.EROFS, getattr(self.operations, name), "/anything")

    def test_version_is_pinned_and_backend_retargeting_is_rejected(self):
        with self.assertRaises(ValueError):
            ArtifactFuseOperations(self.snapshot, version=8)
        self.snapshot.version = 8
        self.assert_errno(errno.ESTALE, self.operations.getattr, "/alpha.txt")

    def test_backend_size_change_is_detected_as_io_error(self):
        original_read = self.snapshot.read_file

        def changed(path):
            return original_read(path) + b"changed"

        self.snapshot.read_file = changed
        self.assert_errno(
            errno.EIO, self.operations.read, "/alpha.txt", 100, 0, 0
        )

    def test_real_served_snapshot_backend_is_mount_compatible(self):
        artifact_id = "11111111-2222-4333-8444-555555555555"
        artifact = Artifact(
            provider="owner",
            artifact_id=artifact_id,
            title="Mounted fixture",
            live_version="v-exact",
            kind="code",
        )
        fetched = FetchedArtifact(
            artifact=artifact,
            version=ArtifactVersion(
                provider="owner",
                artifact_id=artifact_id,
                version_id="v-exact",
            ),
            representations=(
                Representation(
                    label="served",
                    media_type="text/html",
                    data=b"<h1>served</h1>",
                ),
            ),
        )
        operations = ArtifactFuseOperations(
            ServedArtifactSnapshot(fetched), version="v-exact"
        )

        self.assertEqual(
            [row[0] for row in operations.readdir("/", 0)],
            [".", "..", ".artifactfs", "served.html"],
        )
        self.assertEqual(operations.read("/served.html", 6, 4, 0), b"served")
        self.assertEqual(
            [row[0] for row in operations.readdir("/.artifactfs", 0)],
            [".", "..", "metadata.json"],
        )

    def test_nfd_lookup_resolves_the_nfc_snapshot_entry(self):
        self.snapshot.entries["café.txt"] = FakeEntry(
            "café.txt", "file", b"unicode"
        )
        self.assertEqual(self.operations.read("/cafe\u0301.txt", 7, 0, 0), b"unicode")


class MountSnapshotTests(unittest.TestCase):
    def test_mount_uses_secure_options_and_never_requests_allow_other(self):
        calls = []
        sentinel = object()

        def fake_fuse(operations, mountpoint, **options):
            calls.append((operations, mountpoint, options))
            return sentinel

        result = mount_snapshot(
            FakeSnapshot(),
            "/mnt/artifact",
            version=7,
            foreground=False,
            debug=True,
            fuse_factory=fake_fuse,
        )

        self.assertIs(result, sentinel)
        operations, mountpoint, options = calls[0]
        self.assertIsInstance(operations, ArtifactFuseOperations)
        self.assertFalse(callable(operations))
        self.assertTrue(operations.use_ns)
        # Current mfusepy exposes no high-level wrapper for this FUSE 3 field;
        # defining it on the operations object would make mount setup fail.
        self.assertFalse(hasattr(operations, "copy_file_range"))
        self.assertEqual(operations.version, 7)
        self.assertEqual(mountpoint, "/mnt/artifact")
        self.assertEqual(
            options,
            {
                "foreground": False,
                "debug": True,
                "ro": True,
                "default_permissions": True,
                "use_ino": True,
            },
        )
        self.assertNotIn("allow_other", options)

    def test_missing_mfusepy_has_an_actionable_optional_dependency_error(self):
        missing = ModuleNotFoundError("No module named 'mfusepy'")
        with mock.patch(
            "artifactfs.mount.importlib.import_module", side_effect=missing
        ):
            with self.assertRaises(FuseUnavailableError) as caught:
                mount_snapshot(FakeSnapshot(), "/mnt/artifact", version=7)
        message = str(caught.exception)
        self.assertIn("optional", message)
        self.assertIn("mfusepy", message)
        self.assertIn("libfuse", message)
        self.assertIn("macFUSE", message)

    def test_invalid_mountpoint_fails_before_loading_optional_runtime(self):
        with mock.patch("artifactfs.mount.importlib.import_module") as importer:
            with self.assertRaises(ValueError):
                mount_snapshot(FakeSnapshot(), "", version=7)
        importer.assert_not_called()


if __name__ == "__main__":
    unittest.main()
