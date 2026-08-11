import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from artifactfs.cli import _write_new_private_file, main
from artifactfs.mount import FuseUnavailableError


class FakeSnapshot:
    version = "exact-v1"


class ArtifactFSCLITests(unittest.TestCase):
    def test_pack_and_mount_local_snapshot(self):
        mount_calls = []
        with tempfile.TemporaryDirectory() as parent:
            source = os.path.join(parent, "source")
            mountpoint = os.path.join(parent, "mount")
            output = os.path.join(parent, "snapshot.json")
            os.mkdir(source)
            os.mkdir(mountpoint)
            with open(os.path.join(source, "hello.txt"), "wb") as handle:
                handle.write(b"hello\n")

            with redirect_stdout(io.StringIO()):
                packed = main(["pack", source, output])
                mounted = main(
                    ["mount-snapshot", output, mountpoint],
                    mounter=lambda *args, **kwargs: mount_calls.append((args, kwargs)),
                )

            self.assertEqual(packed, 0)
            self.assertEqual(mounted, 0)
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
            snapshot = mount_calls[0][0][0]
            self.assertEqual(snapshot.read_file("hello.txt"), b"hello\n")
            self.assertEqual(mount_calls[0][1]["version"], snapshot.version)

    def test_pack_refuses_to_replace_existing_output(self):
        with tempfile.TemporaryDirectory() as parent:
            source = os.path.join(parent, "source")
            output = os.path.join(parent, "snapshot.json")
            os.mkdir(source)
            with open(output, "wb") as handle:
                handle.write(b"keep")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                status = main(["pack", source, output])
            self.assertEqual(status, 2)
            with open(output, "rb") as handle:
                self.assertEqual(handle.read(), b"keep")

    def test_mount_pins_fetched_version_and_secure_defaults(self):
        fetch_calls = []
        mount_calls = []
        expected_snapshot = FakeSnapshot()

        def fetch(reference, *, version=None):
            fetch_calls.append((reference, version))
            return expected_snapshot

        def mount(snapshot, mountpoint, **options):
            mount_calls.append((snapshot, mountpoint, options))

        with tempfile.TemporaryDirectory() as mountpoint:
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                status = main(
                    [
                        "mount-code",
                        "11111111-2222-4333-8444-555555555555",
                        mountpoint,
                        "--version",
                        "exact-v1",
                        "--debug",
                    ],
                    snapshot_fetcher=fetch,
                    mounter=mount,
                )

        self.assertEqual(status, 0)
        self.assertEqual(fetch_calls[0][1], "exact-v1")
        self.assertIs(mount_calls[0][0], expected_snapshot)
        self.assertEqual(
            mount_calls[0][2],
            {"version": "exact-v1", "foreground": True, "debug": True},
        )
        self.assertIn("served (read-only)", stdout.getvalue())
        self.assertIn("exact-v1", stdout.getvalue())

    def test_background_is_forwarded_without_enabling_writes(self):
        options = []
        with tempfile.TemporaryDirectory() as mountpoint:
            with redirect_stdout(io.StringIO()):
                status = main(
                    ["mount-code", "fixture", mountpoint, "--background"],
                    snapshot_fetcher=lambda *args, **kwargs: FakeSnapshot(),
                    mounter=lambda *args, **kwargs: options.append(kwargs),
                )
        self.assertEqual(status, 0)
        self.assertFalse(options[0]["foreground"])

    def test_rejects_nonempty_and_symlink_mountpoints_before_fetch(self):
        calls = []
        with tempfile.TemporaryDirectory() as parent:
            nonempty = os.path.join(parent, "nonempty")
            os.mkdir(nonempty)
            with open(os.path.join(nonempty, "keep"), "w", encoding="utf-8") as handle:
                handle.write("owned")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                status = main(
                    ["mount-code", "fixture", nonempty],
                    snapshot_fetcher=lambda *args, **kwargs: calls.append(True),
                )
            self.assertEqual(status, 2)
            self.assertEqual(calls, [])
            self.assertIn("empty", stderr.getvalue())

            target = os.path.join(parent, "target")
            link = os.path.join(parent, "link")
            os.mkdir(target)
            os.symlink(target, link)
            with redirect_stderr(io.StringIO()):
                status = main(
                    ["mount-code", "fixture", link],
                    snapshot_fetcher=lambda *args, **kwargs: calls.append(True),
                )
            self.assertEqual(status, 2)
            self.assertEqual(calls, [])

    def test_optional_runtime_failure_is_sanitized(self):
        with tempfile.TemporaryDirectory() as mountpoint:
            stderr = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                status = main(
                    ["mount-code", "fixture", mountpoint],
                    snapshot_fetcher=lambda *args, **kwargs: FakeSnapshot(),
                    mounter=lambda *args, **kwargs: (_ for _ in ()).throw(
                        FuseUnavailableError(
                            "missing https://user:secret@example.test/?token=abc"
                        )
                    ),
                )
        self.assertEqual(status, 2)
        self.assertNotIn("secret", stderr.getvalue())
        self.assertNotIn("token=abc", stderr.getvalue())
        self.assertIn("[REDACTED]", stderr.getvalue())

    def test_missing_runtime_fails_before_provider_fetch(self):
        fetch_calls = []
        mount_calls = []
        with tempfile.TemporaryDirectory() as mountpoint:
            with redirect_stderr(io.StringIO()):
                status = main(
                    ["mount-code", "fixture", mountpoint],
                    snapshot_fetcher=lambda *args, **kwargs: fetch_calls.append(True),
                    mounter=lambda *args, **kwargs: mount_calls.append(True),
                    runtime_loader=lambda: (_ for _ in ()).throw(
                        FuseUnavailableError("optional runtime missing")
                    ),
                )
        self.assertEqual(status, 2)
        self.assertEqual(fetch_calls, [])
        self.assertEqual(mount_calls, [])

    def test_failed_output_cleanup_never_unlinks_a_replacement(self):
        with tempfile.TemporaryDirectory() as parent:
            output = os.path.join(parent, "snapshot.json")
            moved = os.path.join(parent, "opened-original")

            def replace_then_fail(descriptor, data):
                del descriptor, data
                os.rename(output, moved)
                with open(output, "wb") as handle:
                    handle.write(b"replacement")
                raise OSError("simulated write failure")

            with mock.patch("artifactfs.cli.os.write", side_effect=replace_then_fail):
                with self.assertRaises(OSError):
                    _write_new_private_file(output, b"snapshot")

            with open(output, "rb") as handle:
                self.assertEqual(handle.read(), b"replacement")
            self.assertTrue(os.path.exists(moved))

    def test_mountpoint_replacement_during_fetch_is_rejected(self):
        mount_calls = []
        with tempfile.TemporaryDirectory() as parent:
            mountpoint = os.path.join(parent, "mount")
            old = os.path.join(parent, "old")
            os.mkdir(mountpoint)

            def replacing_fetch(*args, **kwargs):
                del args, kwargs
                os.rename(mountpoint, old)
                os.mkdir(mountpoint)
                return FakeSnapshot()

            stderr = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                status = main(
                    ["mount-code", "fixture", mountpoint],
                    snapshot_fetcher=replacing_fetch,
                    mounter=lambda *args, **kwargs: mount_calls.append((args, kwargs)),
                )

        self.assertEqual(status, 2)
        self.assertEqual(mount_calls, [])
        self.assertIn("changed", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
