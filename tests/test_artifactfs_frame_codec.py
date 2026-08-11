import base64
import os
import tempfile
import unittest

from artifactfs import snapshot_directory
from artifactfs import frame_codec


VERSION = "1741803761-9f3a"
SNAPSHOT_BYTES = (
    b'{"artifactfs":1,"files":['
    b'{"data":"AAEC/w==","path":"bin/data.bin"},'
    b'{"data":"aGVsbG8K","path":"hello.txt"}]}'
)


class ArtifactFSFrameCodecTests(unittest.TestCase):
    def test_structured_snapshot_round_trip(self):
        with tempfile.TemporaryDirectory() as root:
            os.mkdir(os.path.join(root, "docs"))
            with open(os.path.join(root, "docs", "readme.md"), "wb") as handle:
                handle.write(b"# mounted\n")
            snapshot = snapshot_directory(root)

        page = frame_codec.render_snapshot_page(snapshot)
        decoded = frame_codec.recover_snapshot_page(page, VERSION)

        self.assertEqual(decoded.version, snapshot.version)
        self.assertEqual(decoded.read_file("docs/readme.md"), b"# mounted\n")

    def test_exact_page_round_trip_is_deterministic(self):
        first = frame_codec.render_snapshot_bytes(SNAPSHOT_BYTES)
        second = frame_codec.render_snapshot_bytes(SNAPSHOT_BYTES)

        self.assertEqual(first, second)
        decoded = frame_codec.recover_snapshot_bytes(first, VERSION)
        self.assertEqual(decoded.snapshot_bytes, SNAPSHOT_BYTES)
        self.assertEqual(decoded.expected_page, first)
        self.assertEqual(len(decoded.sha256), 64)

    def test_arbitrary_prefix_is_not_treated_as_provider_runtime(self):
        page = frame_codec.render_snapshot_bytes(SNAPSHOT_BYTES)
        runtime = "<script>window.evil=1</script><p>authored prefix</p>"

        with self.assertRaisesRegex(
            frame_codec.FrameCodecError, "exact ArtifactFS-managed"
        ):
            frame_codec.recover_snapshot_bytes(runtime + page, VERSION)

        with self.assertRaisesRegex(
            frame_codec.FrameCodecError, "exact ArtifactFS-managed"
        ):
            frame_codec.recover_snapshot_bytes("é" + page, VERSION)

    def test_measured_head_insert_runtime_round_trip(self):
        page = frame_codec.render_snapshot_bytes(SNAPSHOT_BYTES)
        split = page.index("<head") + len("<head")
        runtime = (
            f'><!-- frame-runtime --><base href="/_f/{VERSION}/">'
            '<script>window.__FRAME_PREAMBLE={"capabilities":{}}</script>'
            '<!-- /frame-runtime --'
        )
        served = page[:split] + runtime + page[split:]

        decoded = frame_codec.recover_snapshot_bytes(served, VERSION)

        self.assertEqual(decoded.snapshot_bytes, SNAPSHOT_BYTES)

    def test_head_runtime_is_bound_to_requested_version(self):
        page = frame_codec.render_snapshot_bytes(SNAPSHOT_BYTES)
        split = page.index("<head") + len("<head")
        runtime = (
            '><!-- frame-runtime --><base href="/_f/different-version/">'
            '<script>window.__FRAME_PREAMBLE={}</script>'
            '<!-- /frame-runtime --'
        )

        with self.assertRaisesRegex(
            frame_codec.FrameCodecError, "exact ArtifactFS-managed"
        ):
            frame_codec.recover_snapshot_bytes(
                page[:split] + runtime + page[split:], VERSION
            )

    def test_duplicate_marker_in_runtime_fails_closed(self):
        page = frame_codec.render_snapshot_bytes(SNAPSHOT_BYTES)
        adversarial_runtime = frame_codec.BEGIN_MARKER + "<!-- frame-runtime -->"

        with self.assertRaisesRegex(frame_codec.FrameCodecError, "one ArtifactFS"):
            frame_codec.recover_snapshot_bytes(adversarial_runtime + page, VERSION)

    def test_duplicate_template_marker_fails_closed(self):
        page = frame_codec.render_snapshot_bytes(SNAPSHOT_BYTES)
        decoy = '<div id="%s"></div>' % frame_codec.TEMPLATE_ID

        with self.assertRaisesRegex(frame_codec.FrameCodecError, "one ArtifactFS"):
            frame_codec.recover_snapshot_bytes(decoy + page, VERSION)

    def test_digest_corruption_is_rejected(self):
        page = frame_codec.render_snapshot_bytes(SNAPSHOT_BYTES)
        digest_at = page.index('data-sha256="') + len('data-sha256="')
        replacement = "0" if page[digest_at] != "0" else "1"
        corrupt = page[:digest_at] + replacement + page[digest_at + 1 :]

        with self.assertRaisesRegex(frame_codec.FrameCodecError, "digest mismatch"):
            frame_codec.recover_snapshot_bytes(corrupt, VERSION)

    def test_payload_corruption_is_rejected(self):
        page = frame_codec.render_snapshot_bytes(SNAPSHOT_BYTES)
        payload_at = page.index('data-sha256="') + len('data-sha256="') + 64 + 2
        replacement = "A" if page[payload_at] != "A" else "B"
        corrupt = page[:payload_at] + replacement + page[payload_at + 1 :]

        with self.assertRaises(frame_codec.FrameCodecError):
            frame_codec.recover_snapshot_bytes(corrupt, VERSION)

    def test_arbitrary_and_lookalike_pages_are_rejected(self):
        with self.assertRaisesRegex(frame_codec.FrameCodecError, "begin marker"):
            frame_codec.recover_snapshot_bytes(
                "<!doctype html><p>an ordinary Code Artifact</p>", VERSION
            )

        page = frame_codec.render_snapshot_bytes(SNAPSHOT_BYTES)
        lookalike = page.replace(
            "<body>\n", "<body>\n<p>unmanaged authored content</p>", 1
        )
        with self.assertRaisesRegex(
            frame_codec.FrameCodecError, "exact ArtifactFS-managed"
        ):
            frame_codec.recover_snapshot_bytes(lookalike, VERSION)

    def test_file_bytes_never_become_markup(self):
        hostile = b'{"data":"</template><script>alert(1)</script>"}'

        page = frame_codec.render_snapshot_bytes(hostile)

        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertNotIn(hostile.decode("ascii"), page)
        self.assertEqual(
            frame_codec.recover_snapshot_bytes(page, VERSION).snapshot_bytes,
            hostile,
        )

    def test_malformed_base64_is_rejected(self):
        page = frame_codec.render_snapshot_bytes(SNAPSHOT_BYTES)
        payload_at = page.index('data-sha256="') + len('data-sha256="') + 64 + 2
        malformed = page[:payload_at] + "!" + page[payload_at + 1 :]

        with self.assertRaisesRegex(frame_codec.FrameCodecError, "canonical base64"):
            frame_codec.recover_snapshot_bytes(malformed, VERSION)

    def test_expansion_and_served_page_limits_are_enforced(self):
        page = frame_codec.render_snapshot_bytes(b"x" * 4096)
        expansion_limits = frame_codec.CodecLimits(
            max_snapshot_bytes=1024,
            max_compressed_bytes=frame_codec.DEFAULT_LIMITS.max_compressed_bytes,
            max_served_bytes=frame_codec.DEFAULT_LIMITS.max_served_bytes,
        )
        with self.assertRaisesRegex(frame_codec.FrameCodecError, "expanded snapshot"):
            frame_codec.recover_snapshot_bytes(
                page, VERSION, limits=expansion_limits
            )

        served_limits = frame_codec.CodecLimits(
            max_snapshot_bytes=4096,
            max_compressed_bytes=4096,
            max_served_bytes=64,
        )
        with self.assertRaisesRegex(frame_codec.FrameCodecError, "served page"):
            frame_codec.recover_snapshot_bytes(page, VERSION, limits=served_limits)

    def test_noncanonical_gzip_stream_is_rejected(self):
        page = frame_codec.render_snapshot_bytes(SNAPSHOT_BYTES)
        payload_at = page.index('data-sha256="') + len('data-sha256="') + 64 + 2
        payload_end = page.index("</template>", payload_at)
        payload = page[payload_at:payload_end]
        packed = bytearray(base64.b64decode(payload))
        # The gzip OS byte is informational, so this remains decompressible but
        # is not the single canonical representation emitted by this codec.
        packed[9] = 3
        replacement = base64.b64encode(packed).decode("ascii")
        noncanonical = page[:payload_at] + replacement + page[payload_end:]

        with self.assertRaisesRegex(frame_codec.FrameCodecError, "canonically compressed"):
            frame_codec.recover_snapshot_bytes(noncanonical, VERSION)


if __name__ == "__main__":
    unittest.main()
