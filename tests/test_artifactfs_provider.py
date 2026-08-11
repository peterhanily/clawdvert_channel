import json
import unittest

from artifact_bridge.models import (
    Artifact,
    ArtifactRef,
    ArtifactVersion,
    FetchedArtifact,
    Representation,
)
from artifactfs.provider import ServedArtifactSnapshot, fetch_owner_served_snapshot


SLUG = "11111111-2222-4333-8444-555555555555"


def fetched(*, data=b"<html>served</html>", provider="owner", kind="code"):
    artifact = Artifact(
        provider=provider,
        artifact_id=SLUG,
        title="Fixture",
        live_version="v-exact",
        kind=kind,
        metadata={"assetToken": "DO-NOT-EXPOSE"},
    )
    version = ArtifactVersion(
        provider=provider,
        artifact_id=SLUG,
        version_id="v-exact",
        is_live=True,
    )
    representation = Representation(
        label="served",
        media_type="text/html; charset=utf-8",
        data=data,
    )
    return FetchedArtifact(
        artifact=artifact,
        version=version,
        representations=(representation,),
        provenance={"retrieval": "owner OAuth", "assetToken": "DO-NOT-EXPOSE"},
    )


class ServedArtifactSnapshotTests(unittest.TestCase):
    def test_exposes_served_bytes_and_sanitized_metadata(self):
        snapshot = ServedArtifactSnapshot(fetched())

        self.assertEqual(snapshot.version, "v-exact")
        self.assertEqual(snapshot.artifact_id, SLUG)
        self.assertEqual(snapshot.read_file("served.html"), b"<html>served</html>")
        metadata = snapshot.read_file(".artifactfs/metadata.json")
        decoded = json.loads(metadata)
        self.assertEqual(decoded["representation"], "served")
        self.assertIn("not the artifact's authored source", decoded["warning"])
        self.assertNotIn(b"DO-NOT-EXPOSE", metadata)

        self.assertEqual(
            [entry.path for entry in snapshot.iterdir(".")],
            [".artifactfs", "served.html"],
        )
        self.assertEqual(
            [entry.path for entry in snapshot.iterdir(".artifactfs")],
            [".artifactfs/metadata.json"],
        )

    def test_is_immutable_and_rejects_unsafe_paths(self):
        snapshot = ServedArtifactSnapshot(fetched())
        self.assertEqual(snapshot.get(".").kind, "directory")
        self.assertNotEqual(snapshot.get("served.html").inode_id, 0)
        with self.assertRaises(FileNotFoundError):
            snapshot.get("../served.html")
        with self.assertRaises(FileNotFoundError):
            snapshot.get("/served.html")
        with self.assertRaises(IsADirectoryError):
            snapshot.read_file(".")
        with self.assertRaises(NotADirectoryError):
            tuple(snapshot.iterdir("served.html"))

    def test_rejects_non_owner_or_non_code_content(self):
        with self.assertRaisesRegex(Exception, "owner-frame adapter"):
            ServedArtifactSnapshot(fetched(provider="compliance"))
        with self.assertRaisesRegex(Exception, "owner-frame adapter"):
            ServedArtifactSnapshot(fetched(kind="standard"))

    def test_rejects_noncanonical_identity_and_terminal_control_version(self):
        invalid_id = fetched()
        object.__setattr__(invalid_id.artifact, "artifact_id", "not-a-uuid")
        with self.assertRaisesRegex(Exception, "canonical Artifact UUID"):
            ServedArtifactSnapshot(invalid_id)

        invalid_version = fetched()
        object.__setattr__(invalid_version.version, "version_id", "bad\nversion")
        with self.assertRaisesRegex(Exception, "exact version ID"):
            ServedArtifactSnapshot(invalid_version)

    def test_inode_identity_is_version_and_path_stable(self):
        first = ServedArtifactSnapshot(fetched())
        second = ServedArtifactSnapshot(fetched())
        self.assertEqual(
            first.get("served.html").inode_id,
            second.get("served.html").inode_id,
        )
        self.assertNotEqual(
            first.get("served.html").inode_id,
            first.get(".artifactfs/metadata.json").inode_id,
        )


class FakeOwnerAdapter:
    name = "owner"

    def __init__(self):
        self.closed = False
        self.ref = None
        self.version = None

    def fetch(self, ref, version):
        self.ref = ref
        self.version = version
        return fetched()


class FetchServedSnapshotTests(unittest.TestCase):
    def test_uses_exact_requested_version_without_closing_caller_adapter(self):
        adapter = FakeOwnerAdapter()
        snapshot = fetch_owner_served_snapshot(
            ArtifactRef(provider="owner", artifact_id=SLUG, kind="code"),
            version="v-exact",
            adapter=adapter,
        )

        self.assertEqual(snapshot.version, "v-exact")
        self.assertEqual(adapter.version, "v-exact")
        self.assertFalse(adapter.closed)


if __name__ == "__main__":
    unittest.main()
