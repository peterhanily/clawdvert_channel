"""Streaming filesystem traversal with a hard entry budget."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator, Tuple


class FilesystemEntryLimitError(ValueError):
    """A local bundle exceeded its filesystem-entry budget."""


def iter_bounded_tree(
    root: Path, max_entries: int
) -> Iterator[Tuple[Path, bool]]:
    """Yield descendants without following symlinks or materializing a directory."""

    if max_entries <= 0:
        raise ValueError("filesystem entry limit must be positive")
    stack = [Path(root)]
    discovered = 0
    while stack:
        directory = stack.pop()
        with os.scandir(str(directory)) as entries:
            for entry in entries:
                discovered += 1
                if discovered > max_entries:
                    raise FilesystemEntryLimitError(
                        "bundle exceeds the %d filesystem-entry limit" % max_entries
                    )
                path = Path(entry.path)
                try:
                    is_directory = entry.is_dir(follow_symlinks=False)
                except OSError:
                    is_directory = False
                yield path, is_directory
                if is_directory:
                    stack.append(path)
