"""Expand project SQL*Plus @@ includes for a session fed through stdin."""

from pathlib import Path
import sys


def expand(path):
    with path.open(encoding="utf-8") as source:
        for line in source:
            if line.startswith("@@"):
                yield from expand(path.parent / line[2:].strip())
            else:
                yield line


if __name__ == "__main__":
    for argument in sys.argv[1:]:
        sys.stdout.writelines(expand(Path(argument)))
        print()
