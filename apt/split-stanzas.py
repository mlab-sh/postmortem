#!/usr/bin/env python3
"""Split an `apt-ftparchive packages` dump into one committed stanza per .deb.

The apt index has to keep advertising every version ever published, but CI only
ever has the .deb files it just built - re-downloading the whole history to
re-hash it would be absurd. So each stanza is written to apt/stanzas/<arch>/ and
committed; the release job concatenates them back into a Packages index.

Reads the dump on stdin, writes the files, prints what it wrote.
"""

import os
import re
import sys

ARCH = re.compile(r"^Architecture: (\S+)$", re.M)
FILENAME = re.compile(r"^Filename: (\S+)$", re.M)


def main() -> int:
    dump = sys.stdin.read()
    written = 0

    for stanza in (s.strip() for s in dump.split("\n\n")):
        if not stanza:
            continue

        arch = ARCH.search(stanza)
        filename = FILENAME.search(stanza)
        if not arch or not filename:
            print(f"stanza without Architecture or Filename, refusing:\n{stanza}",
                  file=sys.stderr)
            return 1

        directory = os.path.join("apt", "stanzas", arch.group(1))
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, os.path.basename(filename.group(1)) + ".stanza")

        with open(path, "w", encoding="utf-8") as handle:
            handle.write(stanza + "\n")

        print(path)
        written += 1

    if not written:
        print("no stanza found in the dump", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
