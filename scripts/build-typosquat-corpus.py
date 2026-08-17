#!/usr/bin/env python3
"""Rebuild the offline typosquat corpora in `src/data/`.

One-off maintenance script — postmortem itself never runs it, and never fetches
these lists at scan time. The corpora are compiled into the binary so the
typosquat check stays fully offline and deterministic.

Source: packages.ecosyste.ms, which exposes a downloads-ranked package list for
every registry we cover behind one API. Paced at ~1 request/second because it is
a free public service.

    python3 scripts/build-typosquat-corpus.py

Each list is a UNION with whatever is already on disk: the original curated npm
entries include real squat targets (bcrypt, electron, cypress, ...) that sit
outside the ranked window, and dropping them would lose detections.

Depth is a false-positive control as much as a coverage one. Every entry is a
potential target, but it is also a name recognised as *itself*: `mysql2` (npm
rank 2634) and `random-bytes` (rank 4486) are legitimate packages that a
2000-entry list flagged as near-misses. npm therefore goes deeper than the rest.
"""
import json, os, subprocess, sys, time

DATA = os.path.join(os.path.dirname(__file__), "..", "src", "data")

# (registry, output file, how many names to keep)
TARGETS = [
    ("npmjs.org", "npm-popular.txt", 5000),
    ("pypi.org", "pypi-popular.txt", 2000),
    ("crates.io", "crates-popular.txt", 1200),
    ("rubygems.org", "rubygems-popular.txt", 1200),
    ("packagist.org", "packagist-popular.txt", 1200),
]

UA = "postmortem-corpus-builder (one-off offline typosquat corpus)"

HEADER = """# {title}
#
# The {n} most-downloaded packages on {registry}, plus any curated entries that
# predate this list. Source: packages.ecosyste.ms (downloads, descending),
# fetched {date}. Order is popularity rank, most-downloaded first.
#
# Used only for OFFLINE typosquat proximity: a dependency one edit / one
# transposition / one punctuation variant away from a name in here is flagged.
# The list therefore needs *reach* more than precision — a squat usually targets
# something in the top few thousand, and missing an entry only costs a detection.
# Rebuild with scripts/build-typosquat-corpus.py.
"""


def fetch(url):
    for attempt in range(6):
        r = subprocess.run(
            ["curl", "-sS", "--max-time", "60", "--retry", "2", "-H", f"User-Agent: {UA}", url],
            capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            try:
                return json.loads(r.stdout)
            except json.JSONDecodeError:
                pass
        time.sleep(3 * (attempt + 1))
    raise SystemExit(f"failed to fetch {url}")


def top(registry, want):
    out, page = [], 1
    while len(out) < want:
        batch = fetch(f"https://packages.ecosyste.ms/api/v1/registries/{registry}"
                      f"/packages?sort=downloads&order=desc&per_page=100&page={page}")
        if not batch:
            break
        out.extend(p["name"] for p in batch if p.get("name"))
        page += 1
        time.sleep(1.0)
    return out[:want]


def existing(path):
    if not os.path.exists(path):
        return []
    return [l.strip() for l in open(path) if l.strip() and not l.startswith("#")]


def main():
    date = time.strftime("%Y-%m-%d")
    for registry, filename, want in TARGETS:
        path = os.path.join(DATA, filename)
        names = top(registry, want)
        # Keep curated entries the ranked list does not include.
        keep = [n for n in existing(path) if n not in set(names)]
        names += keep
        title = f"Popular {registry} packages"
        open(path, "w").write(
            HEADER.format(title=title, n=want, registry=registry, date=date)
            + "\n".join(names) + "\n")
        print(f"{filename}: {len(names)} ({len(keep)} carried over)", file=sys.stderr)


if __name__ == "__main__":
    main()
