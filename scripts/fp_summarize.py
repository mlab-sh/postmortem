#!/usr/bin/env python3
"""Summarize a postmortem JSON report for false-positive triage.

Given a report produced by `postmortem <path> --json -o report.json`, prints a
breakdown of findings by category and detail, plus a handful of evidence samples
so a human can eyeball whether they are real or noise. On a known-good repo
(algorithms, popular libraries) essentially every finding is a false positive,
so this doubles as a regression harness for the IOC/obfuscation heuristics.

Usage:
    fp_summarize.py REPORT.json [--label NAME] [--samples N] [--json-line]
"""
import argparse
import json
import sys
from collections import Counter, defaultdict


def load(path):
    with open(path) as fh:
        return json.load(fh)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("--label", default=None, help="repo name for the header")
    ap.add_argument("--samples", type=int, default=5, help="evidence samples per detail")
    ap.add_argument("--json-line", action="store_true",
                    help="emit one compact JSON summary line instead of the report")
    args = ap.parse_args()

    try:
        report = load(args.report)
    except (OSError, json.JSONDecodeError) as e:
        print(f"  !! could not read report: {e}", file=sys.stderr)
        return 2

    label = args.label or report.get("root", args.report)
    findings = report.get("findings", [])
    ecosystems = report.get("ecosystems", [])
    ndeps = len(report.get("dependencies", []))

    by_cat = Counter(f.get("category", "?") for f in findings)
    by_detail = Counter(f.get("detail", "?") for f in findings)
    samples = defaultdict(list)
    for f in findings:
        d = f.get("detail", "?")
        if len(samples[d]) < args.samples:
            ev = f.get("evidence")
            loc = f.get("location", "?")
            samples[d].append((ev, loc))

    if args.json_line:
        print(json.dumps({
            "label": label,
            "ecosystems": ecosystems,
            "dependencies": ndeps,
            "findings": len(findings),
            "by_category": dict(by_cat),
            "by_detail": dict(by_detail),
        }))
        return 0

    print(f"── {label}")
    print(f"   ecosystems: {', '.join(ecosystems) or '(none detected)'}   "
          f"deps: {ndeps}   findings: {len(findings)}")
    if not findings:
        print("   ✓ no findings — clean")
        return 0

    print(f"   by category: " + ", ".join(f"{k}={v}" for k, v in by_cat.most_common()))
    for detail, count in by_detail.most_common():
        print(f"   • [{count}] {detail}")
        for ev, loc in samples[detail]:
            evs = f"{ev!r} " if ev is not None else ""
            print(f"        {evs}@ {loc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
