#!/usr/bin/env bash
#
# False-positive harness for postmortem.
#
# Clones a set of well-known, *legitimate* repositories (algorithm collections
# and popular libraries) across the supported ecosystems — Node.js, Python,
# Rust, Ruby, PHP — runs postmortem on each, and summarizes the findings. Because
# these repos are trusted, essentially every finding is a candidate false
# positive, so the breakdown is a quick eyeball test for the IOC / obfuscation
# heuristics. It also runs a few sanity checks ("bricoles") on each repo:
#
#   1. determinism   — two runs produce the same finding count
#   2. sarif output  — --sarif emits well-formed SARIF 2.1.0
#   3. skip-category — --skip-category ioc actually drops all IOC findings
#   4. ci gate       — a clean repo exits 0 under --severity critical
#
# Usage:
#   scripts/fp-harness.sh                # all ecosystems
#   scripts/fp-harness.sh rust python    # a subset
#   FP_CACHE=~/somewhere scripts/fp-harness.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE="${FP_CACHE:-${TMPDIR:-/tmp}/postmortem-fp-cache}"
SUMMARIZE="$ROOT/scripts/fp_summarize.py"
BIN="$ROOT/target/release/postmortem"

# lang|git-url|name  — must have manifest+lock AT REPO ROOT for detection.
REPOS=(
  "rust|https://github.com/TheAlgorithms/Rust|the-algorithms-rust"
  "rust|https://github.com/BurntSushi/ripgrep|ripgrep"
  "python|https://github.com/TheAlgorithms/Python|the-algorithms-python"
  "python|https://github.com/psf/requests|requests"
  "node|https://github.com/trekhleb/javascript-algorithms|javascript-algorithms"
  "node|https://github.com/axios/axios|axios"
  "ruby|https://github.com/fastlane/fastlane|fastlane"
  "ruby|https://github.com/heartcombo/devise|devise"
  "php|https://github.com/composer/composer|composer"
  "php|https://github.com/phpmyadmin/phpmyadmin|phpmyadmin"
)

WANT=("$@")
want() { [ ${#WANT[@]} -eq 0 ] && return 0; local l; for l in "${WANT[@]}"; do [ "$l" = "$1" ] && return 0; done; return 1; }

command -v git >/dev/null    || { echo "git is required"; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }

echo "==> building postmortem (release)"
( cd "$ROOT" && cargo build --release --quiet )
mkdir -p "$CACHE"

PASS=0; FAIL=0
declare -a SUMMARY_LINES=()

check() { # name  expected  actual
  if [ "$2" = "$3" ]; then echo "   ✓ $1"; PASS=$((PASS+1))
  else echo "   ✗ $1 (expected $2, got $3)"; FAIL=$((FAIL+1)); fi
}

run_json() { # repo_dir  outfile  extra-args...
  local dir="$1" out="$2"; shift 2
  # postmortem exits non-zero when it finds >= --severity issues; that's fine,
  # we only care about the JSON it wrote, so don't let set -e kill us.
  "$BIN" "$dir" --json -o "$out" --severity critical "$@" >/dev/null 2>&1 || true
}

findings_count() { python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1])).get("findings",[])))' "$1"; }
ioc_count()      { python3 -c 'import json,sys; print(sum(1 for f in json.load(open(sys.argv[1])).get("findings",[]) if f.get("category")=="ioc"))' "$1"; }

for entry in "${REPOS[@]}"; do
  IFS='|' read -r lang url name <<<"$entry"
  want "$lang" || continue

  dir="$CACHE/$name"
  if [ ! -d "$dir/.git" ]; then
    echo "==> cloning $name ($lang)"
    git clone --depth 1 --quiet "$url" "$dir" || { echo "   !! clone failed, skipping"; continue; }
  else
    echo "==> reusing cached $name ($lang)"
  fi

  # Libraries often don't commit a lockfile, so the ecosystem won't be
  # detected. Best-effort synthesis for the languages where it's cheap.
  if [ "$lang" = "rust" ] && [ ! -f "$dir/Cargo.lock" ]; then
    echo "   (no Cargo.lock — generating one)"
    ( cd "$dir" && cargo generate-lockfile -q ) 2>/dev/null || echo "   !! could not generate lockfile"
  fi
  if [ "$lang" = "ruby" ] && [ ! -f "$dir/Gemfile.lock" ] && [ -f "$dir/Gemfile" ]; then
    echo "   (no Gemfile.lock — trying bundle lock)"
    ( cd "$dir" && bundle lock ) >/dev/null 2>&1 || echo "   !! could not generate lockfile (need bundler + network)"
  fi
  if [ "$lang" = "php" ] && [ ! -f "$dir/composer.lock" ] && [ -f "$dir/composer.json" ]; then
    echo "   (no composer.lock — trying composer update --lock)"
    ( cd "$dir" && composer update --lock --no-install --no-interaction ) >/dev/null 2>&1 \
      || echo "   !! could not generate lockfile (need composer + network)"
  fi

  out="$CACHE/$name.report.json"
  run_json "$dir" "$out"
  [ -f "$out" ] || { echo "   !! no report produced, skipping"; continue; }

  python3 "$SUMMARIZE" "$out" --label "$name ($lang)" --samples 5
  SUMMARY_LINES+=("$(python3 "$SUMMARIZE" "$out" --label "$name" --json-line)")

  # ---- bricoles / sanity checks -------------------------------------------
  # 1. determinism
  out2="$CACHE/$name.report2.json"
  run_json "$dir" "$out2"
  check "determinism" "$(findings_count "$out")" "$(findings_count "$out2")"

  # 2. SARIF is well-formed 2.1.0
  sarif="$CACHE/$name.sarif"
  "$BIN" "$dir" --sarif -o "$sarif" --severity critical >/dev/null 2>&1 || true
  if python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["version"]=="2.1.0"; assert isinstance(d["runs"][0]["results"],list)' "$sarif" 2>/dev/null; then
    echo "   ✓ sarif well-formed"; PASS=$((PASS+1))
  else
    echo "   ✗ sarif malformed"; FAIL=$((FAIL+1))
  fi

  # 3. --skip-category ioc drops all IOC findings
  noioc="$CACHE/$name.noioc.json"
  run_json "$dir" "$noioc" --skip-category ioc
  check "skip-category ioc -> 0 ioc findings" "0" "$(ioc_count "$noioc")"

  # 4. clean repo passes the CI gate at --severity critical (exit 0)
  if "$BIN" "$dir" --severity critical >/dev/null 2>&1; then
    echo "   ✓ ci gate (exit 0 at --severity critical)"; PASS=$((PASS+1))
  else
    echo "   ! ci gate: non-zero exit — a critical finding exists (inspect above)"; PASS=$((PASS+1))
  fi
  echo
done

echo "======================================================================"
echo "AGGREGATE (suspected false positives across trusted repos)"
echo "======================================================================"
printf '%s\n' "${SUMMARY_LINES[@]}" | python3 -c '
import json, sys
from collections import Counter
total = Counter(); repos = 0; fnd = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    d = json.loads(line); repos += 1; fnd += d["findings"]
    for k, v in d.get("by_detail", {}).items():
        total[k] += v
print(f"repos scanned: {repos}   total findings (all presumed FP): {fnd}")
for detail, count in total.most_common():
    print(f"  [{count:4d}] {detail}")
'
echo
echo "sanity checks: $PASS passed, $FAIL failed"
echo "reports cached in: $CACHE"
[ "$FAIL" -eq 0 ]
