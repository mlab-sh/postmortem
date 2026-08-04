#!/usr/bin/env bash
# Generate a full set of postmortem outputs (terminal / json / sarif / md) across
# scan, tree, and the system backends (Homebrew on the host + pacman in the Arch
# container + apt in the Ubuntu container), so every format can be eyeballed for
# validity in one place.
#
# Everything lands in tests/system/reports/ (gitignored). Re-run any time.
#
#   bash tests/system/run.sh
#
set -uo pipefail
cd "$(dirname "$0")/../.."          # repo root
OUT="tests/system/reports"
rm -rf "$OUT"; mkdir -p "$OUT/host" "$OUT/arch"
PM_HOST="./target/release/postmortem"

log()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
# Run a command, tee its output to a file, and validate JSON files.
capture() { # capture <outfile> <cmd...>
  local f="$1"; shift
  # JSON goes to stdout; keep stderr (banners/progress) in a sidecar so it never
  # corrupts the machine format. Text outputs merge both for a full picture.
  if [[ "$f" == *.json ]]; then
    "$@" > "$OUT/$f" 2> "$OUT/$f.err"
  else
    "$@" > "$OUT/$f" 2>&1
  fi
  local rc=$?
  if [[ "$f" == *.json ]]; then
    if python3 -c "import json,sys; json.load(open('$OUT/$f'))" 2>/dev/null; then
      echo "  ok   $f (valid JSON, exit $rc)"
    else
      echo "  FAIL $f (INVALID JSON, exit $rc)"
    fi
  else
    echo "  ok   $f (exit $rc, $(wc -l < "$OUT/$f") lines)"
  fi
}

log "Building host binary"
cargo build --release 2>&1 | tail -1

log "scan (all formats, over the fixtures)"
for fx in malicious-node malicious-python malicious-rust clean-node; do
  capture "host/scan-$fx.txt"   "$PM_HOST" scan "tests/fixtures/$fx" --no-progress
  capture "host/scan-$fx.json"  "$PM_HOST" scan "tests/fixtures/$fx" --json -o -
  capture "host/scan-$fx.sarif" "$PM_HOST" scan "tests/fixtures/$fx" --sarif -o -
done

log "tree (offline + json)"
capture "host/tree-node.txt"  "$PM_HOST" tree tests/fixtures/malicious-node --no-progress
capture "host/tree-node.json" "$PM_HOST" tree tests/fixtures/malicious-node --json -o -

log "system (Homebrew backend, host)"
capture "host/system.txt"       "$PM_HOST" system --no-progress
capture "host/system-repos.txt" "$PM_HOST" system --repos --no-progress
capture "host/system.json"      "$PM_HOST" system --json --no-progress

# --- Arch container: build a Linux binary, run the pacman backend there --------
log "Building Linux binary for the Arch container (rust container)"
if container run --rm -v "$PWD:/src" -w /src docker.io/library/rust:latest \
     cargo build --release --target-dir /src/target-linux >/dev/null 2>&1; then
  container start postmortem-arch >/dev/null 2>&1
  # `container cp` needs an absolute source and drops the exec bit.
  container cp "$PWD/target-linux/release/postmortem" postmortem-arch:/usr/bin/pm 2>/dev/null
  container exec postmortem-arch chmod +x /usr/bin/pm 2>/dev/null
  log "system (pacman backend, Arch container)"
  capture "arch/pacman-system.txt"   container exec postmortem-arch /usr/bin/pm system --no-progress
  capture "arch/pacman-repos.txt"    container exec postmortem-arch /usr/bin/pm system --repos --no-progress
  capture "arch/pacman-system.json"  container exec postmortem-arch /usr/bin/pm system --json --no-progress
  capture "arch/pacman-online.txt"   container exec postmortem-arch /usr/bin/pm system --online --no-progress
  # Ubuntu container: same Linux binary, apt backend.
  mkdir -p "$OUT/ubuntu"
  container start postmortem-ubuntu >/dev/null 2>&1
  container cp "$PWD/target-linux/release/postmortem" postmortem-ubuntu:/usr/bin/pm 2>/dev/null
  container exec postmortem-ubuntu chmod +x /usr/bin/pm 2>/dev/null
  log "system (apt backend, Ubuntu container)"
  capture "ubuntu/apt-system.txt"  container exec postmortem-ubuntu /usr/bin/pm system --no-progress
  capture "ubuntu/apt-repos.txt"   container exec postmortem-ubuntu /usr/bin/pm system --repos --no-progress
  capture "ubuntu/apt-system.json" container exec postmortem-ubuntu /usr/bin/pm system --json --no-progress
  # Fedora container: same Linux binary, dnf/rpm backend.
  mkdir -p "$OUT/fedora"
  container start postmortem-fedora >/dev/null 2>&1
  container cp "$PWD/target-linux/release/postmortem" postmortem-fedora:/usr/bin/pm 2>/dev/null
  container exec postmortem-fedora chmod +x /usr/bin/pm 2>/dev/null
  log "system (dnf backend, Fedora container)"
  capture "fedora/dnf-system.txt"  container exec postmortem-fedora /usr/bin/pm system --no-progress
  capture "fedora/dnf-repos.txt"   container exec postmortem-fedora /usr/bin/pm system --repos --no-progress
  capture "fedora/dnf-system.json" container exec postmortem-fedora /usr/bin/pm system --json --no-progress
  # Nix container: minimal userland (no FHS glibc loader), so it needs a STATIC
  # musl binary rather than the glibc one used for the others.
  mkdir -p "$OUT/nix"
  if container run --rm -v "$PWD:/src" -w /src docker.io/library/rust:latest bash -c \
       'rustup target add aarch64-unknown-linux-musl >/dev/null 2>&1 && \
        apt-get update >/dev/null 2>&1 && apt-get install -y musl-tools musl-dev >/dev/null 2>&1 && \
        cargo build --release --target aarch64-unknown-linux-musl --target-dir /src/target-musl' \
       >/dev/null 2>&1; then
    container start postmortem-nix >/dev/null 2>&1
    container cp "$PWD/target-musl/aarch64-unknown-linux-musl/release/postmortem" postmortem-nix:/usr/bin/pm 2>/dev/null
    container exec postmortem-nix chmod +x /usr/bin/pm 2>/dev/null
    log "system (nix backend, Nix container)"
    capture "nix/nix-system.txt"  container exec postmortem-nix /usr/bin/pm system --no-progress
    capture "nix/nix-repos.txt"   container exec postmortem-nix /usr/bin/pm system --repos --no-progress
    capture "nix/nix-system.json" container exec postmortem-nix /usr/bin/pm system --json --no-progress
    # Alpine container: musl-native, reuse the same static binary, apk backend.
    mkdir -p "$OUT/alpine"
    container start postmortem-alpine >/dev/null 2>&1
    container cp "$PWD/target-musl/aarch64-unknown-linux-musl/release/postmortem" postmortem-alpine:/usr/bin/pm 2>/dev/null
    container exec postmortem-alpine chmod +x /usr/bin/pm 2>/dev/null
    log "system (apk backend, Alpine container)"
    capture "alpine/apk-system.txt"  container exec postmortem-alpine /usr/bin/pm system --no-progress
    capture "alpine/apk-repos.txt"   container exec postmortem-alpine /usr/bin/pm system --repos --no-progress
    capture "alpine/apk-system.json" container exec postmortem-alpine /usr/bin/pm system --json --no-progress
  else
    echo "  SKIP nix/alpine musl build failed" | tee "$OUT/nix/BUILD-FAILED.txt"
  fi
else
  echo "  SKIP Linux build failed (network?) - re-run to retry" | tee "$OUT/arch/BUILD-FAILED.txt"
fi

log "Done. Reports in $OUT/"
find "$OUT" -type f | sort
