#!/usr/bin/env bash
#
# ABI / API / storage-format compatibility check for TF-PSA-Crypto, runnable from
# the pixi env in this dir. Compares the upstream base (OLD) against the SPAKE2+
# branch (NEW): the SPAKE2+ work is purely additive, so it must report no
# backward-incompatibility.
#
# scripts/abi_check.py wraps abi-dumper + abi-compliance-checker, which parse ELF
# DWARF debug info. They are NOT on conda-forge and do NOT work on macOS (Mach-O),
# so the ABI/API comparison only runs on Linux. This task fetches those tools on
# first run and invokes the check; on non-Linux it explains and exits.
#
# Usage:  pixi run abi-check
# Override revisions: SPAKE2P_ABI_OLD / SPAKE2P_ABI_NEW.
#
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
cd "$REPO"

OLD="${SPAKE2P_ABI_OLD:-665b2368a}"
NEW="${SPAKE2P_ABI_NEW:-spake2p-matter-wip}"
TOOLS="$HERE/.tools"

if [ "$(uname)" != "Linux" ]; then
    cat >&2 <<EOF
[abi-check] ABI/API checks need abi-dumper + abi-compliance-checker, which parse
[abi-check] ELF DWARF debug info and do not work on $(uname) (Mach-O binaries).
[abi-check] Run this task on a Linux x86_64 runner (the pixi env is portable):
[abi-check]     cd checks && pixi run --environment default abi-check
[abi-check] It compares $OLD -> $NEW (override via SPAKE2P_ABI_OLD/NEW).
EOF
    exit 3
fi

# Fetch the ABI tools (not packaged on conda-forge) on first use.
export PATH="$TOOLS/abi-compliance-checker:$TOOLS/abi-dumper:$PATH"
if ! command -v abi-dumper >/dev/null; then
    echo "[abi-check] fetching abi-dumper + abi-compliance-checker (one-time) ..."
    git clone --depth 1 https://github.com/lvc/abi-dumper.git "$TOOLS/abi-dumper"
    git clone --depth 1 https://github.com/lvc/abi-compliance-checker.git "$TOOLS/abi-compliance-checker"
    ln -sf abi-dumper.pl "$TOOLS/abi-dumper/abi-dumper"
    ln -sf abi-compliance-checker.pl "$TOOLS/abi-compliance-checker/abi-compliance-checker"
    chmod +x "$TOOLS"/abi-dumper/abi-dumper.pl "$TOOLS"/abi-compliance-checker/abi-compliance-checker.pl
fi

echo "[abi-check] comparing $OLD -> $NEW (ABI + API + storage)"
exec python3 scripts/abi_check.py -b -o "$OLD" -n "$NEW" \
    --check-abi --check-api --check-storage
