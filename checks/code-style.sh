#!/usr/bin/env bash
#
# C code-style check for TF-PSA-Crypto, runnable from the pixi env in this dir.
#
# framework/scripts/code_style.py hard-requires uncrustify 0.75.1, which is not on
# conda-forge. This script builds that exact version once (cached under
# checks/.tools/) and runs the check with it. Non-destructive by default (prints a
# diff; does not modify files). Pass -f to fix.
#
# Usage (inside `cd checks && pixi shell`, or via `pixi run code-style`):
#   pixi run code-style                 # files changed since the upstream base
#   pixi run code-style -- src/foo.c    # specific files
#   pixi run code-style -- -f           # fix in place
#
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
cd "$REPO"

UNCR="$HERE/.tools/uncrustify-0.75.1/uncrustify"

if ! "$UNCR" --version 2>/dev/null | grep -q '0\.75\.1'; then
    echo "[code-style] building uncrustify 0.75.1 (one-time; conda-forge has no 0.75.1) ..."
    rm -rf "$HERE/.tools/uncrustify-src" "$HERE/.tools/uncrustify-build"
    git clone --depth 1 --branch uncrustify-0.75.1 \
        https://github.com/uncrustify/uncrustify.git "$HERE/.tools/uncrustify-src"
    cmake -S "$HERE/.tools/uncrustify-src" -B "$HERE/.tools/uncrustify-build" \
        -DCMAKE_BUILD_TYPE=Release
    cmake --build "$HERE/.tools/uncrustify-build" -j
    mkdir -p "$HERE/.tools/uncrustify-0.75.1"
    cp "$HERE/.tools/uncrustify-build/uncrustify" "$UNCR"
fi
echo "[code-style] using $("$UNCR" --version)"

if [ "$#" -gt 0 ]; then
    # Explicit files (or extra flags like -f) passed through.
    exec python3 framework/scripts/code_style.py --uncrustify "$UNCR" "$@"
fi
# Default: the C files changed since the upstream base = the SPAKE2+ work.
# (Pass them explicitly rather than --since, which also enumerates the framework
# submodule and is brittle outside CI.)
base="${SPAKE2P_BASE:-665b2368a}"
mapfile -t FILES < <(git diff --name-only --diff-filter=d "$base" -- '*.c' '*.h' \
                     | while read -r f; do [ -f "$f" ] && echo "$f"; done)
if [ "${#FILES[@]}" -eq 0 ]; then
    echo "[code-style] no changed C/H files since $base"; exit 0
fi
echo "[code-style] checking ${#FILES[@]} C/H files changed since $base"
exec python3 framework/scripts/code_style.py --uncrustify "$UNCR" "${FILES[@]}"
