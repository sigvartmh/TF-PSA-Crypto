#!/usr/bin/env bash
#
# Apply the prepared SPAKE2+ follow-up commit.
#
# The commit message (including the DCO Signed-off-by trailer) lives in
# commit/spake2p-followups.txt. This script stages exactly the files that
# belong to the follow-up work and records them as a single signed-off
# commit. Re-run safely: it refuses to run if there is nothing staged to
# commit.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

MSG_FILE="commit/spake2p-followups.txt"

if [ ! -f "$MSG_FILE" ]; then
    echo "error: commit message not found at $MSG_FILE" >&2
    exit 1
fi

# Files that make up the SPAKE2+ follow-up commit (#9370, #9378, #9381).
FILES=(
    core/psa_crypto.c
    drivers/builtin/include/mbedtls/private/spake2p.h
    drivers/builtin/src/psa_crypto_pake.c
    drivers/builtin/src/spake2p.c
    include/psa/crypto_config.h
    tests/suites/test_suite_psa_crypto_pake.data
    tests/suites/test_suite_psa_crypto_pake.function
    tests/suites/test_suite_spake2p.data
    tests/suites/test_suite_spake2p.function
    tests/data_files/spake2p_matter_p256_interop.txt
    docs/architecture/spake2p-matter-rfc9383.md
    ChangeLog.d/spake2p.txt
)

git add -- "${FILES[@]}"

if git diff --cached --quiet; then
    echo "Nothing staged to commit; working tree already up to date." >&2
    exit 0
fi

# The message file already carries the Signed-off-by trailer, so do not add
# another one with -s.
git commit -F "$MSG_FILE"

echo
echo "Committed SPAKE2+ follow-up work:"
git log -1 --stat --format='%H%n%an <%ae>%n%n%B'
