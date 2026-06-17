#!/usr/bin/env bash
#
# split_spake2p_prs.sh — re-cut the SPAKE2+ work on `spake2p-matter-wip` into
# one self-contained, CI-passing branch per upstream Mbed-TLS issue
# (#9343–#9381), ready to open as individual PRs against TF-PSA-Crypto.
#
# Why this exists
# ---------------
# The work was developed *horizontally* (one commit per architecture layer:
# engine, driver, core, public API, tests, docs) while the upstream issues are
# *vertical* feature slices. This script maps the existing commits onto the
# per-issue PR units defined in review.md / Presentation.md, builds each unit on
# top of the clean upstream base, and runs the SPAKE2+ CI gate so we never open a
# PR that fails CI.
#
# Issues are combined where the code was co-developed, so every unit assembles
# from whole commits or whole files - no hunk-level slicing. Assembly modes:
#   commits  : cherry-pick whole commits that map to the unit (PR-A, PR-B, PR-C).
#   combine  : cherry-pick a commit that bundles several issues, drop the whole
#              scaffolding files, and re-commit as one unit (PR-E).
#   cleanup  : pull the authored cleanup files from $SOURCE_BRANCH and commit them
#              on top of the stack (PR-G); requires those edits to be committed on
#              $SOURCE_BRANCH first.
#   pending  : reported as BLOCKED, never silently mis-assembled.
#
set -euo pipefail

# Requires bash >= 4 (associative arrays), like tests/scripts/all.sh. macOS ships
# bash 3.2; re-exec under a newer bash if one is on PATH, else fail clearly.
if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
    for _b in /opt/homebrew/bin/bash /usr/local/bin/bash "$(command -v bash || true)"; do
        if [ -x "$_b" ] && [ "$("$_b" -c 'echo ${BASH_VERSINFO[0]}')" -ge 4 ]; then
            exec "$_b" "$0" "$@"
        fi
    done
    echo "error: this script needs bash >= 4 (found ${BASH_VERSION}). On macOS: 'brew install bash'." >&2
    exit 1
fi

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Clean upstream base: the commit immediately before the SPAKE2+ series.
BASE="${SPAKE2P_BASE:-665b2368a}"

# Source branch holding the full (horizontal) SPAKE2+ history.
SOURCE_BRANCH="${SPAKE2P_SOURCE:-spake2p-matter-wip}"

# Prefix for the generated per-issue branches.
BRANCH_PREFIX="${SPAKE2P_BRANCH_PREFIX:-pr/spake2p}"

# CI gate: replicates the SPAKE2+ all.sh component (TEST_HOOKS + ASan build +
# ctest -R 'spake2p|psa_crypto_pake') directly, so its cleanup never touches our
# untracked artifacts. Upstream CI runs the same set via this all.sh component.
CI_COMPONENT="${SPAKE2P_CI_COMPONENT:-component_tf_psa_crypto_test_spake2p_hooks}"

# Compiler for the ASan build. The default cc on macOS (a nix/CLT clang wrapper)
# can lack <sanitizer/asan_interface.h>; Apple's clang ships it. Override with
# SPAKE2P_CI_CC=<path>. Empty means "use the project default".
CI_CC="${SPAKE2P_CI_CC:-}"
if [ -z "$CI_CC" ] && [ "$(uname)" = "Darwin" ] && [ -x /usr/bin/clang ]; then
    CI_CC=/usr/bin/clang
fi

DRY_RUN=0
FORCE=0
NO_CI=0

# --------------------------------------------------------------------------- #
# PR unit definitions
# --------------------------------------------------------------------------- #
# Format per unit (parallel arrays keyed by the unit id):
#   PR_ISSUES   : issues the unit closes (for the commit trailer / summary)
#   PR_MODE     : commits | combine | cleanup | pending
#   PR_SOURCE   : commit hashes (commits/combine modes) OR file list (cleanup mode)
#   PR_DESC     : human description
#   PR_CIGATE   : keymat | protocol - which test scope must pass
#
# These units form a STACK, not independent branches: PR-C (protocol) needs the
# key types from PR-A and psa_pake_set_context() from PR-B, so each unit is built
# on top of the previous unit's tip (the first builds on $BASE). This mirrors the
# original linear history, so the cherry-picks replay cleanly. When you open the
# PRs, set each PR's GitHub base to the PREVIOUS unit's branch, not main.
#
# STACK_ORDER follows the original commit history where units overlap (B's
# set_context commits precede A's import commit upstream), guaranteeing conflict-
# free replay. UNITS is the display order for the summary table.
# #9343 (key import/export) is folded into PR-C: its config-validation registration
# lives in the "Wire up build configuration" commit (also PR-C), so it is not
# independently buildable. Combining is fine (user-approved), so PR-C closes it too.
UNITS=(B C E G)
STACK_ORDER=(B C E G)

declare -A PR_ISSUES PR_MODE PR_SOURCE PR_DESC PR_CIGATE PR_BRANCH

# PR-B — psa_pake_set_context() (#9344). Small PSA API addition; first on the stack.
PR_ISSUES[B]="9344"
PR_MODE[B]="commits"
PR_SOURCE[B]="11b9e7b5e cfba54498"
PR_DESC[B]="psa_pake_set_context() for SPAKE2+"
PR_CIGATE[B]="protocol"

# PR-C — base SPAKE2+ protocol, engine+driver+core+API+tests+docs.
# Closes the seven protocol-step issues as ordered commits inside one CI boundary.
# The engine commit (9c823ae68) also carries the CMAC paths, so #9377 lands here
# too (HMAC and CMAC were co-developed in one commit; no hunk-slicing).
PR_ISSUES[C]="9343 9347 9349 9352 9355 9359 9367 9370 9377"
PR_MODE[C]="commits"
# 23b74e43c (key import/export, #9343) leads: it is not buildable without the
# build-config commit that follows it, so it ships inside this PR.
PR_SOURCE[C]="23b74e43c 4bd6ed15a 093aded02 9c823ae68 05d7b13f8 cf0e63f00 7da6586b2 4b7c628e1 96291a644 76a0a8427"
PR_DESC[C]="SPAKE2+ key material + base HMAC/CMAC protocol through the PSA PAKE API"
PR_CIGATE[C]="protocol"

# PR-E — Matter profile (#9378) + registration (#9381), combined. Both live in the
# single follow-up WiP commit (dad836d16), which also carries the get_shared_key
# confirmation-gate hardening and the dev scaffolding. The 'combine' mode cherry-
# picks that commit, then removes the scaffolding files (whole files, not hunks)
# before re-committing. No manual slicing required.
PR_ISSUES[E]="9378 9381"
PR_MODE[E]="combine"
# The Matter/registration work spans the WiP commit (dad836d16) and its follow-up
# commit (1b7009c27); 'combine' cherry-picks both, then drops the scaffolding.
PR_SOURCE[E]="dad836d16 1b7009c27"
PR_DESC[E]="Matter (CHIP) SPAKE2+ P-256 profile + registration"
PR_CIGATE[E]="protocol"

# Whole files that must never reach upstream (dropped by the 'combine' mode and by
# PR-G). See review.md A1.
SCAFFOLDING=(CLAUDE.md apply_commit.sh commit/spake2p-followups.txt commit)

# PR-G — final wiring/cleanup: the authored cleanup that is not part of any feature
# commit (rewritten matter-rfc9383.md, curve-gating, .gitignore, ChangeLog split,
# Matter-minimal CI component). These edits live in the working tree / source branch
# rather than in a cherry-pickable feature commit, so this unit pulls the named
# files from $SOURCE_BRANCH onto the PR-E tip. Commit your cleanup on $SOURCE_BRANCH
# first; until then PR-G reports BLOCKED.
PR_ISSUES[G]=""
PR_MODE[G]="cleanup"
PR_SOURCE[G]="docs/architecture/spake2p-matter-rfc9383.md docs/architecture/spake2p-implementation.md docs/spake2p-accelerator-integration.md drivers/builtin/src/spake2p.c .gitignore"
PR_DESC[G]="Final wiring + cleanup (docs, curve-gating, .gitignore)"
PR_CIGATE[G]="protocol"

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

log()  { printf '\033[1;34m[split]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m  %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; }

run() {
    # Echo + execute, unless dry-run (then just echo).
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    + %s\n' "$*"
    else
        "$@"
    fi
}

usage() {
    cat <<EOF
Usage: scripts/split_spake2p_prs.sh [options]

Re-cuts the SPAKE2+ history into one CI-gated branch per upstream issue.

Options:
  -n, --dry-run     Print planned actions; create no branches, run no CI.
  -f, --force       Overwrite existing pr/spake2p-* branches.
      --no-ci       Build/assemble branches but skip the CI gate.
  -h, --help        This help.

Environment overrides:
  SPAKE2P_BASE (=$BASE), SPAKE2P_SOURCE (=$SOURCE_BRANCH),
  SPAKE2P_CI_COMPONENT (=$CI_COMPONENT).
EOF
}

require_clean_tree() {
    if ! git diff --quiet || ! git diff --cached --quiet; then
        err "working tree is dirty. Commit/stash changes before splitting."
        exit 1
    fi
    if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
        err "index not clean."
        exit 1
    fi
}

verify_preconditions() {
    git rev-parse --verify "$BASE^{commit}" >/dev/null 2>&1 \
        || { err "base commit '$BASE' not found (set SPAKE2P_BASE)."; exit 1; }
    git rev-parse --verify "$SOURCE_BRANCH" >/dev/null 2>&1 \
        || { err "source branch '$SOURCE_BRANCH' not found (set SPAKE2P_SOURCE)."; exit 1; }
    log "base=$BASE  source=$SOURCE_BRANCH  ci_component=$CI_COMPONENT"
}

# Run the CI gate for a unit. Returns 0 on pass, non-zero on fail.
ci_gate() {
    local unit="$1" scope="${PR_CIGATE[$1]}"
    if [ "$NO_CI" -eq 1 ]; then
        log "  CI skipped (--no-ci) for PR-$unit"
        return 0
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '    + ci_gate PR-%s scope=%s\n' "$unit" "$scope"
        return 0
    fi
    log "  CI gate (scope=$scope) for PR-$unit ..."
    local jobs; jobs="$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)"
    local rc=0 hooks=0 filter
    local cmake_args=()
    # ASan is opt-in (SPAKE2P_CI_ASAN=1). The macOS ASan runtime hangs in the
    # leak detector at exit and ctest overrides ASAN_OPTIONS, so the default gate
    # is a normal build + ctest, which runs the identical suites reliably. On
    # Linux/upstream CI set SPAKE2P_CI_ASAN=1 (and SPAKE2P_CI_CC if needed) to get
    # the ASan build matching component_tf_psa_crypto_test_spake2p_hooks.
    if [ -n "${SPAKE2P_CI_ASAN:-}" ]; then
        cmake_args+=(-DCMAKE_BUILD_TYPE:String=Asan)
        [ -n "$CI_CC" ] && cmake_args+=(-DCMAKE_C_COMPILER="$CI_CC")
        export ASAN_OPTIONS="detect_leaks=0${ASAN_OPTIONS:+,$ASAN_OPTIONS}"
    fi
    case "$scope" in
        keymat)   filter='psa_crypto-suite' ;;                 # key import/export tests
        protocol) filter='spake2p|psa_crypto_pake'; hooks=1 ;; # engine + PSA PAKE suites
        *) err "unknown CI scope '$scope'"; return 2 ;;
    esac
    [ "$hooks" -eq 1 ] && scripts/config.py set MBEDTLS_TEST_HOOKS
    rm -rf build-ci
    if ! cmake -S . -B build-ci "${cmake_args[@]}" >/tmp/spake2p-ci-cfg.log 2>&1; then
        warn "  configure failed:"; tail -12 /tmp/spake2p-ci-cfg.log >&2; rc=1
    elif ! make -C build-ci -j"$jobs" >build-ci/build.log 2>&1; then
        warn "  build failed:"; tail -15 build-ci/build.log >&2; rc=1
    else
        # --timeout guards against any runtime hang; a stuck test fails the gate
        # rather than blocking the whole split.
        ( cd build-ci && ctest -R "$filter" --timeout 300 --output-on-failure ) || rc=$?
    fi
    [ "$hooks" -eq 1 ] && git checkout -- .   # undo TEST_HOOKS, keep the tree clean
    return $rc
}

# Assemble one unit onto the given base ref. Sets globals ASM_STATUS (OK/SKIP/
# BLOCKED/ERROR) and ASM_BRANCH; always returns 0.
assemble_unit() {
    local unit="$1" base_ref="$2"
    local mode="${PR_MODE[$1]}" branch="${BRANCH_PREFIX}-${PR_ISSUES[$1]:-cleanup}"
    branch="${branch// /-}"

    log "PR-$unit  (${PR_DESC[$unit]})  -> $branch"
    log "  closes: ${PR_ISSUES[$unit]:-<none, cleanup>}   mode: $mode   stacked on: $base_ref"

    if git rev-parse --verify "$branch" >/dev/null 2>&1; then
        if [ "$FORCE" -eq 1 ]; then
            run git branch -D "$branch"
        else
            warn "  branch $branch exists; use --force to overwrite. Skipping."
            ASM_STATUS=SKIP; return 0
        fi
    fi

    run git checkout -q -B "$branch" "$base_ref"

    case "$mode" in
        commits)
            local c
            for c in ${PR_SOURCE[$unit]}; do
                run git cherry-pick -x "$c"
            done
            ;;
        combine)
            # Cherry-pick the commit(s) that bundle several issues, drop the whole
            # scaffolding files, and re-commit as one combined unit. File-level
            # only: no hunk-slicing.
            local c f
            for c in ${PR_SOURCE[$unit]}; do
                run git cherry-pick -n "$c"
            done
            for f in "${SCAFFOLDING[@]}"; do
                [ -e "$f" ] && run git rm -rf --quiet --ignore-unmatch -- "$f"
            done
            run git commit -q -m "SPAKE2+: Matter profile and registration

Combined follow-up: Matter (CHIP) P-256 key schedule and SPAKE2+
registration via psa_key_derivation_output_key().

Closes: #9378
Closes: #9381"
            ;;
        cleanup)
            # Pull the named authored-cleanup files from $SOURCE_BRANCH onto this
            # tip and commit. Requires the cleanup to be committed on $SOURCE_BRANCH.
            local files="${PR_SOURCE[$unit]}" missing=0 ff
            for ff in $files; do
                git cat-file -e "$SOURCE_BRANCH:$ff" 2>/dev/null || { missing=1; warn "  $ff not committed on $SOURCE_BRANCH"; }
            done
            if [ "$missing" -eq 1 ]; then
                warn "  cleanup files not yet committed on $SOURCE_BRANCH -> BLOCKED."
                ASM_STATUS=BLOCKED; return 0
            fi
            # shellcheck disable=SC2086
            run git checkout "$SOURCE_BRANCH" -- $files
            for f in "${SCAFFOLDING[@]}"; do
                [ -e "$f" ] && run git rm -rf --quiet --ignore-unmatch -- "$f"
            done
            run git commit -q -m "SPAKE2+: docs, toggles and cleanup

Rewrite docs/architecture/spake2p-matter-rfc9383.md to the real
TF-PSA-Crypto layout, curve-gate the per-curve M/N tables, ignore
out-of-tree build directories, and remove development scaffolding."
            ;;
        pending)
            warn "  unit not sliceable from current commits; see notes below."
            ASM_STATUS=BLOCKED; return 0
            ;;
        *) err "unknown mode '$mode'"; ASM_STATUS=ERROR; return 0 ;;
    esac

    ASM_BRANCH="$branch"; ASM_STATUS=OK
}

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

while [ $# -gt 0 ]; do
    case "$1" in
        -n|--dry-run) DRY_RUN=1 ;;
        -f|--force)   FORCE=1 ;;
        --no-ci)      NO_CI=1 ;;
        -h|--help)    usage; exit 0 ;;
        *) err "unknown option: $1"; usage; exit 1 ;;
    esac
    shift
done

[ "$DRY_RUN" -eq 1 ] || require_clean_tree
verify_preconditions

START_REF="$(git symbolic-ref --quiet --short HEAD || git rev-parse HEAD)"
declare -A RESULT
for _u in "${UNITS[@]}"; do RESULT[$_u]="(not reached)"; done
TIP="$BASE"   # running top of the stack; each unit branches from here.

for unit in "${STACK_ORDER[@]}"; do
    echo
    ASM_STATUS=""; ASM_BRANCH=""
    assemble_unit "$unit" "$TIP"
    case "$ASM_STATUS" in
        BLOCKED) RESULT[$unit]="BLOCKED (cleanup not committed on source); stack stops here"; break ;;
        SKIP)    RESULT[$unit]="SKIP (branch exists)";          continue ;;
        ERROR)   RESULT[$unit]="ERROR (assembly)";              break ;;
    esac
    branch="$ASM_BRANCH"
    PR_BRANCH[$unit]="$branch"
    if ci_gate "$unit"; then
        RESULT[$unit]="PASS  (base: $TIP -> $branch)"
    else
        RESULT[$unit]="CI-FAIL ($branch)"
    fi
    # Advance the stack tip so the next unit builds on this one.
    TIP="$branch"
done

# Return to the starting branch (best effort).
run git checkout -q "$START_REF" 2>/dev/null || true

# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #
echo
echo "==================== SPAKE2+ PR split summary ===================="
printf '%-5s  %-26s  %s\n' "UNIT" "ISSUES" "STATUS"
printf '%-5s  %-26s  %s\n' "----" "------" "------"
for unit in "${UNITS[@]}"; do
    printf 'PR-%-2s  %-26s  %s\n' "$unit" "${PR_ISSUES[$unit]:-cleanup}" "${RESULT[$unit]:-?}"
done
echo "================================================================="

cat <<EOF

Stack order: BASE -> PR-B -> PR-A -> PR-C -> PR-E -> PR-G.
When opening the PRs, set each PR's GitHub base to the PREVIOUS unit's branch.

If PR-G reports BLOCKED, its cleanup is not yet committed on $SOURCE_BRANCH.
PR-G pulls these files from $SOURCE_BRANCH onto the PR-E tip:
  ${PR_SOURCE[G]}
Commit your cleanup (the rewritten docs/architecture/spake2p-matter-rfc9383.md,
the curve-gated spake2p.c, the .gitignore rule, the split ChangeLog) on
$SOURCE_BRANCH, then re-run. See review.md sections A and C.
EOF
