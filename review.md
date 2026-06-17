# SPAKE2+ implementation review

Review of the SPAKE2+ work on branch `spake2p-matter-wip` against the goal of
upstreaming it to **Mbed-TLS/TF-PSA-Crypto** as self-contained, CI-passing PRs
mapped to the upstream issues (#9343 to #9381), and shipping a **Matter-minimal**
build in sisdk.

Scope: `TF-PSA-Crypto/` only. The separate `mbedtls/` 3.6.4 implementation
(`library/psa_crypto_spake2p.c`) is **not** part of this review.

Severity legend: **A** = upstream-blocking / **B** = minimization ("strictly what
is needed") / **C** = hygiene. Items marked **[FIXED]** have been addressed in the
working tree; the rest are owned by a PR in the plan below.

PR structure (issues combined where the code was co-developed, no hunk-slicing).
The four PRs stack and each one builds and passes its full SPAKE2+ test suites
(verified by `scripts/split_spake2p_prs.sh`):

| PR | Closes | Notes |
|----|--------|-------|
| PR-B | #9344 | set_context; stacks on the upstream base |
| PR-C | #9343 #9347 #9349 #9352 #9355 #9359 #9367 #9370 #9377 | key material + base HMAC/CMAC protocol; #9343 and CMAC ride here (not independently buildable, see A4) |
| PR-E | #9378 #9381 | Matter + registration (one follow-up commit, scaffolding removed) |
| PR-G | cleanup | docs rewrite, scaffolding removal, curve-gating, .gitignore, ChangeLog split |

---

## A. Upstream-blocking

### A1. Developer scaffolding committed into history
- **Where:** `CLAUDE.md`, `apply_commit.sh`, `commit/spake2p-followups.txt` - all
  introduced by commit `0d6051fc9` ("WiP: SPAKE2+ Matter").
- **Problem:** Local development aids (LLM behavioral notes, a one-off commit
  helper, a draft commit message). They must not appear in an upstream PR.
- **Why it matters:** Upstream review will reject unrelated tooling; it also leaks
  internal workflow into a public history.
- **Fix:** When **PR-E** cherry-picks the WiP commit it removes these whole files
  before committing (file-level, no hunk-slicing); `split_spake2p_prs.sh` does this
  in its `combine` mode. Verified again in **PR-G**.

### A2. Stale / incorrect architecture doc (`spake2p-matter-rfc9383.md`)  [FIXED]
- **Where:** `docs/architecture/spake2p-matter-rfc9383.md` (old lines 10, 46, 61, 97, 99).
- **Problem:** The doc referenced symbols and files that **did not exist** in
  TF-PSA-Crypto:
  - `drivers/builtin/src/psa_crypto_spake2p.c` - the real engine is
    `drivers/builtin/src/spake2p.c`.
  - `mbedtls_psa_spake2p_derive_keys`, `mbedtls_psa_spake2p_hash_update_block`,
    `mbedtls_psa_spake2p_make_key_share` - the real engine uses the
    `mbedtls_spake2p_*` naming (e.g. `spake2p_get_mn`, `mbedtls_spake2p_get_shared_key`).
  - `test_suite_psa_crypto_spake2p` - PSA-level SPAKE2+ tests live in
    `test_suite_psa_crypto_pake`; the engine self-test is `test_suite_spake2p`.
- **Root cause:** The doc was copied from the separate `mbedtls/` 3.6.4
  implementation (which *does* use `psa_crypto_spake2p.c` / `mbedtls_psa_spake2p_*`)
  and never re-pointed at the TF-PSA-Crypto layout.
- **Fix [applied]:** The doc has been rewritten to the real TF-PSA-Crypto layout
  (`spake2p.c` + `mbedtls_spake2p_*`, tests in `test_suite_psa_crypto_pake`),
  mapping Matter to RFC 9383 and the engine context fields. Lands in **PR-E**.

### A3. One WiP commit lumps multiple issues + scaffolding
- **Where:** commit `0d6051fc9` mixes the Matter key schedule (#9378),
  registration / `KEY_PAIR_DERIVE` (#9381), the `get_shared_key()` confirmation
  gate (#9370 hardening), **and** the scaffolding from A1, across 15 files.
- **Problem:** A single commit covers several concerns plus tooling.
- **Fix (combined approach):** Cherry-pick the WiP commit into **PR-E**, which
  closes #9378 and #9381 together (and carries the #9370 gate hardening on top of
  the base `get_shared_key` from PR-C), then remove the scaffolding files in the
  same step. No hunk-level slicing is required.

### A4. Commit series is horizontal (by layer), issues are vertical (by feature)
- **Where:** the commit series (`1871291c0` to `136886697`).
- **Problem:** The 1342-line engine `spake2p.c` lands in a single commit
  (`7347ffa55`) yet implements seven step-issues (#9347/#9349/#9352/#9355/#9359/
  #9367/#9370); the driver, core, and public-API wiring are separate commits.
- **Why it matters:** No commit closes a single protocol-step issue.
- **Fix (accepted approach):** Keep the protocol-step issues as ordered commits
  *inside* **PR-C** (the CI boundary for the base ciphersuite), each carrying a
  `Closes: #<n>` trailer. #9343 (key import/export) also folds into PR-C: its
  config-validation registration lives in the "Wire up build configuration" commit
  (`PSA_WANT_KEY_TYPE_SPAKE2P_PUBLIC_KEY`), so it does **not** build on its own (a
  standalone PR-A fails to compile - confirmed by the splitter). PR-B (#9344) is
  the only small standalone PR. The PRs stack (PR-B -> PR-C -> PR-E -> PR-G); set
  each PR's GitHub base to the previous branch. See `Presentation.md` "PR map".

---

## B. Minimization ("strictly what is needed" for Matter)

### B1. P-384 / P-521 M/N constant tables always compiled  [FIXED]
- **Where:** `drivers/builtin/src/spake2p.c` (the `spake2p_secp384r1_M/N`,
  `spake2p_secp521r1_M/N` byte arrays) and the switch arms in `spake2p_get_mn()`.
- **Problem:** These constants and switch arms were compiled unconditionally, even
  in a P-256-only Matter build (~256 bytes of `.rodata` plus dead branches).
- **Why it matters:** Matter only needs P-256; the extra curves are pure overhead
  on a constrained target and widen the audited surface.
- **Fix [applied]:** The per-curve tables and their `spake2p_get_mn` arms are now
  guarded by `#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)` /
  `_SECP384R1_ENABLED` / `_SECP521R1_ENABLED` (the same convention `ecp_curves.c`
  uses), so a P-256-only build drops the other curves. Default all-curves build and
  both SPAKE2+ test suites still pass. Lands in **PR-E**/**PR-G**.

### B2. No verified Matter-minimal compile path
- **Where:** `include/psa/crypto_config.h` (all three SPAKE2+ algs enabled),
  `drivers/builtin/.../crypto_adjust_config_enable_builtins.h`.
- **Problem:** There is no CI configuration that enables **only**
  `PSA_WANT_ALG_SPAKE2P_MATTER` (+ key types) and confirms HMAC-generic, CMAC, AES,
  and P-384/P-521 are all absent from the build.
- **Why it matters:** Without it, "Matter-only" is unverified and could silently
  regress.
- **Fix (remaining):** Audit the config-adjust cascade so the Matter alg pulls in
  only `secp256r1` + SHA-256 + `MBEDTLS_SPAKE2P_C` +
  `MBEDTLS_PSA_BUILTIN_ALG_SPAKE2P_MATTER`, then add a Matter-only CI component
  mirroring the existing SPAKE2+ component in
  `tests/scripts/components-configuration-platform.sh`. Owned by **PR-E**/**PR-G**.

### Positives (no action)
- CMAC engine code is already correctly gated under `#if defined(MBEDTLS_CMAC_C)`,
  so a non-CMAC build already excludes it.
- `PSA_WANT_KEY_TYPE_SPAKE2P_KEY_PAIR_GENERATE` is intentionally left disabled -
  correct: SPAKE2+ keys are password-derived registration material, not random.

---

## C. Hygiene

### C1. Build directory not ignored  [FIXED]
- **Where:** untracked `build_spake2p/`; `.gitignore` previously only covered
  `/build/`.
- **Problem:** `build_spake2p/` (a full CMake tree, including `libtfpsacrypto.a`)
  was one `git add -A` away from being committed.
- **Fix [applied]:** Added `/build[-_]*/` to `.gitignore`; `build_spake2p/` and
  `build-split/` are now ignored. Lands in **PR-G**.

### C2. Single lumped ChangeLog entry
- **Where:** `ChangeLog.d/spake2p.txt` (one file describing several features).
- **Problem:** Upstream expects one `ChangeLog.d/` entry per change/PR.
- **Fix:** Split per-PR (base PAKE+CMAC / Matter+registration) as the branches are
  cut. Owned by each PR; verified in **PR-G**.

---

## Issue to owning-PR summary

| Issue | Title | Owning PR |
|-------|-------|-----------|
| #9344 | `psa_pake_set_context()` | PR-B |
| #9343 | key pair import/export | PR-C (not buildable standalone) |
| #9347 | setup + output key share | PR-C |
| #9349 | verifier transcript hash | PR-C |
| #9352 | verifier confirmation | PR-C |
| #9355 | verifier confirmation check | PR-C |
| #9359 | prover transcript hash | PR-C |
| #9367 | prover confirmation check | PR-C |
| #9370 | `get_shared_key()` (+ confirmation gate) | PR-C (gate hardening in PR-E) |
| #9377 | CMAC support | PR-C |
| #9378 | Matter support | PR-E |
| #9381 | registration | PR-E |
| - | docs/scaffolding/toggle/ChangeLog cleanup | PR-G |

See `Presentation.md` for the per-issue narrative and the architecture mapping, and
`scripts/split_spake2p_prs.sh` for the mechanical re-cut that enforces this table.
