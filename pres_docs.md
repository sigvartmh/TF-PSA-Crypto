# SPAKE2+ PR Decomposition — Presentation Notes

Goal: split the monolithic SPAKE2+ work (branch `spake2p-matter-wip`) into clean, self-contained,
per-issue draft PRs against the fork `sigvartmh/TF-PSA-Crypto`, each building under
`CMAKE_BUILD_TYPE=Check` with its tests passing and a ChangeLog entry.

Issues live on `github.com/Mbed-TLS/mbedtls`. PRs live on `github.com/sigvartmh/TF-PSA-Crypto`.

**STATUS: COMPLETE — all 13 issues delivered as 15 draft PRs (#6–#20).** Every PR builds under `CMAKE_BUILD_TYPE=Check` (`-Werror`) and was independently re-verified (rebuild + RFC 9383 KATs with `MBEDTLS_TEST_HOOKS`) before pushing. A full SPAKE2+ exchange (HMAC, CMAC, and Matter/draft-02 profiles) round-trips end to end with the shared key matching RFC 9383 / draft-02 vectors on both roles.

## Structural finding (important context for the deck)

The implementation does **not** decompose along issue boundaries. Issues 9342 and 9344 map to
self-contained commits and split cleanly. But the **core protocol** (issues
9347/9349/9352/9355/9359/9367/9370/9377) is implemented as **three monolithic commits**:

1. the low-level primitive `drivers/builtin/src/spake2p.c` (key share, transcript hash,
   key schedule, MAC, get_shared_key — prover **and** verifier, HMAC/CMAC/Matter together);
2. the built-in PAKE driver step-machine `psa_crypto_pake.c` (all steps, both roles);
3. the PSA-core PAKE operations `core/psa_crypto.c` (setup, state machine, get_shared_key).

Prover and verifier share the same functions, so the fine-grained issues are *code paths*, not
separable commits. Producing one independently-building PR per issue requires re-slicing these
monoliths by function/role — feasible only as a **stack** (each PR builds on the previous via a
`dev-merged-<issue>` base), not as independent PRs off `development`.

## PR status

| Issue | Title | Branch | PR | Base | Status |
|------:|-------|--------|----|------|--------|
| 9342 | SPAKE2+ public key import/export | `pr/spake2p-9342-public-key-import-export` | [#6](https://github.com/sigvartmh/TF-PSA-Crypto/pull/6) | development | ✅ builds, 1991 tests pass |
| 9344 | psa_pake_set_context() | `pr/spake2p-9344-set-context` | [#7](https://github.com/sigvartmh/TF-PSA-Crypto/pull/7) | development | ✅ builds, 76 pake tests pass |
| 9343 | SPAKE2+ key pair import/export | `pr/spake2p-9343-key-pair-import-export-depends-on-9342` | [#8](https://github.com/sigvartmh/TF-PSA-Crypto/pull/8) | dev-merged-9343 | ✅ builds, 1993 + pake tests pass; depends on #9342 |
| 9347 (prover) | prover setup + output key share | `pr/spake2p-9347-prover-depends-on-9342-9343-9344` | [#9](https://github.com/sigvartmh/TF-PSA-Crypto/pull/9) | dev-merged-9347 | ✅ builds `Check -Werror`; RFC 9383 KATs pass w/ hooks (6/6 spake2p, 87/87 pake), 1993 no regression |
| 9347 (verifier) | verifier setup + key share | `pr/spake2p-9347-verifier-depends-on-9342-9343-9344` | [#10](https://github.com/sigvartmh/TF-PSA-Crypto/pull/10) | (prover branch) | ✅ tests-only; RFC 9383 server-share KATs pass (10/10 spake2p, 91/91 pake), 1993 no regression |
| 9349 | verifier transcript hash | `pr/spake2p-9349-transcript-hash-depends-on-9347` | [#11](https://github.com/sigvartmh/TF-PSA-Crypto/pull/11) | dev-merged-9349 | ✅ invasive transcript-hash KAT vs RFC 9383; 13/13 spake2p, 91/91 pake, 1993 no regression |
| 9352 | verifier confirmation | `pr/spake2p-9352-verifier-confirmation-depends-on-9349` | [#12](https://github.com/sigvartmh/TF-PSA-Crypto/pull/12) | dev-merged-9352 | ✅ key schedule + confirmV KATs vs RFC 9383 (16/16 spake2p, 93/93 pake, 1993 no regression) |
| 9359 | prover transcript hash | `pr/spake2p-9359-prover-transcript-hash-depends-on-9352` | [#13](https://github.com/sigvartmh/TF-PSA-Crypto/pull/13) | dev-merged-9359 | ✅ tests-only; prover transcript KAT (same TT as verifier) + ordering negatives; 17/17, 95/95, 1993 |
| 9355 | prover confirm-check (input CONFIRM) | `pr/spake2p-9355-prover-confirm-check-depends-on-9359` | [#14](https://github.com/sigvartmh/TF-PSA-Crypto/pull/14) | dev-merged-9355 | ✅ constant-time verify; accepts RFC confirmV, tamper→INVALID_SIGNATURE; 20/20, 97/97, 1993 |
| 9367 (prover) | prover output CONFIRM (confirmP) | `pr/spake2p-9367-prover-depends-on-9355` | [#15](https://github.com/sigvartmh/TF-PSA-Crypto/pull/15) | dev-merged-9367 | ✅ tests-only; confirmP KATs P-256/384/521 vs RFC; 23/23, 99/99, 1993 |
| 9367 (verifier) | verifier input CONFIRM check | `pr/spake2p-9367-verifier-depends-on-9355` | [#16](https://github.com/sigvartmh/TF-PSA-Crypto/pull/16) | (9367-prover branch) | ✅ tests-only; accepts confirmP, tamper→INVALID_SIGNATURE; 23/23, 101/101, 1993 |
| 9370 | get_shared_key + confirm guard | `pr/spake2p-9370-get-shared-key-depends-on-9367` | [#17](https://github.com/sigvartmh/TF-PSA-Crypto/pull/17) | dev-merged-9370 | ✅ full-handshake K_shared KAT vs RFC + confirmed-flag security gate; **+ e2e `spake2p_rounds` (random ephemerals, two ops, shared keys equal, HMAC P-256/384/521) + `spake2p_rounds_wrong_password` (mismatched password → confirm fails) in a DEFAULT non-hooks build — parity with `ecjpake_rounds`**; 26/26, 105/105, 1993 |
| 9377 | CMAC profile | `pr/spake2p-9377-cmac-depends-on-9370` | [#18](https://github.com/sigvartmh/TF-PSA-Crypto/pull/18) | dev-merged-9377 | ✅ CMAC confirm KATs vs RFC 9383 App C; **+ e2e rounds + wrong-password for CMAC (P-256/384/521)**; 30/30, 109/109 pake, 1993 |
| 9378 | Matter profile (draft-02) | `pr/spake2p-9378-matter-depends-on-9370` | [#19](https://github.com/sigvartmh/TF-PSA-Crypto/pull/19) | dev-merged-9378 | ✅ draft-02 schedule; Matter interop KAT (K_shared=Ke); **+ e2e rounds + wrong-password for Matter (P-256)**; 27/27, 107/107 pake, 1993 |
| 9381 | registration (derive key pair) | `pr/spake2p-9381-registration-depends-on-9370` | [#20](https://github.com/sigvartmh/TF-PSA-Crypto/pull/20) | dev-merged-9381 | ✅ derive w0‖w1 KAT (RFC 9383 §3.2) + curve negatives; rebased onto latest 9370 (inherits e2e rounds); 108/108 pake, 1993 |

All five leaf bases (`dev-merged-9377/9378/9381`) now sit on the same 9370 tip (`429e6030a`, with the e2e tests).

## Technical notes per delivered PR

### #6 — 9342 public key import/export
- `psa_spake2p_import_key()` parses `w0 ‖ L`, loads the curve group, validates `L` is on-curve.
- Export-size macros `PSA_KEY_EXPORT_SPAKE2P_*_MAX_SIZE` wired into the PSA export-size dispatch.
- 5 RFC 9383 positive vectors + 5 negative cases (`import_with_data`/`import_with_policy`).
- Self-contained; registers `PSA_WANT_ALG_SPAKE2P_HMAC` + `..._KEY_TYPE_SPAKE2P_PUBLIC_KEY`.

### #7 — 9344 psa_pake_set_context()
- Stores the context in the operation object via the PSA local-input copy layer.
- `PSA_ERROR_BAD_STATE` for EC-JPAKE and out-of-order/repeated calls; `INVALID_ARGUMENT` for NULL+len.
- 7 negative/positive cases in `test_suite_psa_crypto_pake`.

### #8 — 9343 key pair import/export (depends on #9342)
- `psa_spake2p_import_key()` extended to parse the prover key pair `w0 ‖ w1` (two equal-length SECP_R1 scalars); reported key size = curve size.
- Relaxed alg-policy check (any SPAKE2+ alg or `PSA_ALG_NONE`); re-enabled KEY_PAIR config selectors + derived `PSA_WANT_ALG_SOME_SPAKE2P`.
- `spake2p_import_export` round-trips (key pair P-256/P-384, public P-256/P-521) + 2 negative key-pair cases.
- Base branch `dev-merged-9343` = development + #9342.

### #9 — 9347 prover setup + key share (depends on #9342/#9343/#9344)
- First protocol slice. Introduces the built-in `spake2p.c` primitive **carved to prover setup + `write_key_share` only** (M/N constants, group/point load, init/free/setup, input setters, `make_own_share`, `write_key_share` + a `MBEDTLS_TEST_HOOKS` ephemeral-injection entry point). Transcript/confirm/derive/get_shared_key deliberately omitted — they land in later slices.
- PSA driver + core wired for `psa_pake_setup` and `psa_pake_output(KEY_SHARE)`; all other steps/roles → `PSA_ERROR_NOT_SUPPORTED`.
- Correctness proven by RFC 9383 Appendix C key-share KATs (P-256/P-384/P-521) at both the primitive and PSA layers, made deterministic via the ephemeral hook.
- Base `dev-merged-9347` = development + #9342 + #9343 + #9344.

### #10 — 9347 verifier setup + key share (depends on #9347-prover)
- **Tests-only** delta stacked on the prover slice (#9): the built-in primitive already computes shares for both roles, so this PR adds verifier-side `psa_pake_setup` + `output(KEY_SHARE)` coverage rather than new code.
- RFC 9383 Appendix C server key-share (`Y`) KATs at both the `spake2p.c` primitive and PSA layers (10/10 spake2p, 91/91 pake), 1993 no regression.
- Base = the #9347-prover branch (PR #9), not a `dev-merged-*` base.

### #11 — 9349 verifier transcript hash + peer key-share input
- Adds verifier `psa_pake_input(KEY_SHARE)`: validates the peer point is on-curve, then builds the SPAKE2+ transcript `TT` (M/N, both shares, `Z`/`V`) in `spake2p.c`.
- New `spake2p_invasive.h` hook exposes the computed `TT` for an invasive transcript-hash KAT vs RFC 9383.
- 13/13 spake2p, 91/91 pake; base `dev-merged-9349`.

### #12 — 9352 verifier confirmation output
- Implements the key schedule (`TT` → HKDF → `K_main` → `K_confirm` = `KcA`/`KcB`) and the verifier confirmation MAC (`confirmV`); the biggest single protocol delta (`spake2p.c` +293).
- Verifier `psa_pake_output(CONFIRM)` wired; key-schedule + `confirmV` KATs vs RFC 9383 (16/16 spake2p, 93/93 pake).
- Base `dev-merged-9352`.

### #13 — 9359 prover transcript hash
- **Tests-only:** the prover derives the same transcript `TT` as the verifier, so this PR adds prover-side transcript KATs + step-ordering negatives, no new source.
- 17/17 spake2p, 95/95 pake; base `dev-merged-9359`.

### #14 — 9355 prover confirmation check (input CONFIRM)
- Adds **constant-time** verification of the peer (verifier) confirmation MAC on `psa_pake_input(CONFIRM)`.
- Accepts the RFC `confirmV`; any tamper → `PSA_ERROR_INVALID_SIGNATURE` (20/20 spake2p, 97/97 pake).
- Base `dev-merged-9355`.

### #15 — 9367 prover confirmation output (confirmP)
- **Tests-only:** prover `psa_pake_output(CONFIRM)` emits `confirmP` using the key-schedule/MAC machinery already in place from #9352.
- `confirmP` KATs P-256/384/521 vs RFC 9383 (23/23 spake2p, 99/99 pake); base `dev-merged-9367`.

### #16 — 9367 verifier confirmation check (depends on #9367-prover)
- **Tests-only:** verifier `psa_pake_input(CONFIRM)` checks `confirmP` in constant time; tamper → `PSA_ERROR_INVALID_SIGNATURE`.
- 23/23 spake2p, 101/101 pake; base = the #9367-prover branch (PR #15).

### #17 — 9370 get_shared_key() + end-to-end rounds
- Implements `psa_pake_get_shared_key()` returning `K_shared`, **gated on the confirmed flag** so the key cannot be released before confirmation succeeds (security gate).
- Adds a `spake2p_rounds` end-to-end test (random ephemerals, two operations, both shared keys equal, P-256/384/521) in a **DEFAULT non-hooks build** — parity with `ecjpake_rounds`.
- Full-handshake `K_shared` KAT vs RFC 9383 (26/26 spake2p, 104/104 pake); two commits; base `dev-merged-9370`.

### #18 — 9377 CMAC key-confirmation support
- Adds the `PSA_ALG_SPAKE2P_CMAC` variant: selects AES-CMAC for the confirmation MAC while sharing the rest of the key schedule (`spake2p.c` +21).
- CMAC confirm KATs vs RFC 9383 Appendix C (`confirmV`/`confirmP`/`K_shared`) + CMAC e2e rounds (30/30 spake2p); two commits; base `dev-merged-9377`.

### #19 — 9378 Matter ciphersuite (draft-02)
- Adds `PSA_ALG_SPAKE2P_MATTER`: the draft-02 key schedule and `K_shared = Ke`, with P-256-only gating in the driver/core.
- Matter interop KAT from `tests/data_files/spake2p_matter_p256_interop.txt` (27/27 spake2p, 101/101 pake); base `dev-merged-9378`.

### #20 — 9381 registration (derive key pair)
- Implements registration via `psa_key_derivation_output_key`, producing the prover key pair `w0 ‖ w1` per RFC 9383 §3.2, behind a new `crypto_config.h` selector (`core/psa_crypto.c` +96).
- Derive-`w0‖w1` KAT + non-P-256 curve negatives (104/104 pake); base `dev-merged-9381`.

## Slicing decision (protocol cluster)
The protocol is three monolithic *files* (`spake2p.c`, `psa_crypto_pake.c`, `core/psa_crypto.c`) sharing one context. Per the chosen **strict function-level carving**: each issue's PR carves only its functions, stacked on a `dev-merged-<issue>` base. 9347 and 9367 split into prover/verifier PRs.

## Convention notes
- Dependent PRs use a `dev-merged-<issue>` base (= development + dependency branches) so the PR diff shows only that issue's delta.
- `pres_docs.md` is excluded via `.git/info/exclude` and must never be committed.
