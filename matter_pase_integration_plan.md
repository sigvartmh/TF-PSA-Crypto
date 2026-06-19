# Matter PASE ⇄ TF-PSA-Crypto SPAKE2+ Integration Plan (suggestion)

Status: **proposal / design note.** Not committed; intended to seed a discussion and a follow-up
work item. The Matter (connectedhomeip / "CHIP") stack is **not present in this SDK tree**
(`platform/` is the Silicon Labs platform SDK: SE firmware, mbedTLS, RTOS — no CHIP source), so the
specifics below are based on the **public connectedhomeip crypto interface** — the same reference our
`PSA_ALG_SPAKE2P_MATTER` KAT is validated against (`tests/data_files/spake2p_matter_p256_interop.txt`).
Exact symbol names/signatures must be confirmed against the Matter SDK version actually used.

---

## 1. Goal

Use TF-PSA-Crypto's SPAKE2+ (`PSA_ALG_SPAKE2P_MATTER`, validated byte-for-byte against the
connectedhomeip P-256 vector) as the cryptographic engine underneath **Matter PASE** (Passcode
Authenticated Session Establishment), so the SPAKE2+ math runs through the PSA driver interface and
can be offloaded to the Secure Engine / an accelerator, instead of Matter's bundled mbedTLS-direct
SPAKE2+.

## 2. Layering: what we provide vs. what Matter PASE owns

```
┌─────────────────────────────────────────────────────────────┐
│ Matter commissioning / Secure Channel  (connectedhomeip)     │
│   PASESession: PBKDFParamRequest/Response, Pake1/2/3 framing, │
│   passcode→PBKDF2(w0,w1), session-key derivation from Ke,     │  ← Matter stack (NOT this library)
│   Context string, empty A/B identities                       │
├─────────────────────────────────────────────────────────────┤
│ CHIP crypto abstraction:  class Spake2p (CHIPCryptoPAL.h)     │  ← the seam we replace
├─────────────────────────────────────────────────────────────┤
│ PSA PAKE API  (psa_pake_setup/output/input/get_shared_key)   │
│ PSA_ALG_SPAKE2P_MATTER  — draft-02 key schedule              │  ← TF-PSA-Crypto (this library, done)
│   → built-in software, or SE/accelerator via PSA driver      │
└─────────────────────────────────────────────────────────────┘
```

What this library already does (issues #9342–#9381, PRs #6–#20):

- SPAKE2+ setup, key share, transcript hash, **draft-02 Matter key schedule** (`Kae=SHA256(TT)`,
  `Ka‖Ke`, `Kca‖Kcb = HKDF(Ka,"ConfirmationKeys")`, `K_shared = Ke`, HMAC-SHA-256 confirmation),
  mutual confirmation, and `get_shared_key` gated on confirmation.
- Validated against the connectedhomeip interop vector — **same `Ke`, `confirmP`, `confirmV` bytes**.

What Matter PASE must keep owning (out of scope for a PSA crypto library):

- **PBKDF2** of the passcode into `w0/w1` with the on-the-wire iteration count + salt
  (PBKDFParamResponse). (We expose `psa_key_derivation_output_key(PSA_KEY_TYPE_SPAKE2P_KEY_PAIR)` —
  #9381 — which can perform the reduction step, but the Matter PBKDF parameters and framing stay in
  the stack.)
- **Message framing & state machine**: PBKDFParamRequest/Response, Pake1 (`pA`), Pake2 (`pB`,`cB`),
  Pake3 (`cA`).
- The Matter **Context** string (e.g. `"CHIP PAKE V1 Commissioning"` — confirm against the spec
  version) and the convention of **empty** prover/verifier identities.
- **Session-key derivation** from `Ke` (HKDF → I2R/R2I keys + AttestationChallenge).

## 3. Where Matter implements PASE (connectedhomeip, for reference)

- `src/crypto/CHIPCryptoPAL.h` — abstract `class Spake2p` and the concrete
  `Spake2p_P256_SHA256_HKDF_HMAC`.
- `src/crypto/CHIPCryptoPALmbedtls.cpp` (and `...OpenSSL.cpp`, `...PSA.cpp`) — backend point math.
- `src/protocols/secure_channel/PASESession.cpp` — the PASE protocol/state machine.

The `Spake2p` class is the natural replacement seam: add a backend that drives the **PSA PAKE API**.

## 4. Protocol flow ↔ PSA PAKE mapping

Matter PASE roles: **Commissioner = prover = `PSA_PAKE_ROLE_CLIENT`** (knows `w0,w1`);
**Commissionee = verifier = `PSA_PAKE_ROLE_SERVER`** (stores `w0, L`).

| Matter step | CHIP `Spake2p` call | PSA PAKE equivalent |
|---|---|---|
| init w/ context | `Init(context,len)` | `psa_pake_setup(op,key,cs)` → `psa_pake_set_context` |
| load secrets (prover) | `BeginProver(idP,idV,w0,w1)` | import `PSA_KEY_TYPE_SPAKE2P_KEY_PAIR` (`w0‖w1`) → `setup`; `set_role(CLIENT)`; `set_user/peer` |
| load secrets (verifier) | `BeginVerifier(idV,idP,w0,L)` | import `PSA_KEY_TYPE_SPAKE2P_PUBLIC_KEY` (`w0‖L`) → `setup`; `set_role(SERVER)`; `set_user/peer` |
| own share + read peer | `ComputeRoundOne(peer, out)` | `psa_pake_output(KEY_SHARE)` (own X/Y) **and** `psa_pake_input(KEY_SHARE)` (peer's) |
| own confirm + derive Ke | `ComputeRoundTwo(peer, out)` | `psa_pake_output(CONFIRM)` (own cA/cB); Ke derived internally |
| verify peer confirm | `KeyConfirm(peer)` | `psa_pake_input(CONFIRM)` → fails with `PSA_ERROR_INVALID_SIGNATURE` on mismatch |
| extract shared secret | `GetKeys(out)` | `psa_pake_get_shared_key(op,attr,&key)` → 16-byte `Ke` |

Concrete wire sequence (commissioner C / commissionee S):

```
C: setup, set_role(CLIENT), set_user(""), set_peer(""), set_context("CHIP PAKE V1 Commissioning")
S: setup, set_role(SERVER),  set_user(""), set_peer(""), set_context(<same>)
Pake1  C→S:  pA = psa_pake_output(C, KEY_SHARE)            ; S: psa_pake_input(S, KEY_SHARE, pA)
Pake2  S→C:  pB = psa_pake_output(S, KEY_SHARE)            ; C: psa_pake_input(C, KEY_SHARE, pB)
             cB = psa_pake_output(S, CONFIRM)              ; C: psa_pake_input(C, CONFIRM, cB)   // must succeed
Pake3  C→S:  cA = psa_pake_output(C, CONFIRM)              ; S: psa_pake_input(S, CONFIRM, cA)   // must succeed
both:  Ke = psa_pake_get_shared_key(...)   // refused until that side's input(CONFIRM) verified (#9370 guard)
```

This is exactly the flow exercised by our end-to-end test `spake2p_rounds` (random ephemerals, both
roles agree on `Ke`) and the negative `spake2p_rounds_wrong_password` (mismatched passcode → confirm
fails) — so the PSA layer is already proven to support the Matter sequence.

## 5. API impedance mismatch (the main integration work)

CHIP's `Spake2p` **combines** steps that PSA **splits**:

- `ComputeRoundOne` both *consumes* the peer share and *produces* the own share. PSA separates this
  into `input(KEY_SHARE)` and `output(KEY_SHARE)`. The adapter must split/sequence these and buffer
  the own share until the framing layer asks for it. Note PSA has no ordering constraint between the
  two `output(KEY_SHARE)` of the two parties, so Pake1-before-Pake2 framing is preserved naturally.
- `ComputeRoundTwo` *produces* the own confirm **and** derives `Ke`. In PSA, `output(CONFIRM)`
  produces the MAC and the key schedule (incl. `Ke`) is derived once both shares are in; `Ke` is then
  fetched separately via `get_shared_key`.
- `GetKeys` returns `Ke`; in PSA it is a key object (`psa_pake_get_shared_key` imports it under
  caller attributes) — export it (or, better, keep it as a PSA key and feed Matter's session-key HKDF
  through `psa_key_derivation_*`).

Recommended shape: a `Spake2pPsaPakeBackend : public Spake2p` adapter that holds one
`psa_pake_operation_t` and a small buffer for the locally produced share/MAC, mapping the table above.

## 6. Build / configuration

- Enable `PSA_WANT_ALG_SPAKE2P_MATTER` (+ `PSA_WANT_KEY_TYPE_SPAKE2P_PUBLIC_KEY`,
  `..._KEY_PAIR_*`, `PSA_WANT_ALG_HMAC`, `PSA_WANT_ALG_HKDF`, `PSA_WANT_ECC_SECP_R1_256`) in the
  TF-PSA-Crypto config used by the Matter build.
- Point Matter's crypto layer at TF-PSA-Crypto as the PSA provider; select the new
  PSA-PAKE-backed `Spake2p` at build time (a `CHIP_CRYPTO_PSA_SPAKE2P` flag, parallel to Matter's
  existing `CHIP_CRYPTO_PSA`).
- SE/accelerator: because the math runs through the PSA driver interface, a Secure-Engine SPAKE2+
  driver can later serve the same path with no change to the Matter adapter (this is the whole point
  of routing through PSA rather than mbedTLS-direct).

## 7. Security considerations

- **Confirmation-before-key**: `get_shared_key` is refused until that party verified the peer's
  confirmation MAC (the dedicated `confirmed` flag, #9370) — independent of call-sequence state. Keep
  relying on this; do not extract `Ke` on a path that skips `input(CONFIRM)`.
- **Constant-time** MAC compare is used for confirmation (`mbedtls_ct_memcmp`); a mismatch returns
  `PSA_ERROR_INVALID_SIGNATURE` (→ Matter must abort PASE and rate-limit, per spec).
- **Context / identities** must match on both sides bit-for-bit (they enter the transcript). Matter
  uses empty identities and a fixed Context; a mismatch surfaces as a confirmation failure, not a
  silent wrong key.
- `w0/w1` and `Ke` live in PSA key slots; prefer keeping `Ke` as a non-exportable PSA key and running
  the session-key HKDF via `psa_key_derivation` to avoid copying the secret into Matter heap.

## 8. Phased plan

1. **Spike** — stand up `Spake2pPsaPakeBackend` against TF-PSA-Crypto and replay the connectedhomeip
   interop vector through it (assert `pA,pB,cA,cB,Ke` match `spake2p_matter_p256_interop.txt`).
2. **Wire PASESession** — select the backend under a build flag; run a loopback PASE
   (commissioner↔commissionee) and confirm both derive identical session keys.
3. **PBKDF path** — verify passcode→`w0/w1` (Matter PBKDF2 params) feeding the backend; optionally
   use `psa_key_derivation_output_key(SPAKE2P_KEY_PAIR)` (#9381) for the reduction.
4. **Interop** — run against an unmodified connectedhomeip peer (the other role) on the wire.
5. **Offload** — swap in the SE/accelerator PSA SPAKE2+ driver behind the same adapter.
6. **Negative/robustness** — wrong passcode, tampered Pake2/Pake3, out-of-order, abort/rate-limit.

## 9. Test strategy (reuse what exists)

- Unit: our `test_suite_spake2p` / `test_suite_psa_crypto_pake` KATs already validate the Matter
  key schedule and a full e2e handshake (`spake2p_rounds`, `spake2p_rounds_wrong_password`).
- Adapter: vector-replay (step 1) + loopback (step 2) above.
- CI: the `component_tf_psa_crypto_test_spake2p_hooks` all.sh component (added to PR #9) builds with
  `MBEDTLS_TEST_HOOKS` so the deterministic KATs run — extend it (or the Matter side) with the
  adapter loopback once it exists.

## 10. Open questions / to verify against the target Matter SDK

- Exact `Spake2p` virtual API + the build flag name for selecting a PSA-PAKE backend in that version.
- The exact Context string and identity convention for the Matter version/profile in use.
- Whether to expose `Ke` as bytes or keep it a PSA key for the downstream session-key HKDF.
- `Ke` length expectation on the Matter side (our Matter `Ke` = 16 bytes, `Kae[16..31]`).

## 11. References

- This repo: `PSA_ALG_SPAKE2P_MATTER` (PR #19), `get_shared_key` guard (PR #17), e2e
  `spake2p_rounds*` (PR #17), interop vector `tests/data_files/spake2p_matter_p256_interop.txt`.
- RFC 9383 (SPAKE2+) and draft-bar-cfrg-spake2plus-02 (Matter's key schedule).
- connectedhomeip: `src/crypto/CHIPCryptoPAL.*`, `src/protocols/secure_channel/PASESession.cpp`.
- Matter Core Specification — "Passcode-Authenticated Session Establishment (PASE)".
