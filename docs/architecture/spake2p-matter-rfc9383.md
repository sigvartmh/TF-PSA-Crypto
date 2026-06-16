# Matter SPAKE2+ (P-256) and RFC 9383

This note maps the **Matter / connectedhomeip SPAKE2+ profile** implemented in
TF-PSA-Crypto onto **RFC 9383** (SPAKE2+), and separates **key material** handling
(always in the PSA core) from the **online PAKE transcript** (in the optional
built-in SPAKE2+ engine).

It is the Matter-specific companion to
[`spake2p-implementation.md`](spake2p-implementation.md); read that first for the
overall layering and the cryptographic core.

## Scope in this repository

| Layer | Location | Role |
|-------|----------|------|
| SPAKE2+ key import / export / derive (`w0 \|\| w1`, `w0 \|\| L`) | `core/psa_crypto.c` (`psa_spake2p_import_key`, `psa_spake2p_export_public_key`) | Validates curve points and, for key pairs, checks `w1 . G == L`. |
| Online PAKE (`TT`, shares, key schedule, confirmation, shared secret) | `drivers/builtin/src/spake2p.c` (`mbedtls_spake2p_*`), built when `MBEDTLS_PSA_BUILTIN_ALG_SPAKE2P_MATTER` is enabled | Implements Matter P-256 SPAKE2+ selected by `PSA_ALG_SPAKE2P_MATTER`. |

In configurations that ship the PSA key store **without** the SPAKE2+ built-in
engine, `psa_pake_*` for `PSA_ALG_SPAKE2P_MATTER` is unavailable; the key-material
APIs still apply.

Normative references: [RFC 9383](https://www.rfc-editor.org/rfc/rfc9383), the Matter
Core Specification (PASE / SPAKE2+ parameters), and the connectedhomeip test vector
reproduced in `tests/data_files/spake2p_matter_p256_interop.txt`.

---

## Roles: Matter, RFC and PSA

| Matter / CHIP (interop naming) | RFC 9383 | PSA `psa_pake_set_role` | Password key |
|--------------------------------|----------|-------------------------|--------------|
| **Commissioner / prover** (knows the passcode) | `idProver` | `PSA_PAKE_ROLE_CLIENT` | `PSA_KEY_TYPE_SPAKE2P_KEY_PAIR` (`w0 \|\| w1`) |
| **Commissionee / verifier** (holds `L = w1 . P`) | `idVerifier` | `PSA_PAKE_ROLE_SERVER` | `PSA_KEY_TYPE_SPAKE2P_PUBLIC_KEY` (`w0 \|\| L`) |

In PASE the commissioner with the passcode is the **client (prover)**; the
commissionee is the **server (verifier)**. The built-in engine derives the role
from the password length in `mbedtls_psa_pake_setup`: `2 . plen` bytes is a prover,
`3 . plen + 1` bytes is a verifier (see `psa_crypto_pake.c`).

The local and peer identities map to the engine via
`mbedtls_spake2p_set_user` / `mbedtls_spake2p_set_peer`, stored in the context
`user` / `peer` fields. The verifier swaps them when assembling the transcript so
`idProver` (A) is always hashed first, matching RFC 9383.

---

## Transcript `TT` (RFC 9383 Section 3.3)

RFC 9383 defines (with 8-byte little-endian length prefixes `len(S)`):

```text
TT = len(Context)    || Context
   || len(idProver)  || idProver
   || len(idVerifier)|| idVerifier
   || len(M) || M
   || len(N) || N
   || len(shareP) || shareP
   || len(shareV) || shareV
   || len(Z) || Z
   || len(V) || V
   || len(w0) || w0
```

The built-in engine assembles exactly these components, in this order, with a
length-prefixed helper (length prefix followed by payload) inside the derive path
of `spake2p.c`. Mapping to the Matter interop vector names:

| `TT` field | Matter / vector name | Notes |
|------------|----------------------|-------|
| `Context` | `Context` | If the application never calls `psa_pake_set_context`, the block is **omitted**; an explicit zero-length context is still hashed as `len(0) \|\| nil`. |
| `idProver` | **A** | First identity (the engine swaps roles on the verifier so A stays first). |
| `idVerifier` | **B** | Second identity. |
| `M`, `N` | Fixed group points | Matter P-256 constants, 65-byte SEC1 uncompressed when hashed. |
| `shareP` | **X** | Prover public share (engine field `shareP`). |
| `shareV` | **Y** | Verifier public share (engine field `shareV`). |
| `Z`, `V` | **Z**, **V** | As in RFC Section 3.3. |
| `w0` | **w0** | The shared scalar `w0` (engine field `w0`). |

Curve operations for the shares follow RFC Section 3.3: the prover uses **M** in
`shareP = x . P + w0 . M`, the verifier uses **N** in `shareV = y . P + w0 . N`
(`mbedtls_spake2p_write_key_share`). The deterministic transcript and all
intermediates are recorded in `tests/data_files/spake2p_matter_p256_interop.txt`.

---

## Key schedule: RFC 9383 Section 3.4 versus the Matter profile

RFC 9383 Section 3.4 (the HMAC and CMAC ciphersuites, `kdf_type` not Matter):

- `K_main = Hash(TT)` (full digest, 32 bytes for SHA-256).
- `K_confirmP || K_confirmV = HKDF(salt = nil, K_main, "ConfirmationKeys")`.
- `K_shared = HKDF(salt = nil, K_main, "SharedKey")`.

The **Matter P-256 profile** (`kdf_type == MBEDTLS_SPAKE2P_KDF_MATTER`) follows the
split-digest description carried in the connectedhomeip interop vector instead of
the literal RFC KDF calls on the full `K_main`:

- `Kae = SHA256(TT)` (the same value as `K_main`).
- `Ka = Kae[0 .. 15]`, `Ke = Kae[16 .. 31]` (two equal halves).
- `Kca || Kcb = HKDF(salt = nil, IKM = Ka, "ConfirmationKeys", L = 32)`; each
  confirmation key (`Kca`, `Kcb`) is **16 bytes**, stored in the engine as
  `K_confirmP` / `K_confirmV`.
- The **session / shared secret** is the **16-byte** slice `Ke`, stored as
  `K_shared` with `shared_key_len == 16`. There is **no** second HKDF with
  `"SharedKey"`.

So `TT` matches RFC Section 3.3, while the key derivation matches Matter's
documented profile, a deliberate deviation from the illustrative RFC Section 3.4
layout. This split is implemented in the derive path of `spake2p.c`, guarded by
`ctx->kdf_type == MBEDTLS_SPAKE2P_KDF_MATTER`.

---

## Key confirmation (RFC 9383 Section 3.4)

RFC: `confirmP = MAC(K_confirmP, shareV)`, `confirmV = MAC(K_confirmV, shareP)`.

The Matter profile uses **HMAC-SHA-256** with the 16-byte confirmation keys above,
computed over the **65-byte uncompressed** peer share. As in RFC message ordering
the verifier confirms first: the prover verifies `confirmV`
(`mbedtls_spake2p_read_confirm`) before it emits `confirmP`
(`mbedtls_spake2p_write_confirm`). A mismatch is a constant-time failure
(`mbedtls_ct_memcmp` -> `MBEDTLS_ERR_ECP_VERIFY_FAILED` ->
`PSA_ERROR_INVALID_SIGNATURE`).

The shared secret is released only after confirmation succeeds: the context
`confirmed` flag is set inside `mbedtls_spake2p_read_confirm`, and
`mbedtls_spake2p_get_shared_key` refuses to output `Ke` until it is set.

---

## Tests in this tree

| Concern | Suite | Notes |
|---------|-------|-------|
| SPAKE2+ **key** import / export / derive / validation | `tests/suites/test_suite_psa_crypto` | Runs in all builds with SPAKE2+ key-type support. |
| SPAKE2+ **engine** (RFC and Matter vectors, tampered confirm) | `tests/suites/test_suite_spake2p` | `mbedtls_spake2p_self_test` plus generated cases. |
| SPAKE2+ **PAKE** through PSA (rounds, Matter known-answer, wrong confirm/context/identity, step order) | `tests/suites/test_suite_psa_crypto_pake` | Built with `MBEDTLS_PSA_BUILTIN_ALG_SPAKE2P_*`; the Matter KAT (`spake2p_psa_matter_kat`) needs `MBEDTLS_TEST_HOOKS` for ephemeral injection. |

When adding protocol behaviour, extend the **engine** (`spake2p.c`) and
**`test_suite_psa_crypto_pake`** together; keep **key material** regressions in
**`test_suite_psa_crypto`**.
