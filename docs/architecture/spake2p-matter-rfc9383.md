# Matter SPAKE2+ (P-256) and RFC 9383

This note maps the **Matter / connectedhomeip SPAKE2+ profile** used by TF-PSA-Crypto to **RFC 9383** (SPAKE2+), and separates **key material** handling (always in the core library) from the **online PAKE transcript** (in the optional built-in SPAKE2+ driver).

## Scope in this repository

| Layer | Location | Role |
|--------|-----------|------|
| **SPAKE2+ key import / export / generate** (`w0 \|\| w1 \|\| L`, `w0 \|\| L`) | `core/psa_crypto.c` (`psa_spake2p_import_key`, …) | Validates curve points and, for key pairs, checks `w1·G == L`. |
| **Online PAKE** (`TT`, shares, `Kae`, confirmation, shared secret) | Present when `MBEDTLS_PSA_BUILTIN_ALG_SPAKE2P` is enabled: `drivers/builtin/src/psa_crypto_spake2p.c` (upstream TF-PSA-Crypto layout) | Implements Matter P-256 SPAKE2+ with `PSA_ALG_SPAKE2P_MATTER`. |

In tree configurations that only ship PSA **without** the SPAKE2+ built-in driver, `psa_pake_*` for `PSA_ALG_SPAKE2P_MATTER` is not available; key material APIs still apply.

Normative references: [RFC 9383](https://www.rfc-editor.org/rfc/rfc9383), Matter Core Specification (PASE / SPAKE2+ parameters).

---

## Roles: Matter ↔ RFC ↔ PSA

| Matter / CHIP (interop naming) | RFC 9383 | PSA `psa_pake_set_role` |
|--------------------------------|----------|-------------------------|
| **A / client** (prover, knows password) | `idProver` | `PSA_PAKE_ROLE_CLIENT` → `psa_pake_set_user` is **A** in the transcript |
| **B / server** (verifier, holds `L = w1·P`) | `idVerifier` | `PSA_PAKE_ROLE_SERVER` → `psa_pake_set_peer` from the client’s view is **B**; the server swaps when hashing so **A** is still first in `TT` |

PASE: commissioner with passcode is typically the **client (prover)**; the commissionee is the **server (verifier)**.

---

## Transcript `TT` — RFC 9383 §3.3

RFC 9383 defines (with 8-byte little-endian length prefixes `len(S)`):

```text
TT = len(Context)  || Context
  || len(idProver) || idProver
  || len(idVerifier) || idVerifier
  || len(M) || M
  || len(N) || N
  || len(shareP) || shareP
  || len(shareV) || shareV
  || len(Z) || Z
  || len(V) || V
  || len(w0) || w0
```

The Matter built-in driver (`mbedtls_psa_spake2p_derive_keys`) hashes the same components in the same order, using `mbedtls_psa_spake2p_hash_update_block` (length prefix + payload). Mapping:

| `TT` field | Matter / test vector name | Notes |
|------------|---------------------------|--------|
| `Context` | `Context` | Optional: if the application never sets PAKE context, that block is **omitted**; an explicit **zero-length** context is still hashed as `len(nil) \|\| nil`. |
| `idProver` | **A** | First identity in the hash (see role swap in driver for server). |
| `idVerifier` | **B** | Second identity. |
| `M`, `N` | Fixed group points | Same constants as Matter P-256 (65-byte SEC1 uncompressed). |
| `shareP` | **X** | Prover public share. |
| `shareV` | **Y** | Verifier public share. |
| `Z`, `V` | **Z**, **V** | As in RFC §3.3. |
| `w0` | **w0** | First `w0_len` bytes of SPAKE2+ key material. |

Deterministic vectors for the full transcript and intermediates are recorded in `tests/data_files/spake2p_matter_p256_interop.txt` (connectedhomeip-style description).

Curve operations for public shares match RFC §3.3: prover uses **M** in `X = x·P + w0·M`, verifier uses **N** in `Y = y·P + w0·N` (see `mbedtls_psa_spake2p_make_key_share` in the driver).

---

## Key schedule — RFC 9383 §3.4 vs Matter profile

RFC 9383 §3.4:

- `K_main = Hash(TT)` (full digest, e.g. 32 bytes for SHA-256).
- `K_confirmP \|\| K_confirmV = KDF(nil, K_main, "ConfirmationKeys")`.
- `K_shared = KDF(nil, K_main, "SharedKey")`.

The **Matter P-256 profile implemented in the driver** matches the **split digest + HKDF** description in `tests/data_files/spake2p_matter_p256_interop.txt`, not the literal RFC KDF calls on the full `K_main`:

- `Kae = SHA256(TT)` (same as `K_main`).
- `Ka = Kae[0..15]`, `Ke = Kae[16..31]`.
- `Kca \|\| Kcb = HKDF-SHA256(salt = empty, IKM = Ka, info = "ConfirmationKeys", L = 32)`; each confirmation key is **16 bytes** (`Kca`, `Kcb`).
- The **session / shared secret** material taken from PSA is the **16-byte** slice `Ke` (no HKDF with `"SharedKey"`).

So: **`TT` matches RFC §3.3**; **key derivation matches Matter’s documented profile**, which is a **deliberate deviation** from the illustrative RFC §3.4 KDF layout on full `K_main`.

---

## Key confirmation — RFC §3.4

RFC: `confirmP = MAC(K_confirmP, shareV)`, `confirmV = MAC(K_confirmV, shareP)`.

The driver uses **HMAC-SHA256** with the 16-byte keys above, over the **65-byte uncompressed** peer share, and enforces **confirmV before confirmP** on the prover (client) side, as in RFC message ordering.

---

## Tests in this tree

| Concern | Suite | Notes |
|---------|--------|--------|
| SPAKE2+ **key** import / export / generate / validation | `tests/suites/test_suite_psa_crypto` | Runs in all builds with SPAKE2+ key type support. |
| SPAKE2+ **PAKE** (vectors, wrong confirm/context/identity, step order) | `tests/suites/test_suite_psa_crypto_spake2p` | Only in configurations with `MBEDTLS_PSA_BUILTIN_ALG_SPAKE2P` and `PSA_WANT_ALG_SPAKE2P_MATTER` (see upstream TF-PSA-Crypto driver + suite). |

When adding protocol behaviour, extend the **driver** and **`test_suite_psa_crypto_spake2p`** together; keep **key material** regressions in **`test_suite_psa_crypto`**.
