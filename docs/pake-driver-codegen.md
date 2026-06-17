# Making the PAKE driver-wrapper codegen-driven

## Purpose

The PSA driver-wrapper dispatch for PAKE (`psa_driver_wrapper_pake_*`) is
**hand-written** in the codegen template, so adding a real vendor/accelerator PAKE
driver (for example the SE-accelerated SPAKE2+ driver in
[`spake2_hw.md`](spake2_hw.md), or EC-JPAKE) requires editing the generated template
by hand. This note explains why, and designs a **targeted** change that makes PAKE
dispatch generated from the driver JSON, so new PAKE drivers are added by dropping a
JSON file.

It is the detail behind Step 3 of
[`spake2p-accelerator-integration.md`](spake2p-accelerator-integration.md) and the
matching risk in [`spake2_hw.md`](spake2_hw.md).

## TL;DR

- Driver-wrapper codegen exists but is **minimal**: of 64 wrapper functions in the
  template, only **4** are generated (the key-management one-shots). Everything else
  - all crypto one-shots, all multipart operations, and PAKE - is hand-written.
- The reusable generators (`OS-template-transparent.jinja` /
  `OS-template-opaque.jinja`) only handle **one-shot** operations (a single call,
  dispatched by key location). PAKE is **multipart/stateful** and needs a different
  shape (select-and-record at `setup`, dispatch by `operation->id` afterwards).
- "PAKE codegen" therefore means adding **multipart codegen**, which does not exist
  for any operation yet. Recommended scope: a **PAKE-specific** multipart template
  that also serves EC-JPAKE, keeping the operation-context union hand-defined.

---

## How driver-wrapper codegen works today

`scripts/generate_driver_wrappers.py` renders
`scripts/data_files/driver_templates/psa_crypto_driver_wrappers.h.jinja` with jinja2,
passing the driver descriptions (`scripts/data_files/driver_jsons/*.json`, validated
against `driver_transparent_schema.json` / `driver_opaque_schema.json`) as the
`drivers` context list.

The reusable generators are:

- `OS-template-transparent.jinja` - for each transparent driver / capability that
  lists `entry_point`, emit:
  ```
  status = {{ entry_point_name(capability, entry_point, driver) }}( <params> );
  if( status != PSA_ERROR_NOT_SUPPORTED ) return status;
  ```
- `OS-template-opaque.jinja` - for each opaque driver, emit `case {{ driver.location }}:
  return {{ entry_point_name(...) }}( <params> );`
- macros `entry_point_name` (template line 59) and a per-operation
  `entry_point_param(driver)` that supplies the C argument list.

`entry_point_name` resolves to `{{driver.prefix}}_{{driver.type}}_{{entry_point}}`
unless the JSON overrides it via `names`.

## What is generated vs hand-written

The OS-templates are `{% include %}`d in only **four** places, all key management:

| Generated entry point | Template lines |
|-----------------------|----------------|
| `import_key` | ~791-824 |
| `export_key` / `export_public_key` | ~840-866 |
| `copy_key` / `get_builtin_key` | ~882-899 |

Every other wrapper - `sign_hash`, `aead_*`, `cipher_*`, `hash_*`, `mac_*`,
`key_derivation_*`, and **`pake_*`** - is written out by hand with hardcoded blocks
guarded by `PSA_CRYPTO_DRIVER_TEST` (the in-tree test driver) and
`MBEDTLS_PSA_BUILTIN_*`. The PAKE block is `psa_driver_wrapper_pake_{setup,output,
input,get_shared_key,abort}` at template lines ~2752-2910; it references
`mbedtls_test_transparent_pake_*` and `MBEDTLS_TEST_TRANSPARENT_DRIVER_ID` directly
and carries a `/* Add cases for opaque driver here */` placeholder.

The driver JSON schema already allows **free-form** `entry_points` strings, so
`pake_*` can be declared in a JSON today; there is simply no template logic that
consumes it.

---

## Why PAKE cannot reuse the one-shot templates

A one-shot wrapper is a single function call dispatched by key location, with no
state kept between calls. The OS-templates encode exactly that.

PAKE is a **multipart operation**: the backend is chosen once and then reused across
several calls.

- `pake_setup` must select a backend by key location **and record it**: set
  `operation->id` to the winning driver's id and initialize that driver's member of
  the operation-context union.
- `pake_output`, `pake_input`, `pake_get_shared_key`, `pake_abort` must **not**
  re-select; they `switch( operation->id )` and route to the same driver.

The one-shot templates do none of: writing `operation->id`, emitting the id-dispatch
`switch`, or selecting the per-driver context-union member. (This is also why the
multipart hash/cipher/aead/mac wrappers are still hand-written.)

### The operation-context union and driver IDs

`struct psa_pake_operation_s` (`include/psa/crypto_extra.h:1265`) holds a
`psa_driver_pake_context_t ctx` (line 1296). That union is **hand-maintained** in
`include/psa/crypto_driver_contexts_composites.h:120` - today with members
`mbedtls_ctx` (`mbedtls_psa_pake_operation_t`, line 149) and
`transparent_test_driver_ctx` (line 151). `operation->id` is the existing
`PSA_CRYPTO_*_DRIVER_ID` discriminator.

A new PAKE driver already has to add its context type as a union member here and
have a driver id. The targeted design below **keeps that hand-defined** (one member,
as the test driver does) and generates only the dispatch.

---

## Design: targeted PAKE-multipart codegen

Generate the five PAKE wrappers from the driver JSON, keeping the union/id
hand-defined. Three pieces:

### 1. Driver JSON: a `pake` capability

Let a driver declare the PAKE entry points and which ciphersuites it accelerates:

```jsonc
{
  "prefix": "sl_se", "type": "transparent",
  "mbedtls/h_condition": "defined(SL_SE_SUPPORTS_SPAKE2P)",
  "capabilities": [{
    "mbedtls/c_condition": "defined(SL_SE_SUPPORTS_SPAKE2P)",
    "entry_points": ["pake_setup", "pake_output", "pake_input",
                     "pake_get_implicit_key", "pake_abort"],
    "algorithms": ["PSA_ALG_SPAKE2P_MATTER", "PSA_ALG_SPAKE2P_HMAC(PSA_ALG_ANY_HASH)"],
    "fallback": true,
    "names": { "pake_get_implicit_key": "sl_se_transparent_pake_get_implicit_key" }
  }]
}
```

`fallback: true` means "fall through to the next backend on `NOT_SUPPORTED`" (so the
software engine still handles non-accelerated ciphersuites). The schema already
permits all of this; no schema change is required for the minimal version. (An
optional `pake_context` field naming the union member avoids a naming convention.)

### 2. New jinja templates for the multipart pattern

Two small templates analogous to the OS-templates:

- `pake-setup-transparent.jinja` - for each transparent PAKE driver/capability:
  ```jinja
  #if ({{ capability['mbedtls/c_condition'] or 1 }})
  status = {{ entry_point_name(capability, "pake_setup", driver) }}(
               &operation->data.ctx.{{ pake_ctx_member(driver) }}, inputs );
  if( status == PSA_SUCCESS )
      operation->id = {{ driver_id(driver) }};
  if( status != PSA_ERROR_NOT_SUPPORTED )
      return( status );
  #endif
  ```
  followed by the existing `MBEDTLS_PSA_BUILTIN_PAKE` fallback that sets
  `operation->id = PSA_CRYPTO_MBED_TLS_DRIVER_ID`.

- `pake-dispatch.jinja` (parameterized by `entry_point`) - the id-dispatch used by
  `output`/`input`/`get_implicit_key`/`abort`:
  ```jinja
  switch( operation->id ) {
  #if defined(MBEDTLS_PSA_BUILTIN_PAKE)
      case PSA_CRYPTO_MBED_TLS_DRIVER_ID:
          return( mbedtls_psa_pake_{{ entry_point }}( &operation->data.ctx.mbedtls_ctx, ... ) );
  #endif
  {% for driver in drivers if has_pake(driver) %}
  #if ({{ driver_c_condition(driver) }})
      case {{ driver_id(driver) }}:
          return( {{ entry_point_name(cap, entry_point, driver) }}(
                      &operation->data.ctx.{{ pake_ctx_member(driver) }}, ... ) );
  #endif
  {% endfor %}
      default: ... return PSA_ERROR_INVALID_ARGUMENT;
  }
  ```

`driver_id`, `pake_ctx_member` and `driver_c_condition` are tiny helper macros that
derive the id / union-member / `#if` guard from the driver fields (conventionally
`{{prefix|upper}}_..._DRIVER_ID` and `{{prefix}}_transparent_pake_ctx`, or from an
explicit JSON field).

### 3. Conversion with a byte-for-byte no-diff proof

Land it safely:

1. Convert the five hand-written PAKE wrappers to the new templates so that, with
   **only the existing test + builtin drivers**, the regenerated
   `psa_crypto_driver_wrappers.h` is **identical** to the current one. Regenerate and
   `git diff` the generated header - it must show **no change**. This proves the
   templates reproduce today's behaviour.
2. Then a real PAKE driver (the SE SPAKE2+ driver, or EC-JPAKE) is added by dropping
   a JSON entry in `driverlist.json` plus one hand-added union member - **no template
   edit**.

---

## Scope options

| Scope | What | Effort / risk |
|-------|------|---------------|
| **Targeted (recommended)** | PAKE-only multipart templates; reuse for EC-JPAKE; union stays hand-defined | small; isolated to the PAKE section |
| General multipart codegen | one multipart framework for hash/cipher/aead/mac/pake; optionally codegen the union too | large; touches every multipart wrapper; better aligned with the upstream end-state |

## Recommendation

Do the **targeted** version. It removes the manual template edit for PAKE drivers
(the immediate blocker for the SE SPAKE2+ work and J-PAKE), is contained to the PAKE
section, and is verifiable by the no-diff proof. Treat the general multipart codegen
as a separate, upstream-coordinated effort.

## Why this matters here

With targeted PAKE codegen in place, the SE-accelerated SPAKE2+ driver from
[`spake2_hw.md`](spake2_hw.md) is registered purely by JSON: no edit to the
hand-written PAKE section of `psa_crypto_driver_wrappers.h.jinja`. The same applies
to bringing EC-JPAKE under the driver model.

## Risks and constraints

- `psa_crypto_driver_wrappers.h.jinja` is an **upstream-shared, generated** template.
  Changes affect every consumer and should track the Mbed-TLS codegen direction;
  coordinate upstream rather than forking the template locally.
- The operation-context union (`crypto_driver_contexts_composites.h`) stays
  hand-maintained in the targeted scope - a new driver still adds one member there.
  Codegen of the union is possible but is part of the larger general effort.
- PAKE capability matching on `algorithms` should reuse the existing capability
  algorithm-matching the JSONs already use for ECC (`p256_transparent_driver.json`),
  so the `pake` capability is consistent with other entry points.

## Verification

1. **No-diff proof:** regenerate `psa_crypto_driver_wrappers.h` after the template
   conversion (test + builtin only); `git diff` shows no change.
2. **Generated dispatch correctness:** add a JSON-only PAKE driver (start with the
   in-tree test driver moved to JSON), regenerate, and run the PAKE driver-dispatch
   tests (`spake2p_driver_hits` in `test_suite_psa_crypto_driver_wrappers`) plus the
   PAKE round-trip suites (`test_suite_psa_crypto_pake`).
3. **Build matrix:** builds with and without `PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT`
   and with/without `MBEDTLS_PSA_BUILTIN_PAKE` compile and pass.
