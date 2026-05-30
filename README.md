pkcs11-bridge
=============

Layer-3 backend of the openssl-provider-wit stack. Exposes a real
PKCS#11 token through the narrow `tegmentum:key-backend` contract,
so the same `simple-provider-adapter` that drives the stub key in
Phase 3 can drive a SoftHSM2 / YubiHSM / Luna / CloudHSM key here.

  simple-provider-adapter (Layer 2)
    ↓ tegmentum:key-backend
  pkcs11-bridge (this component, Layer 3)
    ↓ pkcs11:host (slot-manager + session + object + crypto + util)
  pkcs11-wasm-host  (Rust wasmtime adapter, ~/git/pkcs11-wasm-host)
    ↓ libpkcs11.so  (libsofthsm2 / Yubico / Luna / ...)

URI format (RFC 7512 subset)
---------------------------

  pkcs11:slot-id=0;object=my-tls-key;pin-value=1234

Supported attributes: `slot-id`, `object` (CKA_LABEL), `id`
(CKA_ID, may be percent-encoded), `pin-value`. Tolerated but
ignored: `token`, `manufacturer`, `model`, `library-version`,
`library-manufacturer`, `library-description`, `serial`, `type`,
`module-path`, `module-name`. The broader RFC 7512 surface
(library version filters, `pin-source=`, etc.) lands in Phase 8
when concrete deployments hit cases the simpler form misses.

`slot-id` is required in Phase 4 -- token-label-only lookup needs
an extra slot-enumeration pass that's pure boilerplate to add but
not yet wired.

Mechanism mapping
-----------------

The adapter passes a typed `signature-mechanism` to the bridge;
this table translates it to a PKCS#11 `CKM_*`:

  Ecdsa(Sha256)       -> CKM_ECDSA_SHA256       (token hashes)
  Ecdsa(Sha384)       -> CKM_ECDSA_SHA384
  Ecdsa(Sha512)       -> CKM_ECDSA_SHA512
  Ecdsa(Raw)          -> CKM_ECDSA               (caller pre-hashed)
  RsaPkcs1(Sha256)    -> CKM_SHA256_RSA_PKCS    (token hashes)
  RsaPkcs1(Sha384)    -> CKM_SHA384_RSA_PKCS
  RsaPkcs1(Sha512)    -> CKM_SHA512_RSA_PKCS
  RsaPkcs1(Raw)       -> CKM_RSA_PKCS           (caller pre-wrapped DigestInfo)
  RsaPss({d, m, s})   -> CKM_SHA{256,384,512}_RSA_PKCS_PSS
  Eddsa               -> CKM_EDDSA
  RsaRaw              -> CKM_RSA_X_509

Cipher mechanisms (used for `key.decrypt`):

  RsaPkcs1     -> CKM_RSA_PKCS
  RsaOaep(_)   -> CKM_RSA_PKCS_OAEP             (params NOT yet marshalled)
  RsaRaw       -> CKM_RSA_X_509

Status
------

**Phase 4.5 complete (code + composition).** The bridge:

  - Parses pkcs11: URIs (RFC 7512 subset).
  - Opens a PKCS#11 session, logs in with the URI's pin-value.
  - Resolves the URI to a private-key CK_OBJECT_HANDLE.
  - `key.algorithm` returns Ec or Rsa derived from CKA_KEY_TYPE.
  - `key.sign` translates the mech and calls C_SignInit + C_Sign
    in one shot through `session.sign`.
  - `key.public_key_info` finds the matching public-key object,
    pulls CKA_EC_PARAMS + CKA_EC_POINT (or CKA_MODULUS +
    CKA_PUBLIC_EXPONENT), and assembles SubjectPublicKeyInfo DER
    by hand in src/spki.rs (no `der` / `spki` crate dep).
  - `key.verify` / `key.decrypt` wired analogously.
  - `key.derive` returns MechanismNotSupported (ECDH wiring is
    Phase 8 work).

  Built artifact: ~110 KB wasm. `wasm-tools validate` clean.

  Composes cleanly with simple-provider-adapter (`wac plug`):

    wac plug \
      ~/git/simple-provider-adapter/target/wasm32-wasip2/release/simple_provider_adapter.wasm \
      --plug target/wasm32-wasip2/release/pkcs11_bridge.wasm \
      -o adapter-with-pkcs11.wasm

  The composed component exports the full openssl:provider-abi and
  imports just the unsatisfied pkcs11:host interfaces (6 packages),
  which a host like `~/git/pkcs11-wasm-host` provides through
  `wasmtime::component::Linker::add_to_linker`.

**Phase 4.6 (SoftHSM smoke) -- DEFERRED.** Requires:

  - SoftHSM2 installed locally (`brew install softhsm`).
  - An initialized token (use
    `~/git/pkcs11-wasm-host/scripts/softhsm-setup.sh`).
  - A wasmtime test harness that loads
    `adapter-with-pkcs11.wasm`, satisfies the pkcs11:host imports
    via `pkcs11-wasm-host`, calls `tegmentum:key-backend.key.sign`,
    and verifies the returned signature against the token's known
    SPKI via openssl-rs.

  The bridge IS structurally complete -- the smoke is the
  environment-setup-heavy verification step.

Pinned toolchain
----------------

`wit-bindgen 0.44`. Same caveats as `simple-provider-adapter`:
- avoid identifiers like `sha2-256` (use `sha256`),
- skip the `pkcs11:constants` WIT package (it uses `const`
  declarations that 0.44 doesn't parse) -- the constants we need
  are duplicated inline in `src/lib.rs::ck`.
