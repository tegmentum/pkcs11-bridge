//! pkcs11-bridge — Layer-3 backend that exposes a real PKCS#11 token
//! through the narrow `tegmentum:key-backend` contract.
//!
//! Sits underneath `simple-provider-adapter` in the openssl-provider
//! stack:
//!
//!   simple-provider-adapter (Layer 2)
//!     ↓ tegmentum:key-backend
//!   pkcs11-bridge (this component, Layer 3)
//!     ↓ pkcs11:host (slot-manager + session + object + crypto)
//!   pkcs11-wasm-host (Rust wasmtime adapter)
//!     ↓ libpkcs11.so
//!
//! Each `Key` resource constructor parses a PKCS#11 URI per RFC 7512,
//! opens a session against the named slot, optionally logs in with
//! the pin, and resolves the URI to a CK_OBJECT_HANDLE via
//! `find-objects-init` + `find-objects`.

wit_bindgen::generate!({
    world: "bridge",
    path: "wit",
    generate_all,
});

mod spki;

use std::cell::RefCell;

use exports::tegmentum::key_backend::key_backend as kb;
use pkcs11::object::object as p11_object;
use pkcs11::session::session as p11_session;
use pkcs11::token::slot_manager as p11_slot;
use pkcs11::core::core as p11_core;
use pkcs11::util::util as p11_util;

// ===========================================================================
// PKCS#11 URI parser (RFC 7512 subset)
// ===========================================================================

/// Parsed PKCS#11 URI. Phase 4 supports the path attributes the
/// typical openssl + pkcs11 deployment uses; the broader RFC 7512
/// surface (id, library-version, manufacturer-id, model, ...) lands
/// in Phase 8 when real users hit cases the simpler form misses.
///
/// Two extension attributes outside the RFC, useful for the dev /
/// softhsm flow:
///   init=true            -- self-provision the token + key on first
///                            use (mirrors keystore-pkcs11's pattern)
///   so-pin=NNNN          -- security-officer PIN for token init
///                            (defaults to the same value as pin-value)
///   algorithm=NAME       -- which key to generate when init=true.
///                            Accepted: "ecdsa-p256" (default), "rsa-2048".
#[derive(Default, Debug, Clone)]
struct Pkcs11Uri {
    /// CK_SLOT_ID. Either slot-id or token-label must be set; we
    /// require slot-id in Phase 4 (label lookup needs an extra slot
    /// enumeration pass).
    slot_id: Option<u64>,
    /// CKA_LABEL of the target object.
    object: Option<String>,
    /// CKA_ID hex string (e.g. "%01%02%03"). Optional alternative
    /// to label.
    id: Option<Vec<u8>>,
    /// PIN from `pin-value=`. Phase 4 doesn't yet support
    /// `pin-source=` (which would fetch from a file/URL).
    pin: Option<String>,
    /// Extension: auto-init the token + generate the key if absent.
    init: bool,
    /// Extension: SO PIN for `init=true` (defaults to `pin`).
    so_pin: Option<String>,
    /// Extension: which algorithm to generate on init. Defaults to
    /// "ecdsa-p256".
    algorithm: Option<String>,
}

impl Pkcs11Uri {
    fn parse(s: &str) -> Result<Self, String> {
        let s = s.strip_prefix("pkcs11:")
            .ok_or_else(|| format!("not a pkcs11 URI: {s}"))?;
        // RFC 7512: path-attrs separated by `;`, query-attrs after
        // `?` separated by `&`. We treat both as one keyspace --
        // `pin-value` is technically a query attr but most
        // openssl configs put it in the path. Be liberal.
        let mut out = Pkcs11Uri::default();
        let normalized = s.replace('?', ";").replace('&', ";");
        for kv in normalized.split(';') {
            if kv.is_empty() { continue; }
            let (k, v) = kv.split_once('=')
                .ok_or_else(|| format!("bad pkcs11 attr: {kv}"))?;
            let v = pct_decode(v);
            match k {
                "slot-id"   => out.slot_id = Some(v.parse()
                    .map_err(|_| format!("bad slot-id: {v}"))?),
                "object"    => out.object = Some(v),
                "id"        => out.id = Some(v.into_bytes()),
                "pin-value" => out.pin = Some(v),
                "init"      => out.init = matches!(v.as_str(),
                                                   "true" | "1" | "yes" | "auto"),
                "so-pin"    => out.so_pin = Some(v),
                "algorithm" => out.algorithm = Some(v),
                // Tolerated but ignored in Phase 4.
                "token" | "manufacturer" | "model" | "library-version"
                  | "library-manufacturer" | "library-description"
                  | "serial" | "type" | "module-path" | "module-name" => {}
                _ => return Err(format!("unsupported pkcs11 attr: {k}")),
            }
        }
        if out.slot_id.is_none() {
            return Err("pkcs11-bridge: URI must include slot-id=N".into());
        }
        if out.object.is_none() && out.id.is_none() {
            return Err("pkcs11-bridge: URI must include object= or id=".into());
        }
        Ok(out)
    }
}

/// Percent-decode the subset RFC 7512 uses. Phase 4 handles `%HH`
/// hex escapes; everything else passes through.
fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2]),
            ) {
                out.push((hi << 4) | lo);
                i += 3; continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ===========================================================================
// PKCS#11 attribute / object-class / mechanism constants
// Defined inline; the pkcs11:constants WIT package isn't imported into
// our world (we don't need the full 200+ constants -- just these).
// ===========================================================================

#[allow(non_upper_case_globals)]
mod ck {
    // Object classes (CKO_*)
    pub const CKO_PUBLIC_KEY:  u32 = 0x02;
    pub const CKO_PRIVATE_KEY: u32 = 0x03;
    // Key types (CKK_*)
    pub const CKK_RSA:  u32 = 0x00;
    pub const CKK_EC:   u32 = 0x03;
    // Attributes (CKA_*)
    pub const CKA_CLASS:           u32 = 0x00;
    pub const CKA_TOKEN:           u32 = 0x01;  // persistent (not session) object
    pub const CKA_PRIVATE:         u32 = 0x02;  // hide on public-class enumerations
    pub const CKA_LABEL:           u32 = 0x03;
    pub const CKA_KEY_TYPE:        u32 = 0x100;
    pub const CKA_ID:              u32 = 0x102;
    pub const CKA_SIGN:            u32 = 0x108;  // allow CKO_PRIVATE_KEY to sign
    pub const CKA_VERIFY:          u32 = 0x10A;  // allow CKO_PUBLIC_KEY to verify
    pub const CKA_MODULUS:         u32 = 0x120;
    pub const CKA_MODULUS_BITS:    u32 = 0x121;
    pub const CKA_PUBLIC_EXPONENT: u32 = 0x122;
    pub const CKA_EC_PARAMS:       u32 = 0x180;
    pub const CKA_EC_POINT:        u32 = 0x181;
    // Mechanisms (CKM_*) -- the ones we map. u64 because that's the
    // pkcs11-wit type.
    pub const CKM_RSA_PKCS_KEY_PAIR_GEN: u64 = 0x0000;
    pub const CKM_RSA_PKCS:              u64 = 0x0001;
    pub const CKM_RSA_X_509:             u64 = 0x0003;
    pub const CKM_RSA_PKCS_OAEP:         u64 = 0x0009;
    pub const CKM_SHA256_RSA_PKCS:       u64 = 0x0040;
    pub const CKM_SHA384_RSA_PKCS:       u64 = 0x0041;
    pub const CKM_SHA512_RSA_PKCS:       u64 = 0x0042;
    pub const CKM_SHA256_RSA_PKCS_PSS:   u64 = 0x0043;
    pub const CKM_SHA384_RSA_PKCS_PSS:   u64 = 0x0044;
    pub const CKM_SHA512_RSA_PKCS_PSS:   u64 = 0x0045;
    pub const CKM_ECDSA_KEY_PAIR_GEN:    u64 = 0x1040;
    pub const CKM_ECDSA:                 u64 = 0x1041;
    pub const CKM_ECDSA_SHA256:          u64 = 0x1044;
    pub const CKM_ECDSA_SHA384:          u64 = 0x1045;
    pub const CKM_ECDSA_SHA512:          u64 = 0x1046;
    pub const CKM_EDDSA:                 u64 = 0x1057;

    // ECDSA P-256 named-curve DER: OID 1.2.840.10045.3.1.7
    pub const EC_PARAMS_P256: &[u8] = &[
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    ];
}

fn map_signature_mech(m: &kb::SignatureMechanism) -> Result<u64, kb::BackendError> {
    use kb::SignatureMechanism as M;
    use kb::DigestAlgorithm as D;
    match m {
        M::RsaPkcs1(D::Sha256) => Ok(ck::CKM_SHA256_RSA_PKCS),
        M::RsaPkcs1(D::Sha384) => Ok(ck::CKM_SHA384_RSA_PKCS),
        M::RsaPkcs1(D::Sha512) => Ok(ck::CKM_SHA512_RSA_PKCS),
        M::RsaPkcs1(D::Raw)    => Ok(ck::CKM_RSA_PKCS), // caller pre-wrapped DigestInfo
        M::RsaPss(p) => match p.digest {
            D::Sha256 => Ok(ck::CKM_SHA256_RSA_PKCS_PSS),
            D::Sha384 => Ok(ck::CKM_SHA384_RSA_PKCS_PSS),
            D::Sha512 => Ok(ck::CKM_SHA512_RSA_PKCS_PSS),
            _ => Err(kb::BackendError::MechanismNotSupported(
                "pkcs11-bridge: RSA-PSS only supports SHA-256/384/512".into())),
        },
        M::Ecdsa(D::Sha256) => Ok(ck::CKM_ECDSA_SHA256),
        M::Ecdsa(D::Sha384) => Ok(ck::CKM_ECDSA_SHA384),
        M::Ecdsa(D::Sha512) => Ok(ck::CKM_ECDSA_SHA512),
        M::Ecdsa(D::Raw)    => Ok(ck::CKM_ECDSA), // caller pre-hashed
        M::Eddsa            => Ok(ck::CKM_EDDSA),
        M::RsaRaw           => Ok(ck::CKM_RSA_X_509),
        _ => Err(kb::BackendError::MechanismNotSupported(
            "pkcs11-bridge: digest/mech pair not mapped to a CKM_*".into())),
    }
}

fn map_cipher_mech(m: &kb::CipherMechanism) -> Result<u64, kb::BackendError> {
    use kb::CipherMechanism as M;
    match m {
        M::RsaPkcs1   => Ok(ck::CKM_RSA_PKCS),
        M::RsaOaep(_) => Ok(ck::CKM_RSA_PKCS_OAEP),
        M::RsaRaw     => Ok(ck::CKM_RSA_X_509),
    }
}

fn ck_error_to_backend(e: p11_core::ErrorCode) -> kb::BackendError {
    // The error-code variant is wide; collapse to one of our broad
    // categories. Phase 8 will surface tag-specific mappings.
    let dbg = format!("{:?}", e);
    if dbg.contains("PinIncorrect") || dbg.contains("UserNotLoggedIn") {
        kb::BackendError::AuthenticationFailed(dbg)
    } else if dbg.contains("MechanismInvalid") || dbg.contains("KeyTypeInconsistent") {
        kb::BackendError::MechanismNotSupported(dbg)
    } else if dbg.contains("ObjectHandleInvalid") || dbg.contains("KeyHandleInvalid") {
        kb::BackendError::KeyNotFound(dbg)
    } else {
        kb::BackendError::Internal(dbg)
    }
}

// ===========================================================================
// SPKI assembly
// ===========================================================================

// SPKI assembly lives in src/spki.rs as plain hand-written DER.
// Thin wrappers here translate its &'static str errors into the
// backend-error variant.
fn build_ec_spki(ec_params_der: &[u8], ec_point_der: &[u8])
    -> Result<Vec<u8>, kb::BackendError> {
    spki::build_ec_spki(ec_params_der, ec_point_der)
        .map_err(|e| kb::BackendError::Internal(format!("EC SPKI: {e}")))
}

fn build_rsa_spki(modulus: &[u8], public_exponent: &[u8])
    -> Result<Vec<u8>, kb::BackendError> {
    Ok(spki::build_rsa_spki(modulus, public_exponent))
}

// ===========================================================================
// PKCS#11 session helpers
// ===========================================================================

fn open_session_for(uri: &Pkcs11Uri) -> Result<p11_session::Session, kb::BackendError> {
    // Best-effort initialize -- many hosts auto-init on first call,
    // others require explicit. Ignored if "already-initialized".
    let _ = p11_slot::initialize(None);
    let target_slot = uri.slot_id.ok_or_else(||
        kb::BackendError::Internal("missing slot-id".into()))? as u32;

    let flags = p11_core::SessionFlags::SERIAL_SESSION
              | p11_core::SessionFlags::RW_SESSION;

    // Try the requested slot first. If it errors (typical:
    // CKR_TOKEN_NOT_PRESENT 0xE1) and the URI asked for init=true,
    // provision a token and rediscover the slot id; otherwise
    // propagate the error.
    let sess = match p11_slot::open_session(target_slot, flags) {
        Ok(s)  => s,
        Err(e) if uri.init => {
            // Initialize a token on whatever slot is offered first.
            // SoftHSM2's slot id can shift after init; re-enumerate
            // post-init to find where the token landed.
            let any_slot = *p11_slot::get_slot_list(false)
                .map_err(ck_error_to_backend)?
                .first()
                .ok_or_else(|| kb::BackendError::Internal(
                    "no PKCS#11 slots available for init".into()))?;
            let so_pin = uri.so_pin.clone()
                .or_else(|| uri.pin.clone())
                .unwrap_or_else(|| "1234".into());
            p11_slot::init_token(any_slot, Some(&so_pin), "pkcs11-bridge")
                .map_err(ck_error_to_backend)?;
            let token_slot = *p11_slot::get_slot_list(true)
                .map_err(ck_error_to_backend)?
                .first()
                .ok_or_else(|| kb::BackendError::Internal(
                    "no token slot after init".into()))?;

            // Become SO + set the user PIN, then close the SO
            // session and reopen for the regular user-login path
            // below.
            let so_sess = p11_slot::open_session(token_slot, flags)
                .map_err(ck_error_to_backend)?;
            so_sess.login(p11_core::UserType::So,
                          p11_util::Credential::Inline(so_pin.as_bytes().to_vec()))
                .map_err(ck_error_to_backend)?;
            let user_pin = uri.pin.clone()
                .unwrap_or_else(|| "1234".into());
            so_sess.init_pin(p11_util::Credential::Inline(
                user_pin.as_bytes().to_vec()))
                .map_err(ck_error_to_backend)?;
            let _ = so_sess.logout();
            let _ = so_sess.close();

            p11_slot::open_session(token_slot, flags)
                .map_err(ck_error_to_backend)?
        }
        Err(e) => return Err(ck_error_to_backend(e)),
    };

    if let Some(pin) = &uri.pin {
        let cred = p11_util::Credential::Inline(pin.as_bytes().to_vec());
        sess.login(p11_core::UserType::User, cred)
            .map_err(ck_error_to_backend)?;
    }
    Ok(sess)
}

/// Generate a fresh ECDSA P-256 or RSA-2048 keypair under the given
/// label on the provided session. Used only on the init=true path.
fn generate_keypair_for(sess: &p11_session::Session, uri: &Pkcs11Uri)
    -> Result<(), kb::BackendError> {
    let label = uri.object.clone().unwrap_or_else(|| "pkcs11-bridge-key".into());
    let algo  = uri.algorithm.as_deref().unwrap_or("ecdsa-p256");
    let id_bytes = uri.id.clone().unwrap_or_else(|| label.as_bytes().to_vec());

    let (mech, pub_template, priv_template) = match algo {
        "ecdsa-p256" => {
            let mech = p11_core::Mechanism {
                kind: ck::CKM_ECDSA_KEY_PAIR_GEN,
                parameter: None,
            };
            let pub_t = vec![
                p11_core::Attribute { tag: ck::CKA_TOKEN,
                    value: p11_core::AttributeValue::Boolean(true) },
                p11_core::Attribute { tag: ck::CKA_VERIFY,
                    value: p11_core::AttributeValue::Boolean(true) },
                p11_core::Attribute { tag: ck::CKA_LABEL,
                    value: p11_core::AttributeValue::ByteString(label.as_bytes().to_vec()) },
                p11_core::Attribute { tag: ck::CKA_ID,
                    value: p11_core::AttributeValue::ByteString(id_bytes.clone()) },
                p11_core::Attribute { tag: ck::CKA_EC_PARAMS,
                    value: p11_core::AttributeValue::ByteString(ck::EC_PARAMS_P256.to_vec()) },
            ];
            let priv_t = vec![
                p11_core::Attribute { tag: ck::CKA_TOKEN,
                    value: p11_core::AttributeValue::Boolean(true) },
                p11_core::Attribute { tag: ck::CKA_PRIVATE,
                    value: p11_core::AttributeValue::Boolean(true) },
                p11_core::Attribute { tag: ck::CKA_SIGN,
                    value: p11_core::AttributeValue::Boolean(true) },
                p11_core::Attribute { tag: ck::CKA_LABEL,
                    value: p11_core::AttributeValue::ByteString(label.as_bytes().to_vec()) },
                p11_core::Attribute { tag: ck::CKA_ID,
                    value: p11_core::AttributeValue::ByteString(id_bytes) },
            ];
            (mech, pub_t, priv_t)
        }
        "rsa-2048" => {
            let mech = p11_core::Mechanism {
                kind: ck::CKM_RSA_PKCS_KEY_PAIR_GEN,
                parameter: None,
            };
            let pub_t = vec![
                p11_core::Attribute { tag: ck::CKA_TOKEN,
                    value: p11_core::AttributeValue::Boolean(true) },
                p11_core::Attribute { tag: ck::CKA_VERIFY,
                    value: p11_core::AttributeValue::Boolean(true) },
                p11_core::Attribute { tag: ck::CKA_LABEL,
                    value: p11_core::AttributeValue::ByteString(label.as_bytes().to_vec()) },
                p11_core::Attribute { tag: ck::CKA_ID,
                    value: p11_core::AttributeValue::ByteString(id_bytes.clone()) },
                p11_core::Attribute { tag: ck::CKA_MODULUS_BITS,
                    value: p11_core::AttributeValue::Uint32(2048) },
                p11_core::Attribute { tag: ck::CKA_PUBLIC_EXPONENT,
                    value: p11_core::AttributeValue::ByteString(vec![0x01, 0x00, 0x01]) },
            ];
            let priv_t = vec![
                p11_core::Attribute { tag: ck::CKA_TOKEN,
                    value: p11_core::AttributeValue::Boolean(true) },
                p11_core::Attribute { tag: ck::CKA_PRIVATE,
                    value: p11_core::AttributeValue::Boolean(true) },
                p11_core::Attribute { tag: ck::CKA_SIGN,
                    value: p11_core::AttributeValue::Boolean(true) },
                p11_core::Attribute { tag: ck::CKA_LABEL,
                    value: p11_core::AttributeValue::ByteString(label.as_bytes().to_vec()) },
                p11_core::Attribute { tag: ck::CKA_ID,
                    value: p11_core::AttributeValue::ByteString(id_bytes) },
            ];
            (mech, pub_t, priv_t)
        }
        other => return Err(kb::BackendError::MechanismNotSupported(
            format!("init=true algorithm={other} -- only ecdsa-p256 / rsa-2048 supported"))),
    };

    sess.generate_key_pair(&mech, &pub_template, &priv_template)
        .map_err(ck_error_to_backend)?;
    Ok(())
}

fn find_object(sess: &p11_session::Session, uri: &Pkcs11Uri, class: u32)
    -> Result<p11_object::Object, kb::BackendError> {
    let mut template = vec![p11_core::Attribute {
        tag: ck::CKA_CLASS,
        value: p11_core::AttributeValue::ObjectKind(class),
    }];
    if let Some(label) = &uri.object {
        template.push(p11_core::Attribute {
            tag: ck::CKA_LABEL,
            value: p11_core::AttributeValue::ByteString(label.as_bytes().to_vec()),
        });
    }
    if let Some(id) = &uri.id {
        template.push(p11_core::Attribute {
            tag: ck::CKA_ID,
            value: p11_core::AttributeValue::ByteString(id.clone()),
        });
    }
    let search = sess.find_objects_init(&template).map_err(ck_error_to_backend)?;
    let handles = search.next(1).map_err(ck_error_to_backend)?;
    let _ = search.finish();
    let handle = handles.into_iter().next().ok_or_else(||
        kb::BackendError::KeyNotFound(format!(
            "no object matched URI (class=0x{:02x}, label={:?}, id={:?})",
            class, uri.object, uri.id)))?;
    sess.bind_object(handle).map_err(ck_error_to_backend)
}

// ===========================================================================
// WIT impl
// ===========================================================================

struct Bridge;
impl kb::Guest for Bridge {
    type Key = Key;
}

/// One Key resource = one PKCS#11 session + one resolved private key
/// object handle + cached algorithm + cached SPKI. The public key is
/// resolved lazily on first public_key_info() call.
struct Key {
    uri: Pkcs11Uri,
    session: p11_session::Session,
    private_obj: p11_object::Object,
    algorithm: RefCell<Option<kb::KeyAlgorithm>>,
    spki_cache: RefCell<Option<Vec<u8>>>,
}

impl kb::GuestKey for Key {
    fn new(uri: String) -> Self {
        // WIT constructors can't return Result. On URI/session failure
        // we panic -- the user's openssl-side request fails fast and
        // the wasmtime trap surfaces the cause through the host
        // adapter's error log. Phase 8 may introduce a `result<key,
        // error>` constructor variant in the WIT to surface this
        // cleanly.
        let parsed = Pkcs11Uri::parse(&uri).unwrap_or_else(|e|
            panic!("pkcs11-bridge: bad URI: {e}"));
        let sess = open_session_for(&parsed).unwrap_or_else(|e|
            panic!("pkcs11-bridge: open-session failed: {:?}", e));
        // First find attempt. If the URI asked for init=true and the
        // private key doesn't exist, generate it then look it up
        // again. Note: open_session_for already handled token
        // provisioning (init_token + init_pin) when init=true.
        let priv_obj = match find_object(&sess, &parsed, ck::CKO_PRIVATE_KEY) {
            Ok(obj) => obj,
            Err(_) if parsed.init => {
                generate_keypair_for(&sess, &parsed).unwrap_or_else(|e|
                    panic!("pkcs11-bridge: keygen failed: {:?}", e));
                find_object(&sess, &parsed, ck::CKO_PRIVATE_KEY).unwrap_or_else(|e|
                    panic!("pkcs11-bridge: post-keygen lookup failed: {:?}", e))
            }
            Err(e) => panic!("pkcs11-bridge: private-key lookup failed: {:?}", e),
        };
        Self {
            uri: parsed,
            session: sess,
            private_obj: priv_obj,
            algorithm: RefCell::new(None),
            spki_cache: RefCell::new(None),
        }
    }

    fn algorithm(&self) -> kb::KeyAlgorithm {
        if let Some(a) = self.algorithm.borrow().clone() { return a; }
        // Resolve from CKA_KEY_TYPE. EC also needs CKA_EC_PARAMS for
        // the curve name; RSA needs CKA_MODULUS for the bit-width.
        let attrs = self.private_obj
            .get_attributes(&[ck::CKA_KEY_TYPE])
            .unwrap_or_default();
        let key_type = attrs.into_iter()
            .find_map(|a| match a.value {
                p11_core::AttributeValue::KeyKind(k)   => Some(k),
                p11_core::AttributeValue::Uint32(k)    => Some(k),
                _                                       => None,
            })
            .unwrap_or(u32::MAX);
        let algo = match key_type {
            ck::CKK_EC => {
                // Phase 4 hardcodes P-256 -- the broader curve list
                // requires parsing CKA_EC_PARAMS' OID against a
                // table. Practical: most TLS PKCS#11 keys are P-256.
                kb::KeyAlgorithm::Ec(kb::EcInfo { curve: "P-256".into() })
            }
            ck::CKK_RSA => {
                // Try to read modulus bits; fall back to 2048 if the
                // token doesn't expose CKA_MODULUS to us.
                let attrs = self.private_obj
                    .get_attributes(&[ck::CKA_MODULUS])
                    .unwrap_or_default();
                let bits = attrs.into_iter()
                    .find_map(|a| match a.value {
                        p11_core::AttributeValue::ByteString(b) => Some(b.len() as u32 * 8),
                        _ => None,
                    })
                    .unwrap_or(2048);
                kb::KeyAlgorithm::Rsa(kb::RsaInfo { modulus_bits: bits })
            }
            _ => kb::KeyAlgorithm::Ec(kb::EcInfo { curve: "P-256".into() }),
        };
        *self.algorithm.borrow_mut() = Some(algo.clone());
        algo
    }

    fn public_key_info(&self) -> Result<Vec<u8>, kb::BackendError> {
        if let Some(spki) = self.spki_cache.borrow().clone() { return Ok(spki); }
        // Find the matching public-key object via the same URI; PKCS#11
        // keypairs share CKA_ID (and often CKA_LABEL), so the search
        // succeeds with class=CKO_PUBLIC_KEY.
        let pub_obj = find_object(&self.session, &self.uri, ck::CKO_PUBLIC_KEY)?;
        let algo = self.algorithm();
        let spki = match algo {
            kb::KeyAlgorithm::Ec(_) => {
                let attrs = pub_obj.get_attributes(&[ck::CKA_EC_PARAMS, ck::CKA_EC_POINT])
                    .map_err(ck_error_to_backend)?;
                let mut params = None;
                let mut point = None;
                for a in attrs {
                    match (a.tag, a.value) {
                        (ck::CKA_EC_PARAMS, p11_core::AttributeValue::ByteString(b)) => params = Some(b),
                        (ck::CKA_EC_POINT,  p11_core::AttributeValue::ByteString(b)) => point = Some(b),
                        _ => {}
                    }
                }
                let p = params.ok_or_else(|| kb::BackendError::Internal(
                    "EC public key missing CKA_EC_PARAMS".into()))?;
                let pt = point.ok_or_else(|| kb::BackendError::Internal(
                    "EC public key missing CKA_EC_POINT".into()))?;
                build_ec_spki(&p, &pt)?
            }
            kb::KeyAlgorithm::Rsa(_) => {
                let attrs = pub_obj.get_attributes(&[ck::CKA_MODULUS, ck::CKA_PUBLIC_EXPONENT])
                    .map_err(ck_error_to_backend)?;
                let mut m = None;
                let mut e = None;
                for a in attrs {
                    match (a.tag, a.value) {
                        (ck::CKA_MODULUS,         p11_core::AttributeValue::ByteString(b)) => m = Some(b),
                        (ck::CKA_PUBLIC_EXPONENT, p11_core::AttributeValue::ByteString(b)) => e = Some(b),
                        _ => {}
                    }
                }
                let m = m.ok_or_else(|| kb::BackendError::Internal(
                    "RSA public key missing CKA_MODULUS".into()))?;
                let e = e.ok_or_else(|| kb::BackendError::Internal(
                    "RSA public key missing CKA_PUBLIC_EXPONENT".into()))?;
                build_rsa_spki(&m, &e)?
            }
            _ => return Err(kb::BackendError::MechanismNotSupported(
                "pkcs11-bridge: only RSA and EC public_key_info implemented".into())),
        };
        *self.spki_cache.borrow_mut() = Some(spki.clone());
        Ok(spki)
    }

    fn signature_wrapping_policy(&self, _mech: kb::SignatureMechanism)
        -> kb::SignatureWrappingPolicy {
        // Tokens want the message form -- the C_SignInit mechanism
        // tells the token to apply the right hash + padding. The
        // *_RAW variants (CKM_RSA_PKCS, CKM_ECDSA) expect already-
        // hashed/wrapped input; mech_to_ckm returns those for the
        // ::Raw digest variants, and the adapter is expected to
        // pre-process accordingly.
        kb::SignatureWrappingPolicy::Raw
    }

    fn sign(&self, tbs: Vec<u8>, mech: kb::SignatureMechanism)
        -> Result<Vec<u8>, kb::BackendError> {
        let ckm = map_signature_mech(&mech)?;
        let mechanism = p11_core::Mechanism { kind: ckm, parameter: None };
        let raw = self.session.sign(&mechanism, &self.private_obj, &tbs)
            .map_err(ck_error_to_backend)?;
        // ECDSA-family mechanisms in PKCS#11 return raw P1363 (r||s).
        // The tegmentum:key-backend WIT contract says ECDSA returns
        // DER -- convert on the way out. Other mechs pass through.
        if matches!(mech, kb::SignatureMechanism::Ecdsa(_)) {
            spki::ecdsa_raw_to_der(&raw)
                .map_err(|e| kb::BackendError::Internal(format!("ECDSA DER: {e}")))
        } else {
            Ok(raw)
        }
    }

    fn verify(&self, tbs: Vec<u8>, signature: Vec<u8>, mech: kb::SignatureMechanism)
        -> Result<bool, kb::BackendError> {
        let ckm = map_signature_mech(&mech)?;
        let mechanism = p11_core::Mechanism { kind: ckm, parameter: None };
        // PKCS#11 verify needs the PUBLIC key object, not the private.
        let pub_obj = find_object(&self.session, &self.uri, ck::CKO_PUBLIC_KEY)?;
        match self.session.verify(&mechanism, &pub_obj, &tbs, &signature) {
            Ok(())  => Ok(true),
            Err(e) => {
                // CKR_SIGNATURE_INVALID / SIGNATURE_LEN_RANGE → false,
                // not an error -- the verify operation itself succeeded.
                let dbg = format!("{:?}", e);
                if dbg.contains("Signature") {
                    Ok(false)
                } else {
                    Err(ck_error_to_backend(e))
                }
            }
        }
    }

    fn decrypt(&self, ciphertext: Vec<u8>, mech: kb::CipherMechanism)
        -> Result<Vec<u8>, kb::BackendError> {
        let ckm = map_cipher_mech(&mech)?;
        let mechanism = p11_core::Mechanism { kind: ckm, parameter: None };
        let buf = self.session.decrypt(&mechanism, &self.private_obj, &ciphertext, 4096)
            .map_err(ck_error_to_backend)?;
        // output-buffer in pkcs11-wit is a record { data, return-code? }
        // Phase 4 assumes the success path returns full data.
        Ok(buf.data)
    }

    fn derive(&self, _peer_public_key: Vec<u8>)
        -> Result<Vec<u8>, kb::BackendError> {
        // ECDH derive needs CKM_ECDH1_DERIVE + a derive template;
        // not in Phase 4. Plumbing exists in pkcs11-session via
        // derive-key. Phase 8.
        Err(kb::BackendError::MechanismNotSupported(
            "pkcs11-bridge: derive (ECDH) not implemented in Phase 4".into()))
    }
}

export!(Bridge);
