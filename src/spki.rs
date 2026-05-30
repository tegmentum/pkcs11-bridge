//! Minimal hand-written DER assembly for SubjectPublicKeyInfo. We
//! emit the standard X.509 SPKI structure for EC and RSA -- the
//! only two key types Phase 4 surfaces from PKCS#11 tokens.
//!
//! The full DER ecosystem (`der`, `spki`, `const-oid`) was avoided
//! because its derive-macro + lifetime model didn't sit cleanly
//! with wit-bindgen-rt's generated owned types. A direct encoder is
//! 80 lines and has no transitive deps.

/// id-ecPublicKey -- 1.2.840.10045.2.1
const OID_ID_EC_PUBLIC_KEY: &[u8] = &[
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
];
/// rsaEncryption -- 1.2.840.113549.1.1.1
const OID_RSA_ENCRYPTION: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
];
/// NULL
const DER_NULL: &[u8] = &[0x05, 0x00];

/// Wrap `content` in a SEQUENCE tag (0x30).
fn der_seq(content: &[u8]) -> Vec<u8> {
    wrap(0x30, content)
}

/// Wrap `content` in a BIT STRING tag (0x03) with 0 unused bits.
fn der_bit_string(content: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(content.len() + 1);
    body.push(0x00);  // unused-bits count
    body.extend_from_slice(content);
    wrap(0x03, &body)
}

/// Encode a positive integer (raw big-endian bytes) as a DER INTEGER,
/// prepending a 0x00 byte if the high bit would otherwise make it
/// negative (the canonical RSA modulus / exponent encoding).
fn der_integer(big_endian: &[u8]) -> Vec<u8> {
    // Strip leading zeros, then re-add ONE leading zero if the high
    // bit of the first remaining byte is set.
    let mut start = 0;
    while start + 1 < big_endian.len() && big_endian[start] == 0 {
        start += 1;
    }
    let trimmed = &big_endian[start..];
    let mut body = Vec::with_capacity(trimmed.len() + 1);
    if !trimmed.is_empty() && trimmed[0] & 0x80 != 0 {
        body.push(0x00);
    }
    body.extend_from_slice(trimmed);
    wrap(0x02, &body)
}

/// Generic tag-length-value wrapper. Length uses the canonical
/// short-form (<128) or long-form (1-4 length-of-length bytes).
fn wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81); out.push(len as u8);
    } else if len < 0x10000 {
        out.push(0x82);
        out.push((len >> 8) as u8); out.push(len as u8);
    } else if len < 0x1000000 {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8)  as u8);
        out.push(len as u8);
    } else {
        out.push(0x84);
        out.push((len >> 24) as u8);
        out.push((len >> 16) as u8);
        out.push((len >> 8)  as u8);
        out.push(len as u8);
    }
    out.extend_from_slice(content);
    out
}

/// Strip the DER OCTET STRING wrapper from `der_bytes`, returning
/// the contained bytes. PKCS#11's CKA_EC_POINT is conventionally
/// returned as a DER-wrapped OCTET STRING around the SEC1 point.
pub fn strip_octet_string(der_bytes: &[u8]) -> Result<&[u8], &'static str> {
    if der_bytes.len() < 2 || der_bytes[0] != 0x04 {
        return Err("CKA_EC_POINT not an OCTET STRING");
    }
    let (len, hdr) = if der_bytes[1] & 0x80 == 0 {
        (der_bytes[1] as usize, 2usize)
    } else {
        let nb = (der_bytes[1] & 0x7f) as usize;
        if der_bytes.len() < 2 + nb { return Err("truncated OCTET STRING length"); }
        let mut v = 0usize;
        for i in 0..nb { v = (v << 8) | der_bytes[2 + i] as usize; }
        (v, 2 + nb)
    };
    if der_bytes.len() < hdr + len { return Err("truncated OCTET STRING value"); }
    Ok(&der_bytes[hdr..hdr + len])
}

/// Build an EC SubjectPublicKeyInfo:
///   SEQUENCE {
///     SEQUENCE { id-ecPublicKey, ECParameters }
///     BIT STRING(0 unused bits) { SEC1 point }
///   }
///
/// `ec_params_der`: raw bytes of CKA_EC_PARAMS (named-curve OID).
/// `ec_point_der`:  raw bytes of CKA_EC_POINT (OCTET STRING wrapping
/// the SEC1 uncompressed point).
pub fn build_ec_spki(ec_params_der: &[u8], ec_point_der: &[u8])
    -> Result<Vec<u8>, &'static str> {
    let point = strip_octet_string(ec_point_der)?;
    // AlgorithmIdentifier = SEQUENCE { OID, params }
    let mut alg_id = Vec::with_capacity(OID_ID_EC_PUBLIC_KEY.len() + ec_params_der.len());
    alg_id.extend_from_slice(OID_ID_EC_PUBLIC_KEY);
    alg_id.extend_from_slice(ec_params_der);
    let alg = der_seq(&alg_id);
    let bits = der_bit_string(point);
    let mut spki = Vec::with_capacity(alg.len() + bits.len());
    spki.extend_from_slice(&alg);
    spki.extend_from_slice(&bits);
    Ok(der_seq(&spki))
}

/// Build an RSA SubjectPublicKeyInfo:
///   SEQUENCE {
///     SEQUENCE { rsaEncryption, NULL }
///     BIT STRING(0 unused bits) {
///       SEQUENCE { INTEGER modulus, INTEGER exponent }
///     }
///   }
pub fn build_rsa_spki(modulus: &[u8], public_exponent: &[u8]) -> Vec<u8> {
    // RSAPublicKey
    let m = der_integer(modulus);
    let e = der_integer(public_exponent);
    let mut rsa_pub = Vec::with_capacity(m.len() + e.len());
    rsa_pub.extend_from_slice(&m);
    rsa_pub.extend_from_slice(&e);
    let rsa_pub_seq = der_seq(&rsa_pub);

    // AlgorithmIdentifier = SEQUENCE { rsaEncryption, NULL }
    let mut alg_id = Vec::with_capacity(OID_RSA_ENCRYPTION.len() + DER_NULL.len());
    alg_id.extend_from_slice(OID_RSA_ENCRYPTION);
    alg_id.extend_from_slice(DER_NULL);
    let alg = der_seq(&alg_id);

    let bits = der_bit_string(&rsa_pub_seq);

    let mut spki = Vec::with_capacity(alg.len() + bits.len());
    spki.extend_from_slice(&alg);
    spki.extend_from_slice(&bits);
    der_seq(&spki)
}
