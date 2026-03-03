use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use rand::RngCore;
use scrypt::{scrypt, Params};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use zeroize::Zeroize;

// ─── prefixes ────────────────────────────────────────────────────────────────
// full tokens
pub const PFX_V1: &str = "secry:v1:";
pub const PFX_V2: &str = "secry:v2:";
pub const PFX_V3: &str = "secry:v3:";

// compact tokens (sec: prefix, smaller output)
pub const PFX_CV1: &str = "sec:v1:";
pub const PFX_CV2: &str = "sec:v2:";
pub const PFX_CV3: &str = "sec:v3:";

// legacy compat (rwn64 tokens still accepted)
pub const PFX_LEGACY_V1: &str = "rwn64:v1:";
pub const PFX_LEGACY_V2: &str = "rwn64:v2:";
pub const PFX_LEGACY_V3: &str = "rwn64:v3:";

const SL:    usize = 16; // salt  (full)
const SL_C:  usize = 8;  // salt  (compact)
const NL_V1: usize = 12; // nonce v1/v2 (full)
const NL_V3: usize = 24; // nonce v3 (full)
const NL_C:  usize = 8;  // nonce (compact, shared for all algos)
const TL:    usize = 16; // tag
const KL:    usize = 32; // key

// ─── scrypt params ───────────────────────────────────────────────────────────
fn kdf(password: &str, salt: &[u8]) -> [u8; KL] {
    let params = Params::new(14, 8, 1, KL).unwrap(); // N=16384
    let mut key = [0u8; KL];
    scrypt(password.as_bytes(), salt, &params, &mut key).unwrap();
    key
}

// ─── algo enum ───────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Algo { V1, V2, V3 }

impl Algo {
    pub fn prefix(&self, compact: bool) -> &'static str {
        if compact {
            match self { Algo::V1 => PFX_CV1, Algo::V2 => PFX_CV2, Algo::V3 => PFX_CV3 }
        } else {
            match self { Algo::V1 => PFX_V1,  Algo::V2 => PFX_V2,  Algo::V3 => PFX_V3  }
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Algo::V1 => "AES-256-GCM",
            Algo::V2 => "ChaCha20-Poly1305",
            Algo::V3 => "XChaCha20-Poly1305",
        }
    }
    pub fn nonce_len(&self, compact: bool) -> usize {
        if compact { NL_C } else { match self { Algo::V3 => NL_V3, _ => NL_V1 } }
    }
    pub fn salt_len(compact: bool) -> usize {
        if compact { SL_C } else { SL }
    }
}

// ─── detect prefix from token ────────────────────────────────────────────────
pub struct TokenMeta {
    pub algo:    Algo,
    pub compact: bool,
    pub rest:    usize, // byte offset where base64 payload starts
}

pub fn detect(token: &str) -> Option<TokenMeta> {
    let checks: &[(&str, Algo, bool)] = &[
        (PFX_V1,        Algo::V1, false),
        (PFX_V2,        Algo::V2, false),
        (PFX_V3,        Algo::V3, false),
        (PFX_CV1,       Algo::V1, true),
        (PFX_CV2,       Algo::V2, true),
        (PFX_CV3,       Algo::V3, true),
        (PFX_LEGACY_V1, Algo::V1, false),
        (PFX_LEGACY_V2, Algo::V2, false),
        (PFX_LEGACY_V3, Algo::V3, false),
    ];
    for (pfx, algo, compact) in checks {
        if token.starts_with(pfx) {
            return Some(TokenMeta { algo: *algo, compact: *compact, rest: pfx.len() });
        }
    }
    None
}

// ─── encrypt ─────────────────────────────────────────────────────────────────
pub fn encrypt(plaintext: &str, password: &str, algo: Algo, expires_ms: Option<u64>, compact: bool) -> String {
    let sl        = Algo::salt_len(compact);
    let nl        = algo.nonce_len(compact);
    let mut salt  = vec![0u8; sl];
    let mut nonce = vec![0u8; nl];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);

    let mut key = kdf(password, &salt);

    // build inner: [flag(1)] [expires_ms(8)?] [plaintext]
    let mut inner: Vec<u8> = Vec::new();
    if let Some(exp) = expires_ms {
        inner.push(1);
        inner.extend_from_slice(&exp.to_be_bytes());
    } else {
        inner.push(0);
    }
    inner.extend_from_slice(plaintext.as_bytes());

    let ct = match algo {
        Algo::V1 => {
            // AES-GCM needs exactly 12-byte nonce; pad/truncate compact nonce
            let n12 = padded_nonce(&nonce, 12);
            use aes_gcm::Nonce as AesNonce;
            let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
            cipher.encrypt(AesNonce::from_slice(&n12), inner.as_slice()).unwrap()
        }
        Algo::V2 => {
            let n12 = padded_nonce(&nonce, 12);
            use chacha20poly1305::Nonce as ChaNonce;
            let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
            cipher.encrypt(ChaNonce::from_slice(&n12), inner.as_slice()).unwrap()
        }
        Algo::V3 => {
            let n24 = padded_nonce(&nonce, 24);
            use chacha20poly1305::XNonce;
            let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
            cipher.encrypt(XNonce::from_slice(&n24), inner.as_slice()).unwrap()
        }
    };

    key.zeroize();

    // payload: salt + nonce + tag + ct
    // The AEAD crates return ct_with_tag_appended (ct || tag).
    // Node/Python expect tag before ciphertext, so we reorder here.
    let mut payload = Vec::new();
    payload.extend_from_slice(&salt);
    payload.extend_from_slice(&nonce);
    if ct.len() >= TL {
        let (body, tag) = ct.split_at(ct.len() - TL);
        payload.extend_from_slice(tag);  // tag first
        payload.extend_from_slice(body); // then ciphertext
    } else {
        payload.extend_from_slice(&ct);
    }

    format!("{}{}", algo.prefix(compact), URL_SAFE_NO_PAD.encode(&payload))
}

// pads or truncates nonce to target_len (used for compact mode)
fn padded_nonce(n: &[u8], target: usize) -> Vec<u8> {
    let mut v = vec![0u8; target];
    let copy = n.len().min(target);
    v[..copy].copy_from_slice(&n[..copy]);
    v
}

// ─── decrypt ─────────────────────────────────────────────────────────────────
pub struct DecryptResult {
    pub plaintext:     String,
    pub algo:          Algo,
    pub expires_at_ms: Option<u64>,
    pub compact:       bool,
}

pub fn decrypt(token: &str, password: &str) -> Result<DecryptResult, String> {
    let meta = detect(token).ok_or_else(|| "invalid token format".to_string())?;
    let algo    = meta.algo;
    let compact = meta.compact;

    let payload = URL_SAFE_NO_PAD.decode(&token[meta.rest..])
        .map_err(|_| "token is malformed".to_string())?;

    let sl  = Algo::salt_len(compact);
    let nl  = algo.nonce_len(compact);
    let min_len = sl + nl + TL + 2;
    if payload.len() < min_len {
        return Err("token is too short or malformed".into());
    }

    let salt       = &payload[..sl];
    let nonce_raw  = &payload[sl..sl+nl];
    // payload stores tag+ct (tag first); AEAD crates expect ct+tag (tag at end)
    let tag_and_ct = &payload[sl+nl..];
    let ct: Vec<u8> = if tag_and_ct.len() >= TL {
        let (tag, body) = tag_and_ct.split_at(TL);
        let mut v = body.to_vec();
        v.extend_from_slice(tag);
        v
    } else {
        tag_and_ct.to_vec()
    };

    let mut key = kdf(password, salt);

    let inner = match algo {
        Algo::V1 => {
            let n12 = padded_nonce(nonce_raw, 12);
            use aes_gcm::Nonce as AesNonce;
            let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
            cipher.decrypt(AesNonce::from_slice(&n12), ct.as_slice())
                .map_err(|_| "wrong password or corrupted token".to_string())?
        }
        Algo::V2 => {
            let n12 = padded_nonce(nonce_raw, 12);
            use chacha20poly1305::Nonce as ChaNonce;
            let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
            cipher.decrypt(ChaNonce::from_slice(&n12), ct.as_slice())
                .map_err(|_| "wrong password or corrupted token".to_string())?
        }
        Algo::V3 => {
            let n24 = padded_nonce(nonce_raw, 24);
            use chacha20poly1305::XNonce;
            let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
            cipher.decrypt(XNonce::from_slice(&n24), ct.as_slice())
                .map_err(|_| "wrong password or corrupted token".to_string())?
        }
    };

    key.zeroize();

    let has_exp = inner[0] == 1;
    if has_exp {
        let exp = u64::from_be_bytes(inner[1..9].try_into().unwrap());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        if now > exp {
            return Err(format!("token expired at {}", exp));
        }
        let text = String::from_utf8(inner[9..].to_vec())
            .map_err(|_| "invalid utf-8 in plaintext".to_string())?;
        return Ok(DecryptResult { plaintext: text, algo, expires_at_ms: Some(exp), compact });
    }

    let text = String::from_utf8(inner[1..].to_vec())
        .map_err(|_| "invalid utf-8 in plaintext".to_string())?;
    Ok(DecryptResult { plaintext: text, algo, expires_at_ms: None, compact })
}

// ─── verify ──────────────────────────────────────────────────────────────────
pub fn verify(token: &str, password: &str) -> bool {
    decrypt(token, password).is_ok()
}
