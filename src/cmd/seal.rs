use hmac::{Hmac, Mac};
use sha2::Sha256;
use blake3;
use scrypt::{scrypt, Params};
use rand::RngCore;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use crate::ui;

type HmacSha256 = Hmac<Sha256>;

// full prefixes
const PFX_S1: &str = "secry:s1:";
const PFX_S2: &str = "secry:s2:";
// compact prefixes
const PFX_CS1: &str = "sec:s1:";
const PFX_CS2: &str = "sec:s2:";
// legacy compat
const PFX_LEGACY_S1: &str = "rwn64:s1:";
const PFX_LEGACY_S2: &str = "rwn64:s2:";

const PEPPER: &str = "enclove.secry.s2.pepper.v1";

// ── public run ────────────────────────────────────────────────────────────────

pub fn run(text: &str, secret: &str, quiet: bool, use_s2: bool, compact: bool) {
    let t0    = std::time::Instant::now();
    let token = if use_s2 { seal_s2(text, secret, compact) } else { seal_s1(text, secret, compact) };
    let ms    = t0.elapsed().as_millis();
    let algo  = if use_s2 { "BLAKE3 / scrypt N=2^16" } else { "HMAC-SHA256 / scrypt" };

    if !quiet {
        ui::section("seal");
        ui::box_print(&[
            ("input",   &text[..text.len().min(52)]),
            ("algo",    algo),
            ("version", if use_s2 { "s2" } else { "s1" }),
            ("mode",    if compact { "compact (sec:)" } else { "full (secry:)" }),
            ("note",    "one-way — cannot be reversed"),
            ("token",   &token),
        ]);
        ui::ms(ms);
    }

    println!("{}", token);
    if !use_s2 && !quiet {
        eprintln!("  \x1b[33m!\x1b[0m  s1 is less secure — consider using --s2 for stronger protection");
    }
}

pub fn run_verify(text: &str, secret: &str, token: &str, quiet: bool) {
    let t0 = std::time::Instant::now();
    let (ok, version, compact) = if token.starts_with(PFX_S2) || token.starts_with(PFX_CS2) || token.starts_with(PFX_LEGACY_S2) {
        (verify_s2(text, secret, token), "s2", token.starts_with(PFX_CS2))
    } else {
        (verify_s1(text, secret, token), "s1", token.starts_with(PFX_CS1))
    };
    let ms = t0.elapsed().as_millis();

    if !quiet {
        ui::section("seal verify");
        ui::box_print(&[
            ("input",   &text[..text.len().min(52)]),
            ("version", version),
            ("mode",    if compact { "compact" } else { "full" }),
            ("result",  if ok { "match" } else { "no match" }),
        ]);
        ui::ms(ms);
    }

    if !ok { std::process::exit(1); }
}

// ── s1: HMAC-SHA256 / scrypt N=2^14 ─────────────────────────────────────────

fn seal_s1(input: &str, secret: &str, compact: bool) -> String {
    let salt_len = if compact { 8 } else { 16 };
    let out_len  = if compact { 16 } else { 32 };
    let pfx      = if compact { PFX_CS1 } else { PFX_S1 };

    let mut salt = vec![0u8; salt_len];
    rand::thread_rng().fill_bytes(&mut salt);
    let params = Params::new(14, 8, 1, 32).unwrap();
    let mut key = [0u8; 32];
    scrypt(secret.as_bytes(), &salt, &params, &mut key).unwrap();
    let mut mac = HmacSha256::new_from_slice(&key).unwrap();
    mac.update(input.as_bytes());
    let result = mac.finalize().into_bytes();
    let mut payload = Vec::new();
    payload.extend_from_slice(&salt);
    payload.extend_from_slice(&result[..out_len]);
    format!("{}{}", pfx, URL_SAFE_NO_PAD.encode(&payload))
}

fn verify_s1(input: &str, secret: &str, token: &str) -> bool {
    let (pfx, compact) = if token.starts_with(PFX_CS1) {
        (PFX_CS1, true)
    } else if token.starts_with(PFX_S1) {
        (PFX_S1, false)
    } else if token.starts_with(PFX_LEGACY_S1) {
        (PFX_LEGACY_S1, false)
    } else {
        return false;
    };

    let Ok(payload) = URL_SAFE_NO_PAD.decode(&token[pfx.len()..]) else { return false; };
    let salt_len = if compact { 8 } else { 16 };
    let out_len  = if compact { 16 } else { 32 };
    if payload.len() < salt_len + out_len { return false; }
    let salt = &payload[..salt_len];
    let mac  = &payload[salt_len..];

    let params = Params::new(14, 8, 1, 32).unwrap();
    let mut key = [0u8; 32];
    scrypt(secret.as_bytes(), salt, &params, &mut key).unwrap();
    let mut h = HmacSha256::new_from_slice(&key).unwrap();
    h.update(input.as_bytes());
    let expected = h.finalize().into_bytes();
    mac == &expected[..out_len]
}

// ── s2: BLAKE3 / scrypt N=2^16 ───────────────────────────────────────────────

fn seal_s2(input: &str, secret: &str, compact: bool) -> String {
    let salt_len = if compact { 8 } else { 32 };
    let out_len  = if compact { 16 } else { 64 };
    let pfx      = if compact { PFX_CS2 } else { PFX_S2 };

    let mut salt = vec![0u8; salt_len];
    rand::thread_rng().fill_bytes(&mut salt);

    let peppered = format!("{}{}", PEPPER, secret);
    let params = Params::new(16, 8, 1, 32).unwrap();
    let mut key = [0u8; 32];
    scrypt(peppered.as_bytes(), &salt, &params, &mut key).unwrap();

    let mut out = vec![0u8; out_len];
    let mut xof = blake3::Hasher::new_keyed(&key);
    xof.update(input.as_bytes());
    xof.finalize_xof().fill(&mut out);

    let mut payload = Vec::new();
    payload.extend_from_slice(&salt);
    payload.extend_from_slice(&out);
    format!("{}{}", pfx, URL_SAFE_NO_PAD.encode(&payload))
}

fn verify_s2(input: &str, secret: &str, token: &str) -> bool {
    let (pfx, compact) = if token.starts_with(PFX_CS2) {
        (PFX_CS2, true)
    } else if token.starts_with(PFX_S2) {
        (PFX_S2, false)
    } else if token.starts_with(PFX_LEGACY_S2) {
        (PFX_LEGACY_S2, false)
    } else {
        return false;
    };

    let Ok(payload) = URL_SAFE_NO_PAD.decode(&token[pfx.len()..]) else { return false; };
    let salt_len = if compact { 8 } else { 32 };
    let out_len  = if compact { 16 } else { 64 };
    if payload.len() < salt_len + out_len { return false; }
    let salt = &payload[..salt_len];
    let mac  = &payload[salt_len..];

    let peppered = format!("{}{}", PEPPER, secret);
    let params = Params::new(16, 8, 1, 32).unwrap();
    let mut key = [0u8; 32];
    scrypt(peppered.as_bytes(), salt, &params, &mut key).unwrap();

    let mut expected = vec![0u8; out_len];
    let mut xof = blake3::Hasher::new_keyed(&key);
    xof.update(input.as_bytes());
    xof.finalize_xof().fill(&mut expected);

    mac == expected.as_slice()
}
