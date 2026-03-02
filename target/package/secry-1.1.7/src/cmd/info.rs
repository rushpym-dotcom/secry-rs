use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use crate::crypto::{PFX_V1, PFX_V2, PFX_V3, PFX_CV1, PFX_CV2, PFX_CV3,
                    PFX_LEGACY_V1, PFX_LEGACY_V2, PFX_LEGACY_V3};
use crate::ui;

pub fn run(token: &str) {
    // (prefix, version_label, algo_name, compact, legacy)
    let checks: &[(&str, &str, &str, bool, bool)] = &[
        (PFX_V3,        "v3", "XChaCha20-Poly1305",  false, false),
        (PFX_V2,        "v2", "ChaCha20-Poly1305",   false, false),
        (PFX_V1,        "v1", "AES-256-GCM",         false, false),
        (PFX_CV3,       "v3", "XChaCha20-Poly1305",  true,  false),
        (PFX_CV2,       "v2", "ChaCha20-Poly1305",   true,  false),
        (PFX_CV1,       "v1", "AES-256-GCM",         true,  false),
        (PFX_LEGACY_V3, "v3", "XChaCha20-Poly1305",  false, true),
        (PFX_LEGACY_V2, "v2", "ChaCha20-Poly1305",   false, true),
        (PFX_LEGACY_V1, "v1", "AES-256-GCM",         false, true),
        ("secry:s1:",   "s1", "HMAC-SHA256 / scrypt (seal)", false, false),
        ("secry:s2:",   "s2", "BLAKE3 / scrypt (seal)",      false, false),
        ("sec:s1:",     "s1", "HMAC-SHA256 / scrypt (seal)", true,  false),
        ("sec:s2:",     "s2", "BLAKE3 / scrypt (seal)",      true,  false),
        ("rwn64:s1:",   "s1", "HMAC-SHA256 / scrypt (seal)", false, true),
        ("rwn64:s2:",   "s2", "BLAKE3 / scrypt (seal)",      false, true),
    ];

    let found = checks.iter().find(|(pfx, ..)| token.starts_with(pfx));
    let (pfx, ver, algo, compact, legacy) = match found {
        Some(t) => t,
        None => { ui::err("invalid token format"); std::process::exit(1); }
    };

    let Ok(payload) = URL_SAFE_NO_PAD.decode(&token[pfx.len()..]) else {
        ui::err("token is malformed"); std::process::exit(1);
    };

    let salt_len = if *compact { 8 } else { 16 };
    let nl = if *compact { 8 } else if *ver == "v3" { 24 } else { 12 };
    let salt_hex  = hex::encode(&payload[..salt_len.min(payload.len())]);
    let nonce_hex = if payload.len() >= salt_len + nl {
        hex::encode(&payload[salt_len..salt_len+nl])
    } else { "—".into() };

    let mode = if *compact { "compact (sec:)" } else { "full (secry:)" };
    let legacy_note = if *legacy { "yes — rwn64 token" } else { "no" };

    ui::section("info");
    ui::box_print(&[
        ("version",       ver),
        ("algo",          algo),
        ("mode",          mode),
        ("legacy",        legacy_note),
        ("kdf",           "scrypt (N=16384, r=8, p=1)"),
        ("salt",          &salt_hex),
        ("nonce",         &nonce_hex),
        ("payload bytes", &payload.len().to_string()),
    ]);
}
