use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use aes_gcm::aead::generic_array::GenericArray;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use scrypt::{scrypt, Params};
use rand::RngCore;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use crate::ui;

type HmacSha256 = Hmac<Sha256>;

const PFX_SE:  &str = "secry:se:";
const PFX_SEI: &str = "secry:sei:";
const CPX_SE:  &str = "sec:se:";
const CPX_SEI: &str = "sec:sei:";

const MAX_IPS: usize = 5;
const SL:  usize = 16; // salt full
const SL_C: usize = 8; // salt compact
const NL:  usize = 12; // nonce AES-GCM
const TL:  usize = 16; // tag GCM

fn kdf(password: &str, salt: &[u8]) -> [u8; 32] {
    let params = Params::new(14, 8, 1, 32).unwrap();
    let mut key = [0u8; 32];
    scrypt(password.as_bytes(), salt, &params, &mut key).unwrap();
    key
}

fn local_ip() -> String {
    use std::net::UdpSocket;
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| { s.connect("8.8.8.8:80")?; s.local_addr() })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".to_string())
}

fn hmac_ip(key: &[u8], ip: &str) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).unwrap();
    mac.update(ip.as_bytes());
    mac.finalize().into_bytes().into()
}

fn seal_enc_inner(value: &str, password: &str, ips: &[String], compact: bool) -> String {
    let sl = if compact { SL_C } else { SL };
    let mut salt  = vec![0u8; sl];
    let mut nonce = vec![0u8; NL];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);

    let key = kdf(password, &salt);

    // inner: [flag(1)] [count(1)] [hmac_1(32)] ... [hmac_n(32)] [value_utf8]
    let mut inner: Vec<u8> = Vec::new();
    if !ips.is_empty() {
        inner.push(0x01);
        inner.push(ips.len() as u8);
        for ip in ips {
            inner.extend_from_slice(&hmac_ip(&key, ip));
        }
    } else {
        inner.push(0x00);
        inner.push(0x00);
    }
    inner.extend_from_slice(value.as_bytes());

    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let nonce_arr = GenericArray::from_slice(&nonce);
    let ct_with_tag = cipher.encrypt(nonce_arr, inner.as_slice()).unwrap();
    // aes-gcm appends tag at end: ct_with_tag = ciphertext + tag(16)
    let ct_len = ct_with_tag.len() - TL;
    let ct  = &ct_with_tag[..ct_len];
    let tag = &ct_with_tag[ct_len..];

    let pfx = if !ips.is_empty() {
        if compact { CPX_SEI } else { PFX_SEI }
    } else {
        if compact { CPX_SE } else { PFX_SE }
    };

    // payload: salt + nonce + tag + ciphertext  (same order as Node.js/Python)
    let mut payload = Vec::new();
    payload.extend_from_slice(&salt);
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(tag);
    payload.extend_from_slice(ct);

    format!("{}{}", pfx, URL_SAFE_NO_PAD.encode(&payload))
}

fn seal_open_inner(token: &str, password: &str, ip: Option<&str>) -> Result<String, String> {
    let (pfx, sl, _has_ip) = if token.starts_with(PFX_SEI) {
        (PFX_SEI, SL, true)
    } else if token.starts_with(CPX_SEI) {
        (CPX_SEI, SL_C, true)
    } else if token.starts_with(PFX_SE) {
        (PFX_SE, SL, false)
    } else if token.starts_with(CPX_SE) {
        (CPX_SE, SL_C, false)
    } else {
        return Err("invalid seal-enc token".to_string());
    };

    let payload = URL_SAFE_NO_PAD.decode(&token[pfx.len()..])
        .map_err(|_| "invalid base64".to_string())?;

    if payload.len() < sl + NL + TL + 2 {
        return Err("token too short".to_string());
    }

    let salt  = &payload[..sl];
    let nonce = &payload[sl..sl + NL];
    let tag   = &payload[sl + NL..sl + NL + TL];
    let ct    = &payload[sl + NL + TL..];

    let key = kdf(password, salt);

    // reconstruct ct_with_tag for aes-gcm (expects ct || tag)
    let mut ct_with_tag = ct.to_vec();
    ct_with_tag.extend_from_slice(tag);

    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let nonce_arr = GenericArray::from_slice(nonce);
    let inner = cipher.decrypt(nonce_arr, ct_with_tag.as_slice())
        .map_err(|_| "wrong password or corrupted token".to_string())?;

    if inner.len() < 2 {
        return Err("corrupted token".to_string());
    }

    let flag  = inner[0];
    let count = inner[1] as usize;

    if flag == 0x01 {
        // IP-bound token
        let needed = 2 + count * 32;
        if inner.len() < needed {
            return Err("corrupted token".to_string());
        }
        let cur_ip = match ip {
            Some(i) => i.to_string(),
            None    => local_ip(),
        };
        let cur_hmac = hmac_ip(&key, &cur_ip);
        let mut matched = false;
        for i in 0..count {
            let stored = &inner[2 + i * 32..2 + (i + 1) * 32];
            // timing-safe compare
            let ok = stored.iter().zip(cur_hmac.iter()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
            if ok { matched = true; break; }
        }
        if !matched {
            return Err("access denied".to_string());
        }
        let value = std::str::from_utf8(&inner[needed..])
            .map_err(|_| "invalid utf8".to_string())?;
        Ok(value.to_string())
    } else {
        let value = std::str::from_utf8(&inner[2..])
            .map_err(|_| "invalid utf8".to_string())?;
        Ok(value.to_string())
    }
}

// ── public run ────────────────────────────────────────────────────────────────

/// ip_flags: raw --ip args. Empty vec = no IP. [""] = auto-detect. ["1.2.3.4", ...] = fixed IPs.
pub fn run(text: &str, password: &str, ip_flags: &[String], ip_auto: bool, ip_force: bool, quiet: bool, compact: bool) {
    let t0 = std::time::Instant::now();

    // resolve IPs list
    let ips: Vec<String> = if ip_auto && ip_flags.is_empty() {
        vec![local_ip()]
    } else {
        ip_flags.to_vec()
    };

    if !ip_force && ips.len() > MAX_IPS {
        ui::err(&format!("max {} IPs allowed — use --ipf to override", MAX_IPS));
        std::process::exit(1);
    }

    let token = seal_enc_inner(text, password, &ips, compact);
    let ms = t0.elapsed().as_millis();

    if !quiet {
        let ip_str = if ips.is_empty() {
            "none".to_string()
        } else {
            ips.join(", ")
        };
        let max_val = 52.min(text.len());
        ui::box_print(&[
            ("input",   &text[..max_val]),
            ("algo",    "AES-256-GCM / scrypt"),
            ("mode",    if compact { "compact (sec:)" } else { "full (secry:)" }),
            ("ip",      &ip_str),
            ("token",   &token),
        ]);
        ui::ms(ms);
    }

    println!("{}", token);
}

pub fn run_open(token: &str, password: &str, ip: Option<&str>, quiet: bool) {
    let t0 = std::time::Instant::now();

    match seal_open_inner(token, password, ip) {
        Ok(value) => {
            let ms = t0.elapsed().as_millis();
            if !quiet {
                let max_val = 52.min(value.len());
                ui::box_print(&[
                    ("result", "ok"),
                    ("value",  &value[..max_val]),
                ]);
                ui::ms(ms);
            }
            println!("{}", value);
        }
        Err(e) => {
            ui::err(&e);
            std::process::exit(1);
        }
    }
}
