use hmac::{Hmac, Mac};
use sha2::Sha256;
use crate::ui;

type HmacSha256 = Hmac<Sha256>;

pub fn run(text: &str, secret: &str) {
    let t0  = std::time::Instant::now();
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(text.as_bytes());
    let fp  = hex::encode(&mac.finalize().into_bytes()[..8]);
    let ms  = t0.elapsed().as_millis();
    ui::section("fingerprint");
    ui::box_print(&[
        ("input", &text[..text.len().min(52)]),
        ("algo",  "HMAC-SHA256"),
        ("fp",    &fp),
    ]);
    ui::ms(ms);
    println!("{}", fp);
}