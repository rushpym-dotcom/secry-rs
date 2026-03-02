use crate::crypto::{encrypt, Algo};
use crate::ui;

pub fn run(text: &str, password: &str, algo: Algo, expires: Option<&str>, compact: bool) {
    let expires_ms = expires.map(|e| parse_expiry(e).unwrap_or_else(|err| {
        ui::err(&err); std::process::exit(1);
    }));
    let t0    = std::time::Instant::now();
    let token = encrypt(text, password, algo, expires_ms, compact);
    let ms    = t0.elapsed().as_millis();
    ui::section("encrypt");
    ui::box_print(&[
        ("algo",    algo.name()),
        ("mode",    if compact { "compact (sec:)" } else { "full (secry:)" }),
        ("pw",      "inline"),
    ]);
    ui::token(&token);
    ui::ms(ms);
    println!("{}", token);
}

fn parse_expiry(raw: &str) -> Result<u64, String> {
    let raw = raw.trim();
    let (num, unit) = raw.split_at(raw.len() - 1);
    let n: u64 = num.parse().map_err(|_| format!("invalid expiry: {}", raw))?;
    let ms = match unit {
        "s" => n * 1_000,
        "m" => n * 60_000,
        "h" => n * 3_600_000,
        "d" => n * 86_400_000,
        _   => return Err(format!("invalid expiry unit: {} — use s, m, h, d", unit)),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    Ok(now + ms)
}
