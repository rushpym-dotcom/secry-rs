use rand::RngCore;
use crate::ui;

const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn run(nbytes: usize, upper: bool, count: usize) {
    let t0 = std::time::Instant::now();
    let passwords: Vec<String> = (0..count).map(|_| gen(nbytes, upper)).collect();
    let ms    = t0.elapsed().as_millis();
    let bits  = (nbytes as f64 * 5.954) as u64;
    let level = match bits {
        b if b >= 256 => "extreme",
        b if b >= 128 => "very strong",
        b if b >= 80  => "strong",
        b if b >= 60  => "good",
        _             => "weak",
    };
    ui::section("generate password");
    ui::box_print(&[
        ("bytes",   &nbytes.to_string()),
        ("entropy", &format!("{} bits  — {}", bits, level)),
        ("upper",   if upper { "yes" } else { "no" }),
        ("count",   &count.to_string()),
    ]);
    for pw in &passwords {
        ui::pw(pw);
    }
    ui::ms(ms);
    for pw in &passwords {
        println!("{}", pw);
    }
}

fn gen(nbytes: usize, upper: bool) -> String {
    let mut buf = vec![0u8; nbytes];
    rand::thread_rng().fill_bytes(&mut buf);
    let mut pw: String = buf.iter().map(|b| CHARS[(b % 64) as usize] as char).collect();
    if upper && !pw.chars().any(|c| c.is_uppercase()) {
        let mut rb = [0u8; 1];
        rand::thread_rng().fill_bytes(&mut rb);
        let i = (rb[0] as usize) % pw.len();
        let ch = pw.chars().nth(i).unwrap().to_uppercase().next().unwrap();
        pw.replace_range(i..i+1, &ch.to_string());
    }
    pw
}