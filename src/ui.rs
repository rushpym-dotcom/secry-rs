const G: &str = "\x1b[38;5;245m";
const R: &str = "\x1b[0m";
const B: &str = "\x1b[1m";
const C: &str = "\x1b[36m";
const H: &str = "\x1b[38;5;252m";
const RED: &str = "\x1b[31m";

pub fn section(_name: &str) {
    eprintln!();
}

pub fn box_print(rows: &[(&str, &str)]) {
    let lw = rows.iter().map(|(k,_)| k.len()).max().unwrap_or(0);
    eprintln!("  {G}┌{}┐{R}", "─".repeat(lw + 32));
    for (k, v) in rows {
        let pad = " ".repeat(lw - k.len() + 2);
        eprintln!("  {G}│{R}  {G}{k}{R}{pad}{H}{v}{R}");
    }
    eprintln!("  {G}└{}┘{R}", "─".repeat(lw + 32));
}

pub fn token(t: &str) {
    eprintln!("\n  {B}{C}token{R}\n  {H}{t}{R}\n");
}

pub fn pw(p: &str) {
    eprintln!("  {H}{p}{R}");
}

pub fn ms(ms: u128) {
    eprintln!("  {G}done in {ms}ms{R}\n");
}

pub fn err(msg: &str) {
    eprintln!("\n  {RED}✘{R}  {msg}\n");
}