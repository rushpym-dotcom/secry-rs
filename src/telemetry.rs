use std::fs;
use std::path::PathBuf;
use std::io::{self, Write};

const AXIOM_TOKEN: &str = "xaat-8f8ce756-f5da-4907-a3ee-e33cdf727013";
const AXIOM_DATASET: &str = "secry-events";
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn config_path() -> Option<PathBuf> {
    dirs_next::config_dir().map(|d| d.join("secry").join("telemetry"))
}

/// Returns true if telemetry is enabled
pub fn is_enabled() -> bool {
    match config_path() {
        Some(p) => fs::read_to_string(p).map(|s| s.trim() == "1").unwrap_or(false),
        None => false,
    }
}

fn set_enabled(enabled: bool) {
    if let Some(p) = config_path() {
        if let Some(parent) = p.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(p, if enabled { "1" } else { "0" });
    }
}

/// Ask user on first run. Returns true if should proceed normally.
pub fn maybe_ask() {
    if config_path().and_then(|p| fs::read_to_string(p).ok()).is_some() {
        return; // already answered
    }

    eprint!(
        "\n  \x1b[38;5;245m┌────────────────────────────────────────────┐\x1b[0m\n"
    );
    eprint!(
        "  \x1b[38;5;245m│\x1b[0m  \x1b[1mHelp improve secry?\x1b[0m                        \x1b[38;5;245m│\x1b[0m\n"
    );
    eprint!(
        "  \x1b[38;5;245m│\x1b[0m  Share anonymous usage data (commands only). \x1b[38;5;245m│\x1b[0m\n"
    );
    eprint!(
        "  \x1b[38;5;245m│\x1b[0m  No tokens, passwords or IPs are collected.  \x1b[38;5;245m│\x1b[0m\n"
    );
    eprint!(
        "  \x1b[38;5;245m└────────────────────────────────────────────┘\x1b[0m\n"
    );
    eprint!("  \x1b[36m?\x1b[0m  Enable telemetry? \x1b[38;5;245m[y/N]\x1b[0m  ");
    let _ = io::stderr().flush();

    let mut input = String::new();
    let _ = io::stdin().read_line(&mut input);
    let accepted = input.trim().eq_ignore_ascii_case("y");
    set_enabled(accepted);

    if accepted {
        eprintln!("  \x1b[32m✔\x1b[0m  Thanks! You can disable with: secry telemetry --disable\n");
    } else {
        eprintln!("  \x1b[38;5;245m–\x1b[0m  Skipped. Enable later with: secry telemetry --enable\n");
    }
}

/// Send event in background (fire and forget, never blocks)
pub fn track(command: &str) {
    if !is_enabled() { return; }

    let os = std::env::consts::OS;
    let body = format!(
        r#"[{{"command":"{command}","version":"{VERSION}","os":"{os}"}}]"#
    );
    let url = format!("https://api.axiom.co/v1/datasets/{AXIOM_DATASET}/ingest");
    let token = AXIOM_TOKEN.to_string();

    std::thread::spawn(move || {
        let _ = ureq::post(&url)
            .set("Authorization", &format!("Bearer {token}"))
            .set("Content-Type", "application/json")
            .send_string(&body);
    });
}
