use std::collections::HashMap;

const AXIOM_TOKEN:   &str = "xaat-f4db5102-781b-4a60-bb9a-61155d74b897";
const AXIOM_DATASET: &str = "secry-events";
const IW:            usize = 44;
const BAR_W:         usize = 16;

struct Event {
    command: String,
    os:      String,
    version: String,
}

fn adm_path() -> std::path::PathBuf {
    dirs_next::home_dir()
        .unwrap_or_default()
        .join(".secry")
        .join(".adm")
}

fn setup_password() {
    let pw1 = rpassword::prompt_password("  new admin password: ").unwrap_or_default();
    if pw1.len() < 4 {
        eprintln!("\n  \x1b[31m✘\x1b[0m  password too short\n");
        std::process::exit(1);
    }
    let pw2 = rpassword::prompt_password("  confirm password: ").unwrap_or_default();
    if pw1 != pw2 {
        eprintln!("\n  \x1b[31m✘\x1b[0m  passwords don't match\n");
        std::process::exit(1);
    }
    let hash = bcrypt::hash(&pw1, bcrypt::DEFAULT_COST).unwrap_or_else(|_| {
        eprintln!("\n  \x1b[31m✘\x1b[0m  failed to hash password\n");
        std::process::exit(1);
    });
    let path = adm_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&path, &hash).unwrap_or_else(|_| {
        eprintln!("\n  \x1b[31m✘\x1b[0m  failed to save password\n");
        std::process::exit(1);
    });
    // restrict permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    eprintln!("\n  \x1b[32m✔\x1b[0m  admin password set\n");
}

fn verify_password() -> bool {
    let path = adm_path();
    if !path.exists() {
        eprintln!("\n  \x1b[33m!\x1b[0m  no admin password set. run: secry analysis --setup\n");
        std::process::exit(1);
    }
    let stored = std::fs::read_to_string(&path).unwrap_or_default();
    let stored  = stored.trim();
    let pw = rpassword::prompt_password("  admin password: ").unwrap_or_default();
    bcrypt::verify(&pw, stored).unwrap_or(false)
}

fn fetch_events() -> Vec<Event> {
    let end   = chrono::Utc::now();
    let start = end - chrono::Duration::days(30);
    let apl   = format!("['{}']", AXIOM_DATASET);

    let body = serde_json::json!({
        "apl":       apl,
        "startTime": start.to_rfc3339(),
        "endTime":   end.to_rfc3339(),
    });

    let resp = match ureq::post("https://api.axiom.co/v1/datasets/_apl?format=legacy")
        .set("Authorization", &format!("Bearer {}", AXIOM_TOKEN))
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())
    {
        Ok(r)  => r,
        Err(_) => return vec![],
    };

    let body = resp.into_string().unwrap_or_default();
    let json: serde_json::Value = match serde_json::from_str(&body) {
        Ok(j)  => j,
        Err(_) => return vec![],
    };

    let matches = match json["matches"].as_array() {
        Some(m) => m,
        None    => return vec![],
    };

    matches.iter().filter_map(|m| {
        let d = &m["data"];
        Some(Event {
            command: d["command"].as_str()?.to_string(),
            os:      d["os"].as_str()?.to_string(),
            version: d["version"].as_str()?.to_string(),
        })
    }).collect()
}

fn sort_desc(map: &HashMap<String, usize>) -> Vec<(String, usize)> {
    let mut v: Vec<_> = map.iter().map(|(k,v)| (k.clone(), *v)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    v
}

fn print_line(inner: &str, inner_len: usize) {
    let pad = " ".repeat(IW.saturating_sub(inner_len));
    eprintln!("  \x1b[2m\u{2502}\x1b[0m  {}{}\x1b[2m  \u{2502}\x1b[0m", inner, pad);
}

fn print_sep() {
    eprintln!("  \x1b[2m\u{251C}{}\u{2524}\x1b[0m", "\u{2500}".repeat(IW + 4));
}

fn render(events: &[Event]) {
    if events.is_empty() {
        eprintln!("\n  \x1b[2mno data yet.\x1b[0m\n");
        return;
    }

    let mut cmd_map: HashMap<String, usize> = HashMap::new();
    let mut os_map:  HashMap<String, usize> = HashMap::new();
    let mut ver_map: HashMap<String, usize> = HashMap::new();

    for e in events {
        *cmd_map.entry(e.command.clone()).or_insert(0) += 1;
        *os_map.entry(e.os.clone()).or_insert(0)       += 1;
        *ver_map.entry(e.version.clone()).or_insert(0) += 1;
    }

    let total   = events.len();
    let top_cmd = sort_desc(&cmd_map).into_iter().next().map(|(k,_)| k).unwrap_or_else(|| "-".to_string());

    eprintln!();
    eprintln!("  \x1b[2m\u{250C}{}\u{2510}\x1b[0m", "\u{2500}".repeat(IW + 4));
    print_line(&format!("\x1b[1manalytics\x1b[0m  \x1b[2mlast 30 days\x1b[0m"), 9 + 2 + 12);
    print_sep();
    print_line(&format!("\x1b[2mtotal events   \x1b[0m\x1b[1m{}\x1b[0m", total),           15 + total.to_string().len());
    print_line(&format!("\x1b[2mtop command    \x1b[0m\x1b[1m\x1b[96m{}\x1b[0m", top_cmd), 15 + top_cmd.len());
    print_line(&format!("\x1b[2mplatforms      \x1b[0m\x1b[1m{}\x1b[0m", os_map.len()),    15 + os_map.len().to_string().len());
    print_line(&format!("\x1b[2mversions       \x1b[0m\x1b[1m{}\x1b[0m", ver_map.len()),   15 + ver_map.len().to_string().len());
    print_sep();

    print_line("\x1b[2mcommands\x1b[0m", 8);
    for (cmd, count) in sort_desc(&cmd_map).iter().take(8) {
        let pct   = count * BAR_W / total;
        let bar   = format!("{}{}", "\u{2588}".repeat(pct), "\u{2591}".repeat(BAR_W - pct));
        let inner = format!("{:<10}\x1b[96m{}\x1b[0m  \x1b[2m{}\x1b[0m", cmd, bar, count);
        print_line(&inner, 10 + BAR_W + 2 + count.to_string().len());
    }
    print_sep();

    print_line("\x1b[2mplatforms\x1b[0m", 9);
    for (os, count) in sort_desc(&os_map) {
        let pct     = count * 100 / total;
        let pct_str = format!("{}%", pct);
        let inner   = format!("{:<12}\x1b[2m{:>4}  {} events\x1b[0m", os, pct_str, count);
        print_line(&inner, 12 + pct_str.len() + 2 + count.to_string().len() + 7);
    }

    eprintln!("  \x1b[2m\u{2514}{}\u{2518}\x1b[0m\n", "\u{2500}".repeat(IW + 4));
}

pub fn run(setup: bool) {
    if setup {
        setup_password();
        return;
    }

    if !verify_password() {
        eprintln!("\n  \x1b[31m✘\x1b[0m  incorrect password\n");
        std::process::exit(1);
    }

    eprintln!("\n  \x1b[2mfetching analytics...\x1b[0m");
    let events = fetch_events();
    eprint!("\x1b[1A\x1b[2K");
    render(&events);
}
