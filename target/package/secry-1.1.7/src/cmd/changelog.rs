use std::fs;
use std::path::PathBuf;

// ── types ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct Entry {
    version: String,
    date:    String,
    title:   String,
    items:   Vec<String>,
    tags:    Vec<String>,
}

// ── colors ────────────────────────────────────────────────────────────────────

const R:  &str = "\x1b[0m";
const D:  &str = "\x1b[2m";
const B:  &str = "\x1b[1m";
const W:  &str = "\x1b[97m";
const C:  &str = "\x1b[96m";
const G:  &str = "\x1b[92m";
const Y:  &str = "\x1b[93m";
const RE: &str = "\x1b[91m";

fn tag_color(tag: &str) -> &'static str {
    match tag {
        "feature"  => C,
        "fix"      => G,
        "breaking" => RE,
        "security" => Y,
        _          => D,
    }
}

// ── path ──────────────────────────────────────────────────────────────────────

fn data_path() -> PathBuf {
    let mut p = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("."));
    p.push(".secry");
    p.push("changelog.pub.json");
    p
}

// ── load (public — no decryption needed for display) ─────────────────────────
// The file is encrypted with ChaCha20-Poly1305 in admin mode.
// For public display we attempt base64 fallback (legacy) first,
// then inform user to use Node.js CLI for admin operations.

fn load_entries() -> Vec<Entry> {
    let path = data_path();
    if !path.exists() { return vec![]; }

    let raw = match fs::read_to_string(&path) {
        Ok(s)  => s.trim().to_string(),
        Err(_) => return vec![],
    };

    // try base64 legacy format
    if let Ok(decoded) = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD, &raw
    ) {
        if let Ok(text) = String::from_utf8(decoded) {
            return parse_json(&text);
        }
    }

    // encrypted — cannot display without password
    vec![]
}

fn parse_json(text: &str) -> Vec<Entry> {
    let v: serde_json::Value = match serde_json::from_str(text) {
        Ok(v)  => v,
        Err(_) => return vec![],
    };

    let arr = match v["entries"].as_array() {
        Some(a) => a,
        None    => return vec![],
    };

    arr.iter().filter_map(|e| {
        Some(Entry {
            version: e["version"].as_str()?.to_string(),
            date:    e["date"].as_str()?.to_string(),
            title:   e["title"].as_str()?.to_string(),
            items:   e["items"].as_array().map(|a| {
                a.iter().filter_map(|i| i.as_str().map(|s| s.to_string())).collect()
            }).unwrap_or_default(),
            tags: e["tags"].as_array().map(|a| {
                a.iter().filter_map(|i| i.as_str().map(|s| s.to_string())).collect()
            }).unwrap_or_default(),
        })
    }).collect()
}

// ── render ────────────────────────────────────────────────────────────────────

fn render_tags(tags: &[String]) -> String {
    if tags.is_empty() { return String::new(); }
    tags.iter().map(|t| format!("{}[{}]{}", tag_color(t), t, R)).collect::<Vec<_>>().join(" ")
}

fn box_title(title: &str) {
    let line = "─".repeat(48);
    eprintln!("\n  {D}{line}{R}");
    eprintln!("  {B}{W}  {title}{R}");
    eprintln!("  {D}{line}{R}\n");
}

// ── public: view ──────────────────────────────────────────────────────────────

pub fn run(search: Option<&str>, tag: Option<&str>) {
    let mut entries = load_entries();

    if entries.is_empty() {
        let path = data_path();
        if path.exists() {
            // file exists but couldn't be decoded — it's encrypted
            box_title("changelog");
            eprintln!("  {D}changelog is managed via the Node.js CLI.{R}");
            eprintln!("  {D}run: secry changelog  (Node.js version){R}\n");
        } else {
            box_title("changelog");
            eprintln!("  {D}no releases yet.{R}\n");
        }
        return;
    }

    // filter by tag
    if let Some(t) = tag {
        entries.retain(|e| e.tags.iter().any(|et| et == t));
    }

    // filter by search
    if let Some(q) = search {
        let q = q.to_lowercase();
        entries.retain(|e| {
            e.version.contains(&q) ||
            e.title.to_lowercase().contains(&q) ||
            e.items.iter().any(|i| i.to_lowercase().contains(&q))
        });
    }

    let label = match (tag, search) {
        (Some(t), Some(s)) => format!("changelog  tag:{}  search:{}", t, s),
        (Some(t), None)    => format!("changelog  tag:{}", t),
        (None, Some(s))    => format!("changelog  search:{}", s),
        _                  => "changelog".to_string(),
    };

    box_title(&label);

    if entries.is_empty() {
        eprintln!("  {D}no results.{R}\n");
        return;
    }

    for e in &entries {
        let sep = format!("{D}{}{R}", "─".repeat(44));
        eprintln!("  {sep}");
        let tags_str = render_tags(&e.tags);
        if tags_str.is_empty() {
            eprintln!("  {C}{B}v{}{R}  {D}{}{R}", e.version, e.date);
        } else {
            eprintln!("  {C}{B}v{}{R}  {D}{}{R}  {}", e.version, e.date, tags_str);
        }
        eprintln!("  {W}{}{R}\n", e.title);
        for item in &e.items {
            eprintln!("  {D}—{R} {item}");
        }
        eprintln!();
    }
}
