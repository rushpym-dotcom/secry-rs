use crate::ui;

const PKG: &str = "secry";
const CUR: &str = env!("CARGO_PKG_VERSION");

pub fn run() {
    ui::section("upgrade");
    eprintln!("  checking crates.io...\n");

    let url = format!("https://crates.io/api/v1/crates/{}", PKG);
    let res  = ureq::get(&url)
        .set("User-Agent", &format!("secry/{} (upgrade check)", CUR))
        .call();

    match res {
        Ok(r) => {
            let body: String = r.into_string().unwrap_or_default();
            let latest = parse_version(&body).unwrap_or_else(|| "unknown".into());

            ui::box_print(&[
                ("current", CUR),
                ("latest",  &latest),
            ]);

            if latest == CUR {
                eprintln!("\n  \x1b[32m✔\x1b[0m  already up to date\n");
            } else {
                eprintln!("\n  \x1b[33m!\x1b[0m  update available\n");
                eprintln!("     cargo install secry --force\n");
            }
        }
        Err(_) => {
            ui::err("could not reach crates.io — check your connection");
            std::process::exit(1);
        }
    }
}

fn parse_version(body: &str) -> Option<String> {
    let key = "\"newest_version\":\"";
    let start = body.find(key)? + key.len();
    let end   = body[start..].find('"')? + start;
    Some(body[start..end].to_string())
}
