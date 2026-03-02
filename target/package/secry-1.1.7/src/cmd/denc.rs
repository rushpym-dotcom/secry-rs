use crate::crypto::decrypt;
use crate::ui;

pub fn run(token: &str, password: &str) {
    let t0 = std::time::Instant::now();
    match decrypt(token, password) {
        Ok(r) => {
            let ms = t0.elapsed().as_millis();
            ui::section("decrypt");
            ui::box_print(&[
                ("algo",    r.algo.name()),
                ("mode",    if r.compact { "compact" } else { "full" }),
                ("expires", &r.expires_at_ms.map(|e| {
                    let secs = e / 1000;
                    format!("{}", secs)
                }).unwrap_or_else(|| "none".into())),
            ]);
            ui::ms(ms);
            println!("{}", r.plaintext);
        }
        Err(e) => { ui::err(&e); std::process::exit(1); }
    }
}
