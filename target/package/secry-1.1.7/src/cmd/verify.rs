use crate::crypto::verify;
use crate::ui;

pub fn run(token: &str, password: &str) {
    let t0 = std::time::Instant::now();
    let ok = verify(token, password);
    let ms = t0.elapsed().as_millis();
    ui::section("verify");
    ui::box_print(&[
        ("result", if ok { "valid" } else { "invalid" }),
    ]);
    ui::ms(ms);
    if !ok { std::process::exit(1); }
}