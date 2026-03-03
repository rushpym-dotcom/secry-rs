use crate::ui;

pub fn run(enable: bool, disable: bool) {
    if enable {
        if let Some(p) = dirs_next::config_dir().map(|d| d.join("secry").join("telemetry")) {
            if let Some(parent) = p.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(p, "1");
        }
        eprintln!("\n  \x1b[32m✔\x1b[0m  Telemetry enabled\n");
    } else if disable {
        if let Some(p) = dirs_next::config_dir().map(|d| d.join("secry").join("telemetry")) {
            if let Some(parent) = p.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(p, "0");
        }
        eprintln!("\n  \x1b[38;5;245m–\x1b[0m  Telemetry disabled\n");
    } else {
        let enabled = {
            use std::fs;
            dirs_next::config_dir()
                .map(|d| d.join("secry").join("telemetry"))
                .and_then(|p| fs::read_to_string(p).ok())
                .map(|s| s.trim() == "1")
                .unwrap_or(false)
        };
        let status = if enabled {
            "\x1b[32menabled\x1b[0m"
        } else {
            "\x1b[38;5;245mdisabled\x1b[0m"
        };
        ui::box_print(&[
            ("status",  status),
            ("enable",  "secry telemetry --enable"),
            ("disable", "secry telemetry --disable"),
            ("data",    "command, version, os — nothing else"),
        ]);
        eprintln!();
    }
}
