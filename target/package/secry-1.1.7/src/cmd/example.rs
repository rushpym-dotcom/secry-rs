use crate::ui;

pub fn run() {
    ui::section("example");
    eprintln!("  \x1b[38;5;245m# CLI  (secry or sec — both work)\x1b[0m");
    for line in [
        "secry enc 'text' --sw password",
        "secry enc 'text' --sw password --v2",
        "secry enc 'text' --sw password --v3",
        "secry enc 'text' --sw password --compact          # shorter token, sec: prefix",
        "secry denc 'token' --sw password",
        "secry verify 'token' --sw password",
        "secry gen 32 --upper --count 3",
        "secry fp 'text' --sw secret",
        "secry seal 'text' --sw secret",
        "secry seal 'text' --sw secret --compact           # shorter seal token",
        "secry seal-verify 'text' --sw secret --token secry:s1:...",
        "secry info 'token'",
        "",
        "# seal-enc  (reversible -- value can be recovered)",
        "secry sei 'value' --sw masterkey                  # no IP binding",
        "secry sei 'value' --sw masterkey --ip-auto        # bind to current IP",
        "secry sei 'value' --sw masterkey --ip 1.2.3.4     # bind to fixed IP",
        "secry sei 'value' --sw masterkey --ip 1.2.3.4 --ip 5.6.7.8  # multi-IP",
        "secry sei 'value' --sw masterkey --compact",
        "",
        "secry sei-open 'secry:sei:...' --sw masterkey     # auto-detect IP",
        "secry sei-open 'secry:sei:...' --sw masterkey --ip 1.2.3.4",
        "secry sei-open 'secry:se:...'  --sw masterkey     # no IP token",
        "",
        "sec enc 'text' --sw password                      # alias for secry",
        "sec enc 'text' --sw password --compact",
    ] {
        if line.is_empty() {
            eprintln!();
        } else {
            eprintln!("  \x1b[36m$\x1b[0m  \x1b[38;5;252m{}\x1b[0m", line);
        }
    }
    eprintln!();
}