// Entry point for the `sec` binary — delegates everything to secry's main logic
// with the binary name overridden to "sec" for help text.

mod crypto;
mod cmd;
mod ui;
mod telemetry;

use clap::{Parser, Subcommand};
use crypto::Algo;

#[derive(Parser)]
#[command(name = "sec", version, about = "token encryption CLI")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Enc {
        text:     String,
        #[arg(long = "sw", short = 's')]
        password: Option<String>,
        #[arg(long)] v2: bool,
        #[arg(long)] v3: bool,
        #[arg(long)] expires: Option<String>,
        #[arg(long)] compact: bool,
    },
    Denc {
        token:    String,
        #[arg(long = "sw", short = 's')]
        password: Option<String>,
    },
    Gen {
        #[arg(default_value = "24")]
        nbytes: usize,
        #[arg(long)] upper: bool,
        #[arg(long, default_value = "1")] count: usize,
    },
    Verify {
        token:    String,
        #[arg(long = "sw", short = 's')]
        password: Option<String>,
    },
    Fp {
        text:   String,
        #[arg(long = "sw", short = 's')]
        secret: Option<String>,
    },
    Seal {
        text:   String,
        #[arg(long = "sw", short = 's')]
        secret: Option<String>,
        #[arg(long, short = 'q')]
        quiet:  bool,
        #[arg(long = "s2")]
        use_s2: bool,
        #[arg(long)] compact: bool,
    },
    SealVerify {
        text:   String,
        #[arg(long = "sw", short = 's')]
        secret: Option<String>,
        #[arg(long)] token: String,
        #[arg(long, short = 'q')]
        quiet:  bool,
    },
    Sei {
        text: String,
        #[arg(long = "sw", short = 's')]
        password: Option<String>,
        #[arg(long, num_args = 1)]
        ip: Vec<String>,
        #[arg(long = "ip-auto")]
        ip_auto: bool,
        #[arg(long = "ipf")]
        ip_force: bool,
        #[arg(long, short = 'q')]
        quiet: bool,
        #[arg(long)]
        compact: bool,
    },
    SeiOpen {
        token: String,
        #[arg(long = "sw", short = 's')]
        password: Option<String>,
        #[arg(long)]
        ip: Option<String>,
        #[arg(long, short = 'q')]
        quiet: bool,
    },
    Info {
        token: String,
    },
    Example,
    Upgrade,
    Changelog {
        #[arg(long)] search: Option<String>,
        #[arg(long)] tag:    Option<String>,
    },
    Analysis,
    Telemetry {
        #[arg(long)] enable:  bool,
        #[arg(long)] disable: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Cmd::Telemetry { .. } | Cmd::Analysis => {}
        _ => telemetry::maybe_ask(),
    }

    match cli.command {
        Cmd::Enc { text, password, v2, v3, expires, compact } => {
            let pw   = resolve_pw(password, "password");
            let algo = if v3 { Algo::V3 } else if v2 { Algo::V2 } else { Algo::V1 };
            telemetry::track("enc");
            cmd::enc::run(&text, &pw, algo, expires.as_deref(), compact);
        }
        Cmd::Denc { token, password } => {
            let pw = resolve_pw(password, "password");
            telemetry::track("denc");
            cmd::denc::run(&token, &pw);
        }
        Cmd::Gen { nbytes, upper, count } => {
            telemetry::track("gen");
            cmd::gen::run(nbytes, upper, count);
        }
        Cmd::Verify { token, password } => {
            let pw = resolve_pw(password, "password");
            telemetry::track("verify");
            cmd::verify::run(&token, &pw);
        }
        Cmd::Fp { text, secret } => {
            let s = resolve_pw(secret, "secret");
            telemetry::track("fp");
            cmd::fp::run(&text, &s);
        }
        Cmd::Seal { text, secret, quiet, use_s2, compact } => {
            let s = resolve_pw(secret, "secret");
            telemetry::track("seal");
            cmd::seal::run(&text, &s, quiet, use_s2, compact);
        }
        Cmd::SealVerify { text, secret, token, quiet } => {
            let s = resolve_pw(secret, "secret");
            telemetry::track("seal-verify");
            cmd::seal::run_verify(&text, &s, &token, quiet);
        }
        Cmd::Sei { text, password, ip, ip_auto, ip_force, quiet, compact } => {
            let pw = resolve_pw(password, "password");
            telemetry::track("sei");
            cmd::sei::run(&text, &pw, &ip, ip_auto, ip_force, quiet, compact);
        }
        Cmd::SeiOpen { token, password, ip, quiet } => {
            let pw = resolve_pw(password, "password");
            telemetry::track("sei-open");
            cmd::sei::run_open(&token, &pw, ip.as_deref(), quiet);
        }
        Cmd::Info { token } => {
            telemetry::track("info");
            cmd::info::run(&token);
        }
        Cmd::Example => {
            telemetry::track("example");
            cmd::example::run();
        }
        Cmd::Upgrade => {
            telemetry::track("upgrade");
            cmd::upgrade::run();
        }
        Cmd::Changelog { search, tag } => {
        }
        Cmd::Analysis => {
            cmd::analysis::run();
        }
        Cmd::Telemetry { enable, disable } => {
            cmd::tele::run(enable, disable);
        }
    }
}

fn resolve_pw(pw: Option<String>, label: &str) -> String {
    pw.unwrap_or_else(|| {
        rpassword::prompt_password(format!("  {}: ", label)).unwrap_or_default()
    })
}
