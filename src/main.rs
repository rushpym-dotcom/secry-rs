mod crypto;
mod cmd;
mod ui;

use clap::{Parser, Subcommand};
use crypto::Algo;

#[derive(Parser)]
#[command(name = "secry", version, about = "token encryption CLI")]
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
        /// IP(s) para binding (múltiplos: --ip 1.1.1.1 --ip 2.2.2.2)
        #[arg(long, num_args = 1)]
        ip: Vec<String>,
        /// Auto-detect IP local
        #[arg(long = "ip-auto")]
        ip_auto: bool,
        /// Remove limite de 5 IPs
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
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Enc { text, password, v2, v3, expires, compact } => {
            let pw   = resolve_pw(password, "password");
            let algo = if v3 { Algo::V3 } else if v2 { Algo::V2 } else { Algo::V1 };
            cmd::enc::run(&text, &pw, algo, expires.as_deref(), compact);
        }
        Cmd::Denc { token, password } => {
            let pw = resolve_pw(password, "password");
            cmd::denc::run(&token, &pw);
        }
        Cmd::Gen { nbytes, upper, count } => {
            cmd::gen::run(nbytes, upper, count);
        }
        Cmd::Verify { token, password } => {
            let pw = resolve_pw(password, "password");
            cmd::verify::run(&token, &pw);
        }
        Cmd::Fp { text, secret } => {
            let s = resolve_pw(secret, "secret");
            cmd::fp::run(&text, &s);
        }
        Cmd::Seal { text, secret, quiet, use_s2, compact } => {
            let s = resolve_pw(secret, "secret");
            cmd::seal::run(&text, &s, quiet, use_s2, compact);
        }
        Cmd::SealVerify { text, secret, token, quiet } => {
            let s = resolve_pw(secret, "secret");
            cmd::seal::run_verify(&text, &s, &token, quiet);
        }
        Cmd::Sei { text, password, ip, ip_auto, ip_force, quiet, compact } => {
            let pw = resolve_pw(password, "password");
            cmd::sei::run(&text, &pw, &ip, ip_auto, ip_force, quiet, compact);
        }
        Cmd::SeiOpen { token, password, ip, quiet } => {
            let pw = resolve_pw(password, "password");
            cmd::sei::run_open(&token, &pw, ip.as_deref(), quiet);
        }
        Cmd::Info { token } => {
            cmd::info::run(&token);
        }
        Cmd::Example => {
            cmd::example::run();
        }
        Cmd::Upgrade => cmd::upgrade::run(),
        Cmd::Changelog { search, tag } => {
            cmd::changelog::run(search.as_deref(), tag.as_deref());
        }
    }
}

fn resolve_pw(pw: Option<String>, label: &str) -> String {
    pw.unwrap_or_else(|| {
        rpassword::prompt_password(format!("  {}: ", label)).unwrap_or_default()
    })
}
