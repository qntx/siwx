#![allow(clippy::print_stdout, clippy::print_stderr)]
//! siwx — CAIP-122 Sign-In with X CLI tool.

mod cmd;
mod output;

use clap::Parser;
use cmd::{Cli, Commands};

fn main() {
    let cli = Cli::parse();
    let json = cli.json;

    if let Err(e) = run(cli) {
        if json {
            let _ = output::print_json(&output::ErrorOutput {
                error: e.to_string(),
            });
        } else {
            eprintln!("Error: {e}");
        }
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let json = cli.json;
    match cli.command {
        Commands::Evm(cmd) => cmd.execute(json),
        Commands::Svm(cmd) => cmd.execute(json),
        Commands::Nonce(args) => args.execute(json),
        Commands::Parse(args) => args.execute(json),
    }
}
