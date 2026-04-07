#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "CLI tool intentionally outputs to terminal"
)]
//! siwx — CAIP-122 Sign-In with X CLI tool.

mod cmd;
mod output;

use std::process::ExitCode;

use clap::Parser;
use cmd::{Cli, Commands};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.json;

    if let Err(e) = run(cli) {
        if json {
            if output::print_json(&output::ErrorOutput {
                error: e.to_string(),
            })
            .is_err()
            {
                eprintln!("Failed to serialize error output");
            }
        } else {
            eprintln!("Error: {e}");
        }
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
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
