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
use cmd::{Cli, Commands, NonceArgs};

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.json;
    match dispatch(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            report_error(&*e, json);
            ExitCode::FAILURE
        }
    }
}

async fn dispatch(cli: Cli) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let json = cli.json;
    match cli.command {
        Commands::Evm(cmd) => cmd.execute(json).await,
        Commands::Svm(cmd) => cmd.execute(json).await,
        Commands::Nonce(_args) => NonceArgs::execute(json),
    }
}

fn report_error(error: &(dyn std::error::Error + 'static), json: bool) {
    if json {
        let out = error.downcast_ref::<siwx::Error>().map_or_else(
            || output::ErrorOutput::plain(error.to_string()),
            output::ErrorOutput::from_error,
        );
        if output::print_json(&out).is_err() {
            eprintln!("failed to serialize error output");
        }
    } else {
        eprintln!("Error: {error}");
    }
}
