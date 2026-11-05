//! zipdfu creates DFU `.zip` packages for Nordic nRF5 bootloaders, as a drop-in replacement for
//! `nrfutil pkg generate` and `adafruit-nrfutil dfu genpkg`.

mod cli;
mod crc;
mod firmware;
mod ihex;
mod json;
mod legacy;
mod package;
mod protobuf;
mod pyset;
mod secure;
mod signing;
mod zip;

use std::process::ExitCode;

use clap::{CommandFactory, FromArgMatches};

fn main() -> ExitCode {
    let mut command = cli::Cli::command();
    let matches = command.get_matches_mut();
    let args =
        cli::Cli::from_arg_matches(&matches).unwrap_or_else(|err| err.format(&mut command).exit());

    match cli::run(args.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(cli::Error::Usage {
            command: path,
            kind,
            message,
        }) => {
            // Report like clap's own errors (exit code 2), with the subcommand's usage.
            let subcommand = path
                .iter()
                .try_fold(&mut command, |cmd, name| cmd.find_subcommand_mut(name))
                .expect("the subcommand exists");
            subcommand.error(kind, message).exit()
        }
        Err(cli::Error::Failed(err)) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}
