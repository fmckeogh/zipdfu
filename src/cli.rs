//! Command line interface.
//!
//! The commands, options, defaults and validation rules mirror `nrfutil pkg generate`
//! (pc-nrfutil 6.1.7) and `adafruit-nrfutil dfu genpkg` (0.5.3.post16), so zipdfu can replace
//! them in existing build scripts. Integers are parsed like nrfutil does: `0x` for hexadecimal,
//! a leading `0` for octal, decimal otherwise.

use std::fs;
use std::path::PathBuf;

use anyhow::Context;
use clap::error::ErrorKind;
use clap::{Args, Parser, Subcommand};

use crate::legacy::{self, DfuVersion};
use crate::pyset;
use crate::secure::{self, BootValidation};
use crate::signing::SigningKey;

#[derive(Debug, Parser)]
#[command(
    name = "zipdfu",
    version,
    about = "Create DFU .zip packages for Nordic nRF5 bootloaders",
    long_about = "Create DFU .zip packages for Nordic nRF5 bootloaders.\n\n\
        `zipdfu pkg generate` replaces `nrfutil pkg generate` (Secure DFU: nRF5 SDK 12 and later).\n\
        `zipdfu dfu genpkg` replaces `adafruit-nrfutil dfu genpkg` (legacy DFU: nRF5 SDK 11 and \
        earlier, and the Adafruit nRF52 bootloader)."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Secure DFU packages for nRF5 SDK 12+ bootloaders (like `nrfutil pkg`)
    Pkg {
        #[command(subcommand)]
        command: PkgCommand,
    },
    /// Legacy DFU packages for nRF5 SDK 11 and Adafruit bootloaders (like `adafruit-nrfutil dfu`)
    Dfu {
        #[command(subcommand)]
        command: DfuCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum PkgCommand {
    /// Generate a zip package for performing DFU
    #[command(long_about = "Generate a zip package for performing DFU.\n\n\
        .hex files are converted to .bin. Supported combinations of images:\n  \
        bootloader | SoftDevice | application | SoftDevice + bootloader |\n  \
        SoftDevice + application | SoftDevice + bootloader + application\n\
        A bootloader and an application without a SoftDevice need two packages.")]
    Generate(PkgGenerateArgs),
}

#[derive(Debug, Subcommand)]
pub enum DfuCommand {
    /// Generate a zip package for distribution to apps supporting Nordic legacy DFU
    #[command(
        long_about = "Generate a zip package for distribution to apps supporting Nordic legacy DFU.\n\n\
        .hex files are converted to .bin. A SoftDevice and bootloader are merged into a single image."
    )]
    Genpkg(DfuGenpkgArgs),
}

#[derive(Debug, Args)]
pub struct PkgGenerateArgs {
    /// The package to create
    pub zipfile: PathBuf,

    /// Set the debug flag in the init packet, which makes debug bootloaders skip version checks.
    /// Versions then default to 0xFFFFFFFF and --sd-req to 0xFFFE.
    #[arg(long)]
    pub debug_mode: bool,

    /// The application firmware file (.hex or .bin)
    #[arg(long, value_name = "FILE")]
    pub application: Option<PathBuf>,

    /// The application version
    #[arg(long, value_name = "INT", value_parser = u32_or_none)]
    pub application_version: Option<OrNone<u32>>,

    /// The application version as "X.Y.Z", stored as X*10000 + Y*100 + Z (e.g. "2.7.31" is 20731)
    #[arg(long, value_name = "X.Y.Z", value_parser = version_string)]
    pub application_version_string: Option<u32>,

    /// The bootloader firmware file (.hex or .bin)
    #[arg(long, value_name = "FILE")]
    pub bootloader: Option<PathBuf>,

    /// The bootloader version
    #[arg(long, value_name = "INT", value_parser = u32_or_none)]
    pub bootloader_version: Option<OrNone<u32>>,

    /// The hardware version, e.g. 52 for the nRF52 series
    #[arg(long, value_name = "INT", value_parser = u32_or_none)]
    pub hw_version: Option<OrNone<u32>>,

    /// Comma-separated SoftDevice firmware IDs, one of which must be present on the device,
    /// e.g. 0xB6 (S140 6.1.1), 0x100 (S140 7.2.0), 0x123 (S140 7.3.0), 0x124 (S132 7.3.0).
    /// Use 0x00 to update a device without a SoftDevice.
    #[arg(long, value_name = "IDS", value_parser = u32_list_or_none)]
    pub sd_req: Option<OrNone<Vec<u32>>>,

    /// The firmware IDs of the SoftDevice in the package; required when the package also contains
    /// an application, which is then checked against these IDs instead of --sd-req
    #[arg(long, value_name = "IDS", value_parser = u32_list_or_none)]
    pub sd_id: Option<OrNone<Vec<u32>>>,

    /// The SoftDevice firmware file (.hex or .bin)
    #[arg(long, value_name = "FILE")]
    pub softdevice: Option<PathBuf>,

    /// How the bootloader validates the SoftDevice at boot
    #[arg(long, value_name = "METHOD", value_enum, default_value_t = BootValidation::Crc)]
    pub sd_boot_validation: BootValidation,

    /// How the bootloader validates the application at boot
    #[arg(long, value_name = "METHOD", value_enum, default_value_t = BootValidation::Crc)]
    pub app_boot_validation: BootValidation,

    /// The private (signing) key in PEM format
    #[arg(long, value_name = "FILE")]
    pub key_file: Option<PathBuf>,

    /// The application is passed on to another device instead of being applied by the receiver
    #[arg(long)]
    pub external_app: bool,
}

#[derive(Debug, Args)]
pub struct DfuGenpkgArgs {
    /// The package to create
    pub zipfile: PathBuf,

    /// The application firmware file (.hex or .bin)
    #[arg(long, value_name = "FILE")]
    pub application: Option<PathBuf>,

    /// The application version, or "none" to leave the field out of the init packet
    #[arg(long, value_name = "INT", value_parser = u32_or_none, default_value = "0xFFFFFFFF")]
    pub application_version: OrNone<u32>,

    /// The bootloader firmware file (.hex or .bin)
    #[arg(long, value_name = "FILE")]
    pub bootloader: Option<PathBuf>,

    /// The device revision, or "none" to leave the field out of the init packet
    #[arg(long, value_name = "INT", value_parser = u16_or_none, default_value = "0xFFFF")]
    pub dev_revision: OrNone<u16>,

    /// The device type (0x0052 for Adafruit nRF52 boards), or "none" to leave the field out of the init packet
    #[arg(long, value_name = "INT", value_parser = u16_or_none, default_value = "0xFFFF")]
    pub dev_type: OrNone<u16>,

    /// The init packet version: 0.5 (CRC-16), 0.6 (CRC-16 and extended packet ID), 0.7 (SHA-256)
    /// or 0.8 (SHA-256 and ECDSA signature)
    #[arg(long, value_name = "VERSION", value_parser = DfuVersion::parse, default_value = "0.5")]
    pub dfu_ver: DfuVersion,

    /// Comma-separated SoftDevice firmware IDs, one of which must be present on the device,
    /// or "none" for an empty list. 0xFFFE accepts any SoftDevice.
    #[arg(long, value_name = "IDS", value_parser = u16_list_or_none, default_value = "0xFFFE")]
    pub sd_req: OrNone<Vec<u16>>,

    /// The SoftDevice firmware file (.hex or .bin)
    #[arg(long, value_name = "FILE")]
    pub softdevice: Option<PathBuf>,

    /// The private (signing) key in PEM format; implies --dfu-ver 0.8
    #[arg(long, value_name = "FILE")]
    pub key_file: Option<PathBuf>,
}

/// An option value that may also be given as `none`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrNone<T>(pub Option<T>);

/// Why a command failed.
#[derive(Debug)]
pub enum Error {
    /// The options are inconsistent; reported along with the command's usage.
    Usage {
        command: [&'static str; 2],
        kind: ErrorKind,
        message: String,
    },
    /// Anything else, such as unreadable input files.
    Failed(anyhow::Error),
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        Error::Failed(err)
    }
}

pub fn run(command: Command) -> Result<(), Error> {
    match command {
        Command::Pkg {
            command: PkgCommand::Generate(args),
        } => pkg_generate(args),
        Command::Dfu {
            command: DfuCommand::Genpkg(args),
        } => dfu_genpkg(args),
    }
}

fn pkg_generate(args: PkgGenerateArgs) -> Result<(), Error> {
    let usage = |kind, message: &str| {
        Err(Error::Usage {
            command: ["pkg", "generate"],
            kind,
            message: message.into(),
        })
    };
    let missing = |message| usage(ErrorKind::MissingRequiredArgument, message);
    let conflict = |message| usage(ErrorKind::ArgumentConflict, message);

    let (has_app, has_bl, has_sd) = (
        args.application.is_some(),
        args.bootloader.is_some(),
        args.softdevice.is_some(),
    );
    if !has_app && !has_bl && !has_sd {
        return missing("at least one of --application, --bootloader and --softdevice is required");
    }
    if has_bl && has_app && !has_sd {
        return conflict(
            "a bootloader and an application can only be combined with a SoftDevice; use two packages instead",
        );
    }

    let mut app_version = match args.application_version_string {
        Some(version) => {
            if args.application_version.is_some() {
                warn(
                    "both --application-version-string and --application-version given; using the string",
                );
            }
            Some(version)
        }
        None => args.application_version.and_then(|v| v.0),
    };
    let mut bl_version = args.bootloader_version.and_then(|v| v.0);
    let mut hw_version = args.hw_version.and_then(|v| v.0);
    let mut sd_req = args.sd_req.and_then(|v| v.0);
    let sd_id = args.sd_id.and_then(|v| v.0);

    if app_version.is_some() && !has_app {
        return conflict("an application version was given without --application");
    }
    if bl_version.is_some() && !has_bl {
        return conflict("--bootloader-version was given without --bootloader");
    }
    if args.debug_mode {
        warn(
            "--debug-mode sets the debug flag in the init packet; such packages are only accepted by debug \
             bootloaders and are not suitable for production",
        );
        app_version.get_or_insert(0xFFFF_FFFF);
        bl_version.get_or_insert(0xFFFF_FFFF);
        hw_version.get_or_insert(0xFFFF_FFFF);
        sd_req.get_or_insert_with(|| vec![0xFFFE]);
    }
    let Some(hw_version) = hw_version else {
        return missing("--hw-version is required");
    };
    if sd_req.is_none() && !args.external_app {
        return missing("--sd-req is required");
    }
    if has_app && app_version.is_none() {
        return missing(
            "--application-version or --application-version-string is required with --application",
        );
    }
    if has_bl && bl_version.is_none() {
        return missing("--bootloader-version is required with --bootloader");
    }
    if has_app && has_sd && sd_id.is_none() {
        return missing(
            "--sd-id is required when the package contains both a SoftDevice and an application",
        );
    }
    if args.external_app && !has_app {
        return missing("--external-app requires --application");
    }
    if args.external_app && (has_sd || has_bl) {
        return conflict(
            "--external-app is only possible for packages containing just an application",
        );
    }
    let uses_ecdsa = (has_sd && args.sd_boot_validation == BootValidation::EcdsaP256Sha256)
        || (has_app && args.app_boot_validation == BootValidation::EcdsaP256Sha256);
    if uses_ecdsa && args.key_file.is_none() {
        return missing("--key-file is required for VALIDATE_ECDSA_P256_SHA256 boot validation");
    }

    let mut sd_req = sd_req.unwrap_or_default();
    let app_sd_req = match sd_id {
        Some(sd_id) => {
            // Like nrfutil, also accept the new SoftDevice for the SoftDevice (and bootloader)
            // image, so that an update interrupted after the SoftDevice was replaced can be
            // repeated. nrfutil appends `set(sd_id) - set(sd_req)`.
            let extra: Vec<u32> = pyset::set_order(&sd_id)
                .into_iter()
                .filter(|id| !sd_req.contains(id))
                .collect();
            sd_req.extend(pyset::set_order(&extra));
            sd_id
        }
        None => sd_req.clone(),
    };

    let signing_key = args
        .key_file
        .as_deref()
        .map(SigningKey::from_pem_file)
        .transpose()?;
    match &signing_key {
        None => warn(
            "no --key-file given, so the package is unsigned; it is only accepted by bootloaders that do not \
             check signatures and is not suitable for production",
        ),
        Some(key) if key.is_nrfutil_default() => warn(
            "the signing key is nrfutil's publicly known default key; do not use it for production, as anyone \
             can sign updates with it",
        ),
        Some(_) => {}
    }

    let config = secure::Config {
        hw_version,
        debug_mode: args.debug_mode,
        sd_req,
        app_sd_req,
        application: args.application.map(|path| secure::Application {
            path,
            version: app_version.expect("checked above"),
            boot_validation: args.app_boot_validation,
            external: args.external_app,
        }),
        bootloader: args.bootloader.map(|path| secure::Bootloader {
            path,
            version: bl_version.expect("checked above"),
        }),
        softdevice: args.softdevice.map(|path| secure::SoftDevice {
            path,
            boot_validation: args.sd_boot_validation,
        }),
        signing_key,
    };
    write_package(&args.zipfile, secure::build(&config)?)
}

fn dfu_genpkg(args: DfuGenpkgArgs) -> Result<(), Error> {
    let usage = |kind, message: &str| {
        Err(Error::Usage {
            command: ["dfu", "genpkg"],
            kind,
            message: message.into(),
        })
    };

    if args.application.is_none() && args.bootloader.is_none() && args.softdevice.is_none() {
        return usage(
            ErrorKind::MissingRequiredArgument,
            "at least one of --application, --bootloader and --softdevice is required",
        );
    }
    if args.key_file.is_none() && args.dfu_ver == DfuVersion::V0_8 {
        return usage(
            ErrorKind::MissingRequiredArgument,
            "--dfu-ver 0.8 requires --key-file",
        );
    }
    for (omitted, option) in [
        (args.dev_type.0.is_none(), "--dev-type"),
        (args.dev_revision.0.is_none(), "--dev-revision"),
        (
            args.application_version.0.is_none(),
            "--application-version",
        ),
    ] {
        if omitted {
            warn(&format!(
                "{option} none leaves the field out of the init packet, which then no longer has the layout \
                 that SDK 11 based bootloaders expect"
            ));
        }
    }

    let signing_key = args
        .key_file
        .as_deref()
        .map(SigningKey::from_pem_file)
        .transpose()?;
    let dfu_version = if signing_key.is_some() {
        if args.dfu_ver < DfuVersion::V0_8 {
            note("--key-file given, so using --dfu-ver 0.8");
        }
        DfuVersion::V0_8
    } else {
        args.dfu_ver
    };

    let config = legacy::Config {
        dev_type: args.dev_type.0,
        dev_revision: args.dev_revision.0,
        app_version: args.application_version.0,
        // Unlike nrfutil 6, adafruit-nrfutil takes "none" as an empty list.
        sd_req: args.sd_req.0.unwrap_or_default(),
        dfu_version,
        signing_key,
        application: args.application,
        bootloader: args.bootloader,
        softdevice: args.softdevice,
    };
    write_package(&args.zipfile, legacy::build(&config)?)
}

fn write_package(path: &std::path::Path, archive: Vec<u8>) -> Result<(), Error> {
    fs::write(path, archive).with_context(|| format!("cannot write '{}'", path.display()))?;
    println!("Zip created at {}", path.display());
    Ok(())
}

fn warn(message: &str) {
    eprintln!("warning: {message}");
}

fn note(message: &str) {
    eprintln!("note: {message}");
}

/// Parses an integer the way nrfutil does: a `0x` prefix means hexadecimal, a leading `0` octal.
fn integer(s: &str, max: u64) -> Result<u64, String> {
    let s = s.trim();
    let (digits, radix) = match s.as_bytes() {
        [b'0', b'x' | b'X', ..] => (&s[2..], 16),
        [b'0', _, ..] => (&s[1..], 8),
        _ => (s, 10),
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        let hint = if radix == 8 {
            " (a leading 0 denotes an octal number)"
        } else {
            ""
        };
        return Err(format!("'{s}' is not a valid integer{hint}"));
    }
    match u64::from_str_radix(digits, radix) {
        Ok(value) if value <= max => Ok(value),
        _ => Err(format!("'{s}' is out of range (the maximum is {max:#X})")),
    }
}

fn or_none<T>(s: &str, parse: impl Fn(&str) -> Result<T, String>) -> Result<OrNone<T>, String> {
    if s.trim().eq_ignore_ascii_case("none") {
        Ok(OrNone(None))
    } else {
        parse(s).map(|v| OrNone(Some(v)))
    }
}

fn u32_or_none(s: &str) -> Result<OrNone<u32>, String> {
    or_none(s, |s| integer(s, u32::MAX.into()).map(|v| v as u32))
}

fn u16_or_none(s: &str) -> Result<OrNone<u16>, String> {
    or_none(s, |s| integer(s, u16::MAX.into()).map(|v| v as u16))
}

/// A comma-separated list of integers, e.g. SoftDevice IDs.
fn integer_list(s: &str, max: u64) -> Result<Vec<u64>, String> {
    s.split(',').map(|item| integer(item, max)).collect()
}

fn u32_list_or_none(s: &str) -> Result<OrNone<Vec<u32>>, String> {
    or_none(s, |s| {
        Ok(integer_list(s, u32::MAX.into())?
            .into_iter()
            .map(|id| id as u32)
            .collect())
    })
}

fn u16_list_or_none(s: &str) -> Result<OrNone<Vec<u16>>, String> {
    or_none(s, |s| {
        Ok(integer_list(s, u16::MAX.into())?
            .into_iter()
            .map(|id| id as u16)
            .collect())
    })
}

/// Parses "X.Y.Z" into X*10000 + Y*100 + Z, like nrfutil's `--application-version-string`.
fn version_string(s: &str) -> Result<u32, String> {
    const FORMAT: &str = "must be in the format X.Y.Z";
    let parts = s
        .split('.')
        .map(|part| match part {
            "" => Err(FORMAT.to_owned()),
            _ if part.bytes().all(|b| b.is_ascii_digit()) => {
                part.parse::<u64>().map_err(|_| "is too large".to_owned())
            }
            _ => Err(FORMAT.to_owned()),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let [major, minor, patch] = parts[..] else {
        return Err(FORMAT.to_owned());
    };
    // nrfutil lets a larger Y or Z silently spill into the next field ("1.0.100" == "1.1.0").
    if minor > 99 || patch > 99 {
        return Err(
            "Y and Z must be at most 99; use --application-version for other version schemes"
                .to_owned(),
        );
    }
    major
        .checked_mul(10_000)
        .map(|v| v + minor * 100 + patch)
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(|| "is too large".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_like_nrfutil() {
        assert_eq!(integer("0x52", 0xFFFF), Ok(0x52));
        assert_eq!(integer("0X00b6", 0xFFFF), Ok(0xB6));
        assert_eq!(integer("052", 0xFFFF), Ok(0o52));
        assert_eq!(integer("0", 0xFFFF), Ok(0));
        assert_eq!(integer("52840", 0xFFFF), Ok(52840));
        assert_eq!(integer(" 7 ", 0xFFFF), Ok(7));
        assert!(integer("08", 0xFFFF).unwrap_err().contains("octal"));
        for bad in ["", "0x", "-1", "+1", "1_000", "0b1", "x1", "12a"] {
            assert!(integer(bad, u32::MAX.into()).is_err(), "{bad:?}");
        }
        assert!(
            integer("0x10000", 0xFFFF)
                .unwrap_err()
                .contains("out of range")
        );
        assert!(integer("99999999999999999999999", u32::MAX.into()).is_err());
    }

    #[test]
    fn none_and_lists() {
        assert_eq!(u32_or_none("None"), Ok(OrNone(None)));
        assert_eq!(u32_or_none("0xFFFFFFFF"), Ok(OrNone(Some(u32::MAX))));
        assert_eq!(
            u16_list_or_none("0xB6, 0xCA,0xB6"),
            Ok(OrNone(Some(vec![0xB6, 0xCA, 0xB6])))
        );
        assert_eq!(u16_list_or_none("none"), Ok(OrNone(None)));
        assert!(u16_list_or_none("0xB6,").is_err());
        assert!(u16_list_or_none("0x10000").is_err());
        assert_eq!(u32_list_or_none("0x10000"), Ok(OrNone(Some(vec![0x10000]))));
    }

    #[test]
    fn version_strings() {
        assert_eq!(version_string("2.7.31"), Ok(20731));
        assert_eq!(version_string("1.02.3"), Ok(10203));
        assert_eq!(version_string("0.0.0"), Ok(0));
        assert_eq!(version_string("429496.72.95"), Ok(u32::MAX));
        for bad in [
            "1.2",
            "1.2.3.4",
            "1..3",
            "a.b.c",
            "1.2.-3",
            "1.100.0",
            "1.0.100",
            "429497.0.0",
        ] {
            assert!(version_string(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
