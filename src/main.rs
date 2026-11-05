use clap::{ArgGroup, Parser, ValueEnum};
use color_eyre::eyre::Result;
use std::path::PathBuf;

mod firmware;
mod package;

/// Create a DFU package for nRF5 SDK 11 based bootloaders, such as the Adafruit nRF52 bootloader.
///
/// The options are those of `adafruit-nrfutil dfu genpkg`. Firmware files are converted to .bin
/// if they are .hex files, and a SoftDevice and bootloader are merged into one image. Integers
/// are decimal, hexadecimal with a 0x prefix, or octal with a leading 0.
#[derive(Debug, Parser)]
#[command(version, group(ArgGroup::new("firmware").required(true).multiple(true)))]
pub struct Args {
    /// The package to create
    pub zipfile: PathBuf,

    /// The application (.hex or .bin)
    #[arg(long, value_name = "FILE", group = "firmware")]
    pub application: Option<PathBuf>,

    /// The application version, or "none" to leave it out of the init packet
    #[arg(long, value_name = "INT", default_value = "0xFFFFFFFF", value_parser = int_or_none::<u32>)]
    pub application_version: OrNone<u32>,

    /// The bootloader (.hex or .bin)
    #[arg(long, value_name = "FILE", group = "firmware")]
    pub bootloader: Option<PathBuf>,

    /// The device revision, or "none" to leave it out of the init packet
    #[arg(long, value_name = "INT", default_value = "0xFFFF", value_parser = int_or_none::<u16>)]
    pub dev_revision: OrNone<u16>,

    /// The device type (0x0052 for Adafruit nRF52 boards), or "none" to leave it out of the init packet
    #[arg(long, value_name = "INT", default_value = "0xFFFF", value_parser = int_or_none::<u16>)]
    pub dev_type: OrNone<u16>,

    /// The init packet format
    #[arg(long, value_name = "VERSION", default_value = "0.5")]
    pub dfu_ver: DfuVersion,

    /// Comma-separated SoftDevice firmware IDs, one of which must be on the device (0xFFFE means
    /// any), or "none" for an empty list
    #[arg(long, value_name = "IDS", default_value = "0xFFFE", value_parser = list_or_none)]
    pub sd_req: OrNone<Vec<u16>>,

    /// The SoftDevice (.hex or .bin)
    #[arg(long, value_name = "FILE", group = "firmware")]
    pub softdevice: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DfuVersion {
    /// The init packet ends with the image's CRC-16
    #[value(name = "0.5")]
    V0_5,
    /// The init packet ends with an extended packet ID (0) and the image's CRC-16
    #[value(name = "0.6")]
    V0_6,
}

/// An option value that can also be "none".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrNone<T>(pub Option<T>);

fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Args::parse();
    package::create(&args)?;
    println!("Zip created at {}", args.zipfile.display());
    Ok(())
}

/// Parses an integer like adafruit-nrfutil: a `0x` prefix means hexadecimal, a leading `0` octal.
fn parse_int<T: TryFrom<u64>>(s: &str) -> Result<T, String> {
    let s = s.trim();
    let (digits, radix) = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => (hex, 16),
        None if s.len() > 1 && s.starts_with('0') => (&s[1..], 8),
        None => (s, 10),
    };
    let n =
        u64::from_str_radix(digits, radix).map_err(|_| format!("'{s}' is not a valid integer"))?;
    T::try_from(n).map_err(|_| format!("'{s}' is out of range"))
}

fn is_none(s: &str) -> bool {
    s.trim().eq_ignore_ascii_case("none")
}

fn int_or_none<T: TryFrom<u64>>(s: &str) -> Result<OrNone<T>, String> {
    if is_none(s) {
        return Ok(OrNone(None));
    }
    Ok(OrNone(Some(parse_int(s)?)))
}

fn list_or_none(s: &str) -> Result<OrNone<Vec<u16>>, String> {
    if is_none(s) {
        return Ok(OrNone(None));
    }
    let ids = s.split(',').map(parse_int).collect::<Result<_, _>>()?;
    Ok(OrNone(Some(ids)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_integers_like_adafruit_nrfutil() {
        assert_eq!(parse_int::<u16>("0x0052"), Ok(0x52));
        assert_eq!(parse_int::<u16>("0052"), Ok(0o52));
        assert_eq!(parse_int::<u16>("52840"), Ok(52840));
        assert_eq!(parse_int::<u16>("0"), Ok(0));
        assert!(
            parse_int::<u16>("0x10000")
                .unwrap_err()
                .contains("out of range")
        );
        for bad in ["", "0x", "08", "-1", "x"] {
            assert!(parse_int::<u32>(bad).is_err(), "{bad:?}");
        }
        assert_eq!(int_or_none::<u32>("None"), Ok(OrNone(None)));
        assert_eq!(
            list_or_none("0xB6, 0xCA"),
            Ok(OrNone(Some(vec![0xB6, 0xCA])))
        );
        assert!(list_or_none("0xB6,").is_err());
    }

    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Args::command().debug_assert();
    }
}
