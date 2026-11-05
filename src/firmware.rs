//! Loading firmware as the flat binaries stored in packages, like adafruit-nrfutil's `nRFHex`.

use color_eyre::eyre::{OptionExt, Result, WrapErr, bail, ensure};
use std::fs;
use std::path::Path;

/// Data from here up (UICR, FICR, RAM, ...) is not part of a flash image.
const UICR_START: u32 = 0x1000_0000;
/// The magic number of a SoftDevice info structure, four bytes into it.
const SD_INFO_MAGIC: [u8; 4] = 0x51B1_E5DB_u32.to_le_bytes();

pub struct Firmware {
    /// The file name without its extension, which names the files in the package.
    pub name: String,
    pub data: Vec<u8>,
}

/// Loads a `.bin` file as is, or any other file as Intel HEX. The image is padded with 0xFF to a
/// multiple of four bytes.
pub fn load(path: &Path) -> Result<Firmware> {
    let name = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_eyre("invalid file name")?;
    let mut data = if path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("bin"))
    {
        fs::read(path).wrap_err_with(|| format!("cannot read '{}'", path.display()))?
    } else {
        let hex = fs::read_to_string(path)
            .wrap_err_with(|| format!("cannot read '{}'", path.display()))?;
        hex_to_bin(&hex).wrap_err_with(|| format!("cannot convert '{}'", path.display()))?
    };
    ensure!(!data.is_empty(), "'{}' is empty", path.display());
    data.resize(data.len().next_multiple_of(4), 0xFF);
    Ok(Firmware {
        name: name.to_owned(),
        data,
    })
}

/// Flattens Intel HEX from its lowest to its highest address, filling gaps with 0xFF. Data from
/// 0x10000000 up and in the Master Boot Record is left out.
fn hex_to_bin(hex: &str) -> Result<Vec<u8>> {
    let mut chunks = Vec::new();
    let mut base = 0;
    for (i, record) in ihex::Reader::new(hex).enumerate() {
        match record.wrap_err_with(|| format!("invalid record {}", i + 1))? {
            ihex::Record::Data { offset, mut value } => {
                let address = base + u32::from(offset);
                value.truncate(UICR_START.saturating_sub(address) as usize);
                if !value.is_empty() {
                    chunks.push((address, value));
                }
            }
            ihex::Record::ExtendedSegmentAddress(segment) => base = u32::from(segment) << 4,
            ihex::Record::ExtendedLinearAddress(upper) => base = u32::from(upper) << 16,
            // The reader stops at the end-of-file record, and start addresses don't matter.
            _ => {}
        }
    }

    chunks.sort_by_key(|&(address, _)| address);
    let end_of = |(address, data): &(u32, Vec<u8>)| address + data.len() as u32;
    if let Some(pair) = chunks.windows(2).find(|pair| pair[1].0 < end_of(&pair[0])) {
        bail!("data overlaps at address {:#010X}", pair[1].0);
    }
    let (Some(&(start, _)), Some(last)) = (chunks.first(), chunks.last()) else {
        bail!("no data below {UICR_START:#X}");
    };
    let end = end_of(last);
    let mut image = vec![0xFF; (end - start) as usize];
    for (address, data) in &chunks {
        let offset = (address - start) as usize;
        image[offset..offset + data.len()].copy_from_slice(data);
    }

    // The MBR ends at 0x1000, or at 0x3000 for early S132 SoftDevices, whose info structure is in
    // a later page. (Gaps read as 0xFF, which never matches the magic number.)
    let has_magic = |address: u32| {
        let rest = address
            .checked_sub(start)
            .and_then(|offset| image.get(offset as usize..));
        rest.is_some_and(|rest| rest.starts_with(&SD_INFO_MAGIC))
    };
    let mbr_end = if !has_magic(0x3004) && (1..=4).any(|i| has_magic(0x3004 + i * 0x1000)) {
        0x3000
    } else {
        0x1000
    };
    ensure!(
        end > mbr_end,
        "no data above the MBR, which ends at {mbr_end:#X}"
    );
    Ok(image.split_off(mbr_end.saturating_sub(start) as usize))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: u8, address: u16, data: &[u8]) -> String {
        let mut bytes = vec![data.len() as u8, (address >> 8) as u8, address as u8, kind];
        bytes.extend(data);
        bytes.push(bytes.iter().fold(0u8, |sum, b| sum.wrapping_sub(*b)));
        format!(
            ":{}\n",
            bytes.iter().map(|b| format!("{b:02X}")).collect::<String>()
        )
    }

    #[test]
    fn rejects_overlapping_data() {
        let hex = record(0, 0x2000, b"abcd") + &record(0, 0x2002, b"xy");
        assert_eq!(
            hex_to_bin(&hex).unwrap_err().to_string(),
            "data overlaps at address 0x00002002"
        );
    }

    #[test]
    fn rejects_files_without_flash_data() {
        let uicr = record(4, 0, &[0x10, 0x00]) + &record(0, 0x1014, &[0; 4]);
        assert_eq!(
            hex_to_bin(&uicr).unwrap_err().to_string(),
            "no data below 0x10000000"
        );
        let mbr = record(0, 0x0100, &[0; 4]);
        assert_eq!(
            hex_to_bin(&mbr).unwrap_err().to_string(),
            "no data above the MBR, which ends at 0x1000"
        );
    }

    #[test]
    fn rejects_invalid_records() {
        let err = hex_to_bin(&(record(0, 0x2000, b"ab") + ":00000001FE\n")).unwrap_err();
        assert!(
            format!("{err:#}").starts_with("invalid record 2: "),
            "{err:#}"
        );
    }
}
