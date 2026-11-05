//! Loading firmware files and converting them to the flat binaries stored in DFU packages.
//!
//! This reproduces nrfutil's `nRFHex`: a `.bin` file is taken as is, while a `.hex` file is
//! flattened from its lowest to its highest address with gaps filled with 0xFF. Data at or above
//! 0x10000000 (UICR and other non-flash regions) and in the Master Boot Record is left out. The
//! result is padded with 0xFF to a multiple of four bytes.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::ihex::{self, Memory};

/// The MBR occupies the first 4 KiB of flash; SoftDevice hex files include it but DFU must not.
const MBR_END: u64 = 0x1000;
/// Early S132 SoftDevices (identified by the location of their info structure) reserve 12 KiB.
const MBR_END_EARLY_S132: u64 = 0x3000;
/// Everything from here up (UICR, FICR, RAM, peripherals) is not part of a flash image.
const UICR_START: u64 = 0x1000_0000;
/// Magic number of the SoftDevice info structure, located at offset 4 of the structure.
const SD_INFO_MAGIC: u32 = 0x51B1_E5DB;
const SD_INFO_MAGIC_ADDRESS: u64 = 0x3004;

/// How data below the end of the MBR is treated when flattening a hex file.
///
/// The two tools differ only for a hex file with data below 0x1000 followed by a gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MbrHandling {
    /// nrfutil 6: MBR data is discarded, so the image starts at the lowest remaining address.
    Discard,
    /// adafruit-nrfutil (nrfutil 0.5): MBR data still counts as the lowest address, so the image
    /// starts at the end of the MBR and the gap up to the next data is filled with 0xFF.
    Clip,
}

/// A firmware image ready to be packaged.
#[derive(Debug)]
pub struct Firmware {
    /// File name without directory and extension; the package stores `<stem>.bin` and `<stem>.dat`.
    pub stem: String,
    /// The flat binary image.
    pub data: Vec<u8>,
}

/// Loads a `.bin` (by extension, case-insensitively) or Intel HEX (anything else) file.
pub fn load(path: &Path, mbr: MbrHandling) -> Result<Firmware> {
    let stem = path
        .file_stem()
        .with_context(|| format!("'{}' is not a file name", path.display()))?
        .to_str()
        .with_context(|| format!("file name '{}' is not valid UTF-8", path.display()))?
        .to_owned();
    let contents = fs::read(path).with_context(|| format!("cannot read '{}'", path.display()))?;

    let is_bin = path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("bin"));
    let data = if is_bin {
        flatten_bin(contents)
    } else {
        let memory = ihex::parse(&contents)
            .with_context(|| format!("'{}' is not a valid Intel HEX file", path.display()))?;
        flatten_hex(memory, mbr)
    }
    .with_context(|| format!("cannot use '{}'", path.display()))?;

    Ok(Firmware { stem, data })
}

fn flatten_bin(mut data: Vec<u8>) -> Result<Vec<u8>> {
    if data.is_empty() {
        bail!("the file is empty");
    }
    data.resize(word_align(data.len() as u64) as usize, 0xFF);
    Ok(data)
}

fn flatten_hex(mut memory: Memory, mbr: MbrHandling) -> Result<Vec<u8>> {
    let lowest = match mbr {
        MbrHandling::Discard => MBR_END,
        MbrHandling::Clip => 0,
    };
    memory.retain(lowest..UICR_START);
    let (Some(min), Some(max)) = (memory.min_address(), memory.max_address()) else {
        bail!("the file contains no data below {UICR_START:#X} outside the MBR");
    };

    let mbr_end = mbr_end(&memory);
    let start = min.max(mbr_end);
    if start > max {
        bail!("the file contains no data above the MBR (which ends at {mbr_end:#X})");
    }
    let len = usize::try_from(word_align(max - start + 1)).context("image is too large")?;
    Ok(memory.to_vec(start, len, 0xFF))
}

/// Where the MBR ends, judging by the location of a SoftDevice info structure (if any).
fn mbr_end(memory: &Memory) -> u64 {
    let has_magic = |address| memory.read_u32_le(address) == Some(SD_INFO_MAGIC);
    if has_magic(SD_INFO_MAGIC_ADDRESS) {
        MBR_END
    } else if (1..=4).any(|i| has_magic(SD_INFO_MAGIC_ADDRESS + i * 0x1000)) {
        MBR_END_EARLY_S132
    } else {
        MBR_END
    }
}

fn word_align(len: u64) -> u64 {
    len.next_multiple_of(4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ihex::testing::hex_file;

    fn flatten(chunks: &[(u32, &[u8])], mbr: MbrHandling) -> Result<Vec<u8>> {
        flatten_hex(ihex::parse(hex_file(chunks).as_bytes()).unwrap(), mbr)
    }

    #[test]
    fn bin_is_padded_to_words() {
        assert_eq!(
            flatten_bin(vec![1, 2, 3, 4, 5]).unwrap(),
            [1, 2, 3, 4, 5, 0xFF, 0xFF, 0xFF]
        );
        assert_eq!(flatten_bin(vec![1, 2, 3, 4]).unwrap(), [1, 2, 3, 4]);
        assert!(flatten_bin(Vec::new()).is_err());
    }

    #[test]
    fn hex_gaps_are_filled_and_padded() {
        for mbr in [MbrHandling::Discard, MbrHandling::Clip] {
            let image = flatten(&[(0x26000, b"ab"), (0x26004, b"c")], mbr).unwrap();
            assert_eq!(image, [b'a', b'b', 0xFF, 0xFF, b'c', 0xFF, 0xFF, 0xFF]);
        }
    }

    #[test]
    fn uicr_is_dropped() {
        let image = flatten(
            &[(0xF4000, &[1; 6]), (0x1000_1014, &[0, 0x40, 0x0F, 0])],
            MbrHandling::Discard,
        )
        .unwrap();
        assert_eq!(image, [1, 1, 1, 1, 1, 1, 0xFF, 0xFF]);
        assert!(flatten(&[(0x1000_1014, &[0; 4])], MbrHandling::Clip).is_err());
    }

    #[test]
    fn softdevice_mbr_is_dropped() {
        let mut magic_page = vec![0; 8];
        magic_page[4..].copy_from_slice(&SD_INFO_MAGIC.to_le_bytes());
        let chunks: [(u32, &[u8]); 3] = [
            (0, &[0xAA; 16]),
            (0x1000, &[0xBB; 4]),
            (0x3000, &magic_page),
        ];
        for mbr in [MbrHandling::Discard, MbrHandling::Clip] {
            let image = flatten(&chunks, mbr).unwrap();
            assert_eq!(image.len(), 0x2008);
            assert_eq!(image[..4], [0xBB; 4]);
            assert_eq!(image[0x2004..], SD_INFO_MAGIC.to_le_bytes());
        }
    }

    #[test]
    fn early_s132_reserves_12k() {
        let mut magic_page = vec![0; 8];
        magic_page[4..].copy_from_slice(&SD_INFO_MAGIC.to_le_bytes());
        let chunks: [(u32, &[u8]); 3] = [
            (0, &[0xAA; 16]),
            (0x2000, &[0xBB; 16]),
            (0x5000, &magic_page),
        ];
        let image = flatten(&chunks, MbrHandling::Discard).unwrap();
        assert_eq!(image.len(), 0x2008, "starts at 0x3000");
        assert!(image[..0x2000].iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn mbr_data_before_a_gap_depends_on_the_tool() {
        let chunks: [(u32, &[u8]); 2] = [(0, &[0xAA; 16]), (0x2000, &[0xBB; 4])];
        // nrfutil 6 ignores the MBR data entirely...
        assert_eq!(flatten(&chunks, MbrHandling::Discard).unwrap(), [0xBB; 4]);
        // ...while adafruit-nrfutil starts the image at the end of the MBR.
        let image = flatten(&chunks, MbrHandling::Clip).unwrap();
        assert_eq!(image.len(), 0x1004);
        assert!(image[..0x1000].iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn mbr_only_is_an_error() {
        for mbr in [MbrHandling::Discard, MbrHandling::Clip] {
            assert!(flatten(&[(0x100, &[1; 4])], mbr).is_err());
        }
    }
}
