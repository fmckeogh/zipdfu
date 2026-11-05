//! A minimal ZIP writer.
//!
//! Entries are stored uncompressed, as in the archives nrfutil writes (Python's `zipfile`
//! default). Unlike nrfutil, every entry gets the same timestamp and permissions, so the same
//! inputs always produce the same package.

use anyhow::{Result, bail};

use crate::crc::crc32;

const LOCAL_FILE_HEADER: u32 = 0x0403_4B50;
const CENTRAL_DIRECTORY_HEADER: u32 = 0x0201_4B50;
const END_OF_CENTRAL_DIRECTORY: u32 = 0x0605_4B50;
/// ZIP 2.0, created on Unix (so that the permissions below are honoured).
const VERSION_NEEDED: u16 = 20;
const VERSION_MADE_BY: u16 = 3 << 8 | 20;
const FLAG_UTF8_NAME: u16 = 1 << 11;
const METHOD_STORED: u16 = 0;
/// 1980-01-01 00:00:00, the earliest MS-DOS timestamp.
const DOS_TIME: u16 = 0;
const DOS_DATE: u16 = 1 << 5 | 1;
/// A regular file with mode rw-r--r--.
const EXTERNAL_ATTRIBUTES: u32 = 0o100644 << 16;

/// Builds a ZIP archive from `(name, contents)` pairs, in the given order.
pub fn build(entries: &[(&str, &[u8])]) -> Result<Vec<u8>> {
    // Without ZIP64 extensions, sizes and offsets must stay below the 0xFFFF / 0xFFFFFFFF markers.
    let total: usize = entries
        .iter()
        .map(|(name, data)| 76 + 2 * name.len() + data.len())
        .sum();
    if total >= u32::MAX as usize || entries.len() >= u16::MAX as usize {
        bail!("package is too large for a ZIP archive without ZIP64 extensions");
    }
    if let Some((name, _)) = entries
        .iter()
        .find(|(name, _)| name.len() >= u16::MAX as usize)
    {
        bail!("file name '{name}' is too long for a ZIP archive");
    }

    let mut out = Vec::with_capacity(total + 22);
    let mut central = Vec::new();
    for &(name, data) in entries {
        let offset = out.len() as u32;
        let flags = if name.is_ascii() { 0 } else { FLAG_UTF8_NAME };
        let crc = crc32(data);
        let (size, name_len) = (data.len() as u32, name.len() as u16);

        put32(&mut out, LOCAL_FILE_HEADER);
        put16(&mut out, VERSION_NEEDED);
        put16(&mut out, flags);
        put16(&mut out, METHOD_STORED);
        put16(&mut out, DOS_TIME);
        put16(&mut out, DOS_DATE);
        put32(&mut out, crc);
        put32(&mut out, size); // compressed
        put32(&mut out, size); // uncompressed
        put16(&mut out, name_len);
        put16(&mut out, 0); // extra field length
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);

        put32(&mut central, CENTRAL_DIRECTORY_HEADER);
        put16(&mut central, VERSION_MADE_BY);
        put16(&mut central, VERSION_NEEDED);
        put16(&mut central, flags);
        put16(&mut central, METHOD_STORED);
        put16(&mut central, DOS_TIME);
        put16(&mut central, DOS_DATE);
        put32(&mut central, crc);
        put32(&mut central, size);
        put32(&mut central, size);
        put16(&mut central, name_len);
        put16(&mut central, 0); // extra field length
        put16(&mut central, 0); // comment length
        put16(&mut central, 0); // disk number
        put16(&mut central, 0); // internal attributes
        put32(&mut central, EXTERNAL_ATTRIBUTES);
        put32(&mut central, offset);
        central.extend_from_slice(name.as_bytes());
    }

    let central_offset = out.len() as u32;
    let count = entries.len() as u16;
    out.extend_from_slice(&central);
    put32(&mut out, END_OF_CENTRAL_DIRECTORY);
    put16(&mut out, 0); // this disk
    put16(&mut out, 0); // disk with the central directory
    put16(&mut out, count); // entries on this disk
    put16(&mut out, count); // entries in total
    put32(&mut out, central.len() as u32);
    put32(&mut out, central_offset);
    put16(&mut out, 0); // comment length
    Ok(out)
}

fn put16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};

    use super::*;

    #[test]
    fn readable_by_zip_crate() {
        let archive = build(&[
            ("manifest.json", b"{}"),
            ("ünï.bin", &[0xFF; 1000]),
            ("empty.dat", b""),
        ])
        .unwrap();
        let mut zip = ::zip::ZipArchive::new(Cursor::new(archive)).unwrap();
        assert_eq!(zip.len(), 3);
        let expected: [(&str, &[u8]); 3] = [
            ("manifest.json", b"{}"),
            ("ünï.bin", &[0xFF; 1000]),
            ("empty.dat", b""),
        ];
        for (i, (name, data)) in expected.into_iter().enumerate() {
            let mut file = zip.by_index(i).unwrap();
            assert_eq!(file.name().unwrap(), name);
            assert_eq!(file.compression(), ::zip::CompressionMethod::Stored);
            assert_eq!(file.unix_mode(), Some(0o100644));
            let mut contents = Vec::new();
            file.read_to_end(&mut contents).unwrap(); // also verifies the CRC
            assert_eq!(contents, data);
        }
    }

    #[test]
    fn deterministic() {
        let entries: [(&str, &[u8]); 1] = [("a", b"abc")];
        assert_eq!(build(&entries).unwrap(), build(&entries).unwrap());
    }
}
