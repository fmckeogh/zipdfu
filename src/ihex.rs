//! Intel HEX parsing.
//!
//! The accepted syntax follows the Python `intelhex` package used by nrfutil: record types 00-05,
//! a data record crossing a 64 KiB boundary continues at the next address instead of wrapping,
//! overlapping data is an error, and anything after the end-of-file record is ignored. Unlike
//! `intelhex`, whitespace around a record is tolerated.

use std::ops::Range;

use anyhow::{Context, Result, bail};

/// Sparse memory contents loaded from an Intel HEX file.
#[derive(Debug, Default)]
pub struct Memory {
    /// Non-overlapping chunks, sorted by address.
    chunks: Vec<Chunk>,
}

#[derive(Debug)]
struct Chunk {
    address: u64,
    data: Vec<u8>,
}

impl Chunk {
    fn end(&self) -> u64 {
        self.address + self.data.len() as u64
    }
}

impl Memory {
    /// The lowest address that holds data.
    pub fn min_address(&self) -> Option<u64> {
        self.chunks.first().map(|c| c.address)
    }

    /// The highest address that holds data.
    pub fn max_address(&self) -> Option<u64> {
        self.chunks.last().map(|c| c.end() - 1)
    }

    /// Discards all data outside `keep`.
    pub fn retain(&mut self, keep: Range<u64>) {
        self.chunks.retain_mut(|chunk| {
            let start = chunk.address.max(keep.start);
            let end = chunk.end().min(keep.end);
            if start >= end {
                return false;
            }
            chunk.data.truncate((end - chunk.address) as usize);
            chunk.data.drain(..(start - chunk.address) as usize);
            chunk.address = start;
            true
        });
    }

    fn byte_at(&self, address: u64) -> Option<u8> {
        let index = self
            .chunks
            .partition_point(|c| c.address <= address)
            .checked_sub(1)?;
        let chunk = &self.chunks[index];
        chunk
            .data
            .get(usize::try_from(address - chunk.address).ok()?)
            .copied()
    }

    /// Reads a little-endian word, if all four bytes hold data.
    pub fn read_u32_le(&self, address: u64) -> Option<u32> {
        let mut bytes = [0; 4];
        for (offset, byte) in (0..).zip(&mut bytes) {
            *byte = self.byte_at(address + offset)?;
        }
        Some(u32::from_le_bytes(bytes))
    }

    /// Returns `len` bytes starting at `start`, with `fill` wherever there is no data.
    pub fn to_vec(&self, start: u64, len: usize, fill: u8) -> Vec<u8> {
        let mut out = vec![fill; len];
        let end = start + len as u64;
        for chunk in &self.chunks {
            let (from, to) = (chunk.address.max(start), chunk.end().min(end));
            if from < to {
                let src =
                    &chunk.data[(from - chunk.address) as usize..(to - chunk.address) as usize];
                out[(from - start) as usize..(to - start) as usize].copy_from_slice(src);
            }
        }
        out
    }
}

/// Parses an Intel HEX file.
pub fn parse(input: &[u8]) -> Result<Memory> {
    let mut chunks: Vec<Chunk> = Vec::new();
    let mut base: u64 = 0;

    for (index, line) in input.split(|&b| b == b'\n').enumerate() {
        let line = line.trim_ascii();
        if line.is_empty() {
            continue;
        }
        let record = Record::decode(line).with_context(|| format!("line {}", index + 1))?;
        match record.kind {
            DATA => {
                let address = base + u64::from(record.address);
                match chunks.last_mut() {
                    Some(chunk) if chunk.end() == address => {
                        chunk.data.extend_from_slice(record.data())
                    }
                    _ => chunks.push(Chunk {
                        address,
                        data: record.data().to_vec(),
                    }),
                }
            }
            END_OF_FILE => break,
            EXTENDED_SEGMENT_ADDRESS => base = u64::from(record.data_u16()) << 4,
            EXTENDED_LINEAR_ADDRESS => base = u64::from(record.data_u16()) << 16,
            // Start addresses are irrelevant for a flash image.
            _ => {}
        }
    }

    chunks.sort_by_key(|c| c.address);
    if let Some(pair) = chunks
        .windows(2)
        .find(|pair| pair[1].address < pair[0].end())
    {
        bail!("data overlaps at address {:#010X}", pair[1].address);
    }
    Ok(Memory { chunks })
}

const DATA: u8 = 0x00;
const END_OF_FILE: u8 = 0x01;
const EXTENDED_SEGMENT_ADDRESS: u8 = 0x02;
const START_SEGMENT_ADDRESS: u8 = 0x03;
const EXTENDED_LINEAR_ADDRESS: u8 = 0x04;
const START_LINEAR_ADDRESS: u8 = 0x05;

struct Record {
    kind: u8,
    address: u16,
    /// The whole decoded record: length, address, type, data and checksum.
    bytes: Vec<u8>,
}

impl Record {
    /// Decodes one `:LLAAAATT<data>CC` line.
    fn decode(line: &[u8]) -> Result<Self> {
        let Some(digits) = line.strip_prefix(b":") else {
            bail!("record does not start with ':'");
        };
        let (pairs, []) = digits.as_chunks::<2>() else {
            bail!("odd number of hex digits");
        };
        let bytes = pairs
            .iter()
            .map(|pair| {
                let text = std::str::from_utf8(pair).ok();
                text.and_then(|t| u8::from_str_radix(t, 16).ok())
                    .with_context(|| {
                        format!("invalid hex digits '{}'", String::from_utf8_lossy(pair))
                    })
            })
            .collect::<Result<Vec<u8>>>()?;
        if bytes.len() < 5 {
            bail!("record is too short");
        }
        let len = usize::from(bytes[0]);
        if bytes.len() != len + 5 {
            bail!("record length {len} does not match its contents");
        }
        if bytes.iter().fold(0u8, |sum, &b| sum.wrapping_add(b)) != 0 {
            bail!("checksum mismatch");
        }
        let kind = bytes[3];
        let address = u16::from_be_bytes([bytes[1], bytes[2]]);
        let well_formed = match kind {
            DATA => true,
            END_OF_FILE => len == 0,
            EXTENDED_SEGMENT_ADDRESS | EXTENDED_LINEAR_ADDRESS => len == 2 && address == 0,
            START_SEGMENT_ADDRESS | START_LINEAR_ADDRESS => len == 4 && address == 0,
            _ => bail!("unknown record type {kind:02X}"),
        };
        if !well_formed {
            bail!("malformed record of type {kind:02X}");
        }
        Ok(Record {
            kind,
            address,
            bytes,
        })
    }

    fn data(&self) -> &[u8] {
        &self.bytes[4..self.bytes.len() - 1]
    }

    fn data_u16(&self) -> u16 {
        u16::from_be_bytes([self.bytes[4], self.bytes[5]])
    }
}

/// Helpers for writing Intel HEX in tests.
#[cfg(test)]
pub mod testing {
    /// Formats one record, computing its checksum.
    pub fn record(kind: u8, address: u16, data: &[u8]) -> String {
        let [hi, lo] = address.to_be_bytes();
        let mut bytes = vec![data.len() as u8, hi, lo, kind];
        bytes.extend_from_slice(data);
        bytes.push(bytes.iter().fold(0u8, |sum, &b| sum.wrapping_sub(b)));
        let digits: String = bytes.iter().map(|b| format!("{b:02X}")).collect();
        format!(":{digits}\n")
    }

    /// A hex file holding `chunks` of `(address, data)`, using extended linear address records.
    pub fn hex_file(chunks: &[(u32, &[u8])]) -> String {
        let mut out = String::new();
        for &(address, data) in chunks {
            for (i, piece) in data.chunks(16).enumerate() {
                let address = address + 16 * i as u32;
                out += &record(0x04, 0, &((address >> 16) as u16).to_be_bytes());
                out += &record(0x00, address as u16, piece);
            }
        }
        out + &record(0x01, 0, &[])
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{hex_file, record};
    use super::*;

    fn bytes(memory: &Memory, start: u64, len: usize) -> Vec<u8> {
        memory.to_vec(start, len, 0xEE)
    }

    #[test]
    fn data_and_extended_linear_addresses() {
        let memory =
            parse(hex_file(&[(0x0002_6000, b"abc"), (0x1000_1014, &[1, 2, 3, 4])]).as_bytes())
                .unwrap();
        assert_eq!(memory.min_address(), Some(0x26000));
        assert_eq!(memory.max_address(), Some(0x1000_1017));
        assert_eq!(bytes(&memory, 0x25FFF, 5), [0xEE, b'a', b'b', b'c', 0xEE]);
        assert_eq!(memory.read_u32_le(0x1000_1014), Some(0x0403_0201));
        assert_eq!(memory.read_u32_le(0x1000_1015), None);
    }

    #[test]
    fn extended_segment_addresses() {
        let text =
            record(0x02, 0, &[0x10, 0x00]) + &record(0x00, 0x0010, b"xy") + &record(0x01, 0, &[]);
        let memory = parse(text.as_bytes()).unwrap();
        assert_eq!(memory.min_address(), Some(0x10010));
    }

    #[test]
    fn records_do_not_wrap_at_64k() {
        // Like Python's intelhex, a record crossing a segment boundary simply continues.
        let memory =
            parse((record(0x00, 0xFFFE, b"abcd") + &record(0x01, 0, &[])).as_bytes()).unwrap();
        assert_eq!(bytes(&memory, 0xFFFE, 4), *b"abcd");
    }

    #[test]
    fn lenient_formatting() {
        let text = format!(
            "\r\n  {}\r\n\n{}\t\r\n",
            record(0x00, 0x10, b"ab").trim(),
            record(0x05, 0, &[0, 0, 0, 1]).trim()
        )
        .to_lowercase();
        let memory = parse(text.as_bytes()).unwrap(); // no end-of-file record either
        assert_eq!(bytes(&memory, 0x10, 2), *b"ab");
    }

    #[test]
    fn stops_at_end_of_file() {
        let text = record(0x00, 0, b"a") + &record(0x01, 0, &[]) + "garbage\n";
        assert_eq!(parse(text.as_bytes()).unwrap().max_address(), Some(0));
    }

    #[test]
    fn merges_adjacent_records_and_retains_ranges() {
        let mut memory = parse(hex_file(&[(0x0FF8, &[7; 40])]).as_bytes()).unwrap();
        assert_eq!(memory.chunks.len(), 1);
        memory.retain(0x1000..0x1008);
        assert_eq!(
            (memory.min_address(), memory.max_address()),
            (Some(0x1000), Some(0x1007))
        );
        memory.retain(0x2000..0x3000);
        assert_eq!(memory.min_address(), None);
    }

    #[test]
    fn errors() {
        let cases = [
            ("10000000", "line 1: record does not start with ':'"),
            (":0", "line 1: odd number of hex digits"),
            (":0G", "line 1: invalid hex digits '0G'"),
            (":00000001", "line 1: record is too short"),
            (
                ":0100000000",
                "line 1: record length 1 does not match its contents",
            ),
            (":00000001FE", "line 1: checksum mismatch"),
            (":00000006FA", "line 1: unknown record type 06"),
            (":0100000400FB", "line 1: malformed record of type 04"),
            (":0100000100FE", "line 1: malformed record of type 01"),
        ];
        for (text, expected) in cases {
            assert_eq!(
                format!("{:#}", parse(text.as_bytes()).unwrap_err()),
                expected,
                "{text}"
            );
        }
        let line3 = format!("\n{}{}", record(0x00, 0, b"a"), ":00000001FE");
        assert_eq!(
            format!("{:#}", parse(line3.as_bytes()).unwrap_err()),
            "line 3: checksum mismatch"
        );
    }

    #[test]
    fn overlapping_data_is_an_error() {
        let text = record(0x00, 0x10, b"abcd") + &record(0x00, 0x00, &[0; 0x12]);
        assert_eq!(
            parse(text.as_bytes()).unwrap_err().to_string(),
            "data overlaps at address 0x00000010"
        );
    }
}
