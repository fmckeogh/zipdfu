//! A minimal protocol buffers encoder, enough for the init packets defined in the nRF5 SDK's
//! `dfu-cc.proto`.
//!
//! That file uses proto2, where optional fields that are set are always written, even when they
//! hold the default value. Fields are written in the order the caller adds them, which should be
//! field-number order to match other encoders byte for byte.

#[derive(Debug, Default)]
pub struct Message {
    buf: Vec<u8>,
}

const WIRE_VARINT: u32 = 0;
const WIRE_LEN: u32 = 2;

impl Message {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn uint32(mut self, field: u32, value: u32) -> Self {
        self.key(field, WIRE_VARINT);
        self.varint(value.into());
        self
    }

    pub fn bool(self, field: u32, value: bool) -> Self {
        self.uint32(field, value.into())
    }

    pub fn bytes(mut self, field: u32, value: &[u8]) -> Self {
        self.key(field, WIRE_LEN);
        self.varint(value.len() as u64);
        self.buf.extend_from_slice(value);
        self
    }

    pub fn message(self, field: u32, value: Message) -> Self {
        self.bytes(field, &value.buf)
    }

    /// A `repeated uint32` field with `[packed = true]`; omitted entirely when empty.
    pub fn packed_uint32(self, field: u32, values: &[u32]) -> Self {
        if values.is_empty() {
            return self;
        }
        let mut packed = Message::new();
        for &value in values {
            packed.varint(value.into());
        }
        self.message(field, packed)
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    fn key(&mut self, field: u32, wire_type: u32) {
        self.varint(u64::from(field << 3 | wire_type));
    }

    fn varint(&mut self, mut value: u64) {
        while value >= 0x80 {
            self.buf.push(value as u8 | 0x80);
            value >>= 7;
        }
        self.buf.push(value as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_fields() {
        let bytes = Message::new()
            .uint32(1, 1)
            .uint32(2, 0)
            .uint32(7, 4664)
            .packed_uint32(3, &[0xB6, 0xFFFE])
            .packed_uint32(4, &[])
            .bool(9, false)
            .message(8, Message::new().bytes(2, b"ab"))
            .into_bytes();
        assert_eq!(
            bytes,
            [
                0x08, 0x01, // 1: 1
                0x10, 0x00, // 2: 0 (still written)
                0x38, 0xB8, 0x24, // 7: 4664
                0x1A, 0x05, 0xB6, 0x01, 0xFE, 0xFF, 0x03, // 3: [0xB6, 0xFFFE] packed
                0x48, 0x00, // 9: false
                0x42, 0x04, 0x12, 0x02, b'a', b'b', // 8: { 2: "ab" }
            ]
        );
    }

    #[test]
    fn encodes_large_varints() {
        let bytes = Message::new().uint32(1, u32::MAX).into_bytes();
        assert_eq!(bytes, [0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F]);
    }
}
