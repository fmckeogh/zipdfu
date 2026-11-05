//! Checksums used by the legacy init packet and the ZIP container.

/// CRC-16/CCITT-FALSE (polynomial 0x1021, initial value 0xFFFF).
///
/// This is `crc16_compute()` from the nRF5 SDK and `calc_crc16()` from nrfutil, which legacy
/// bootloaders use to verify a received image.
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc = crc.rotate_left(8) ^ u16::from(byte);
        crc ^= (crc & 0xFF) >> 4;
        crc ^= crc << 12;
        crc ^= (crc & 0xFF) << 5;
    }
    crc
}

/// CRC-32 as used by ZIP (IEEE 802.3, reflected, polynomial 0xEDB88320).
pub fn crc32(data: &[u8]) -> u32 {
    const TABLE: [u32; 256] = {
        let mut table = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut crc = i as u32;
            let mut bit = 0;
            while bit < 8 {
                crc = if crc & 1 != 0 {
                    0xEDB8_8320 ^ (crc >> 1)
                } else {
                    crc >> 1
                };
                bit += 1;
            }
            table[i] = crc;
            i += 1;
        }
        table
    };

    !data.iter().fold(!0u32, |crc, &byte| {
        TABLE[usize::from(crc as u8 ^ byte)] ^ (crc >> 8)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Standard check values from the CRC catalogue (input "123456789").
    #[test]
    fn crc16_check_value() {
        assert_eq!(crc16_ccitt(b"123456789"), 0x29B1);
        assert_eq!(crc16_ccitt(b""), 0xFFFF);
    }

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }
}
