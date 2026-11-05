//! Legacy DFU packages for nRF5 SDK 11 and earlier bootloaders, including the Adafruit nRF52
//! bootloader, as created by `adafruit-nrfutil dfu genpkg` (and pc-nrfutil 0.5).
//!
//! The init packet is the SDK's packed little-endian `dfu_init_packet_t` (device type, device
//! revision, application version, SoftDevice list), followed by an extension that depends on the
//! DFU version:
//!
//! | version | extension                                                     |
//! |---------|---------------------------------------------------------------|
//! | 0.5     | CRC-16 of the image                                           |
//! | 0.6     | extended packet ID 0, CRC-16                                  |
//! | 0.7     | extended packet ID 1, image length, SHA-256 of the image      |
//! | 0.8     | as 0.7, then an ECDSA P-256 signature of the packet so far    |
//!
//! Output for 0.5 and 0.6 matches adafruit-nrfutil byte for byte, apart from ZIP metadata such
//! as timestamps. adafruit-nrfutil crashes on 0.7 and 0.8 under Python 3, so those follow its
//! source code (which is unchanged from pc-nrfutil 0.5) instead.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::crc::crc16_ccitt;
use crate::firmware::{self, Firmware, MbrHandling};
use crate::json::Value;
use crate::package::{self, Image, Role, SD_BL_STEM};
use crate::signing::{SigningKey, hex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DfuVersion {
    V0_5,
    V0_6,
    V0_7,
    V0_8,
}

impl DfuVersion {
    const ALL: [(DfuVersion, &str, f64); 4] = [
        (DfuVersion::V0_5, "0.5", 0.5),
        (DfuVersion::V0_6, "0.6", 0.6),
        (DfuVersion::V0_7, "0.7", 0.7),
        (DfuVersion::V0_8, "0.8", 0.8),
    ];

    /// Parses a version number such as `0.5` (or `.5`, `0.50`).
    pub fn parse(s: &str) -> Result<Self, String> {
        let number: f64 = s
            .trim()
            .parse()
            .map_err(|_| format!("'{s}' is not a number"))?;
        Self::ALL
            .into_iter()
            .find(|&(_, _, n)| n == number)
            .map(|(version, _, _)| version)
            .ok_or_else(|| "supported versions are 0.5, 0.6, 0.7 and 0.8".to_owned())
    }

    fn as_str(self) -> &'static str {
        Self::ALL
            .into_iter()
            .find(|&(v, _, _)| v == self)
            .map(|(_, s, _)| s)
            .unwrap()
    }
}

/// Values of the extended packet ID field.
const EXT_PACKET_ID_CRC16: u32 = 0;
const EXT_PACKET_ID_HASH: u32 = 1;
const EXT_PACKET_ID_ECDSA: u32 = 2;

#[derive(Debug)]
pub struct Config {
    /// `None` leaves the field out of the init packet altogether.
    pub dev_type: Option<u16>,
    /// `None` leaves the field out of the init packet altogether.
    pub dev_revision: Option<u16>,
    /// `None` leaves the field out of the init packet altogether.
    pub app_version: Option<u32>,
    /// SoftDevice firmware IDs, as given (order and duplicates are kept).
    pub sd_req: Vec<u16>,
    pub dfu_version: DfuVersion,
    /// Required for (and only used by) DFU version 0.8.
    pub signing_key: Option<SigningKey>,
    pub application: Option<PathBuf>,
    pub bootloader: Option<PathBuf>,
    pub softdevice: Option<PathBuf>,
}

/// Creates the package and returns the ZIP archive.
pub fn build(config: &Config) -> Result<Vec<u8>> {
    let mut images = Vec::new();

    match (&config.softdevice, &config.bootloader) {
        (Some(sd), Some(bl)) => {
            // A SoftDevice and bootloader are merged into a single image.
            let sd = load(sd)?;
            let bl = load(bl)?;
            let sizes = [
                ("bl_size", Value::Int(bl.data.len() as u64)),
                ("sd_size", Value::Int(sd.data.len() as u64)),
            ];
            let data = [sd.data, bl.data].concat();
            let mut image = image(
                config,
                Role::SoftDeviceBootloader,
                SD_BL_STEM.to_owned(),
                data,
            )?;
            image.manifest_fields.extend(sizes);
            images.push(image);
        }
        (Some(sd), None) => {
            let fw = load(sd)?;
            images.push(image(config, Role::SoftDevice, fw.stem, fw.data)?);
        }
        (None, Some(bl)) => {
            let fw = load(bl)?;
            images.push(image(config, Role::Bootloader, fw.stem, fw.data)?);
        }
        (None, None) => {}
    }

    if let Some(app) = &config.application {
        let fw = load(app)?;
        images.push(image(config, Role::Application, fw.stem, fw.data)?);
    }

    let dfu_version = Value::Number(config.dfu_version.as_str());
    package::archive(&images, BTreeMap::from([("dfu_version", dfu_version)]))
}

fn load(path: &Path) -> Result<Firmware> {
    firmware::load(path, MbrHandling::Clip)
}

fn image(config: &Config, role: Role, stem: String, bin: Vec<u8>) -> Result<Image> {
    let (dat, fields) = init_packet(config, &bin)?;
    let manifest_fields = BTreeMap::from([("init_packet_data", Value::Object(fields))]);
    Ok(Image {
        role,
        stem,
        bin,
        dat,
        manifest_fields,
    })
}

/// Encodes the `.dat` file, and returns it with its description for the manifest.
fn init_packet(config: &Config, data: &[u8]) -> Result<(Vec<u8>, BTreeMap<&'static str, Value>)> {
    let mut packet = Vec::new();
    let mut fields = BTreeMap::new();

    if let Some(dev_type) = config.dev_type {
        packet.extend(dev_type.to_le_bytes());
        fields.insert("device_type", dev_type.into());
    }
    if let Some(dev_revision) = config.dev_revision {
        packet.extend(dev_revision.to_le_bytes());
        fields.insert("device_revision", dev_revision.into());
    }
    if let Some(app_version) = config.app_version {
        packet.extend(app_version.to_le_bytes());
        fields.insert("application_version", app_version.into());
    }
    let count = u16::try_from(config.sd_req.len()).context("too many SoftDevice IDs")?;
    packet.extend(count.to_le_bytes());
    for id in &config.sd_req {
        packet.extend(id.to_le_bytes());
    }
    fields.insert(
        "softdevice_req",
        Value::Array(config.sd_req.iter().map(|&id| id.into()).collect()),
    );

    let length = u32::try_from(data.len()).context("image is larger than 4 GiB")?;
    match config.dfu_version {
        DfuVersion::V0_5 | DfuVersion::V0_6 => {
            if config.dfu_version == DfuVersion::V0_6 {
                packet.extend(EXT_PACKET_ID_CRC16.to_le_bytes());
                fields.insert("ext_packet_id", EXT_PACKET_ID_CRC16.into());
            }
            let crc = crc16_ccitt(data);
            packet.extend(crc.to_le_bytes());
            fields.insert("firmware_crc16", crc.into());
        }
        DfuVersion::V0_7 | DfuVersion::V0_8 => {
            let id = if config.dfu_version == DfuVersion::V0_7 {
                EXT_PACKET_ID_HASH
            } else {
                EXT_PACKET_ID_ECDSA
            };
            let hash = Sha256::digest(data);
            packet.extend(id.to_le_bytes());
            packet.extend(length.to_le_bytes());
            packet.extend_from_slice(&hash);
            fields.insert("ext_packet_id", id.into());
            fields.insert("firmware_length", length.into());
            fields.insert("firmware_hash", hex(&hash).into());

            if config.dfu_version == DfuVersion::V0_8 {
                let key = config
                    .signing_key
                    .as_ref()
                    .context("DFU version 0.8 requires a signing key")?;
                let signature = key.sign(&packet)?.to_be_bytes();
                packet.extend(signature);
                fields.insert("init_packet_ecds", hex(&signature).into());
            }
        }
    }
    Ok((packet, fields))
}
