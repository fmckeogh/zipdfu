//! Secure DFU packages for nRF5 SDK 12 and later bootloaders, as created by `nrfutil pkg generate`.
//!
//! Each init packet is a protocol buffers `Packet` message from the SDK's `dfu-cc.proto`. When a
//! key is given, it is a `SignedCommand` whose signature covers the serialized `InitCommand`.
//! The output matches pc-nrfutil 6.1.7 byte for byte, apart from signatures (nrfutil uses random
//! nonces) and ZIP metadata such as timestamps.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::firmware::{self, Firmware, MbrHandling};
use crate::json::Value;
use crate::package::{self, Image, Role, SD_BL_STEM};
use crate::protobuf::Message;
use crate::pyset;
use crate::signing::SigningKey;

/// How the bootloader validates an image at boot (`ValidationType` in `dfu-cc.proto`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum BootValidation {
    #[value(name = "NO_VALIDATION")]
    None,
    #[value(name = "VALIDATE_GENERATED_CRC")]
    Crc,
    #[value(name = "VALIDATE_GENERATED_SHA256")]
    Sha256,
    #[value(name = "VALIDATE_ECDSA_P256_SHA256")]
    EcdsaP256Sha256,
}

impl BootValidation {
    fn proto_value(self) -> u32 {
        match self {
            BootValidation::None => 0,
            BootValidation::Crc => 1,
            BootValidation::Sha256 => 2,
            BootValidation::EcdsaP256Sha256 => 3,
        }
    }
}

/// `FwType` in `dfu-cc.proto`.
#[derive(Debug, Clone, Copy)]
enum FwType {
    Application = 0,
    SoftDevice = 1,
    Bootloader = 2,
    SoftDeviceBootloader = 3,
    ExternalApplication = 4,
}

const OP_CODE_INIT: u32 = 1;
const HASH_TYPE_SHA256: u32 = 3;
const SIGNATURE_TYPE_ECDSA_P256_SHA256: u32 = 0;
/// The "any SoftDevice" ID, which nrfutil uses when no requirement is given.
const SD_ANY: u32 = 0xFFFE;
/// SoftDevice images are not versioned.
const SD_FW_VERSION: u32 = 0xFFFF_FFFF;

#[derive(Debug)]
pub struct Config {
    pub hw_version: u32,
    pub debug_mode: bool,
    /// SoftDevice IDs required by the SoftDevice and bootloader images.
    pub sd_req: Vec<u32>,
    /// SoftDevice IDs required by the application image.
    pub app_sd_req: Vec<u32>,
    pub application: Option<Application>,
    pub bootloader: Option<Bootloader>,
    pub softdevice: Option<SoftDevice>,
    pub signing_key: Option<SigningKey>,
}

#[derive(Debug)]
pub struct Application {
    pub path: PathBuf,
    pub version: u32,
    pub boot_validation: BootValidation,
    /// The image is passed on rather than applied by the receiving device.
    pub external: bool,
}

#[derive(Debug)]
pub struct Bootloader {
    pub path: PathBuf,
    pub version: u32,
}

#[derive(Debug)]
pub struct SoftDevice {
    pub path: PathBuf,
    pub boot_validation: BootValidation,
}

/// The fields of an image's `InitCommand` that differ between images.
struct InitCommand<'a> {
    fw_type: FwType,
    fw_version: u32,
    sd_req: &'a [u32],
    sd_size: u32,
    bl_size: u32,
    app_size: u32,
    boot_validation: Vec<(BootValidation, Vec<u8>)>,
}

/// Creates the package and returns the ZIP archive.
pub fn build(config: &Config) -> Result<Vec<u8>> {
    let mut images = Vec::new();

    match (&config.softdevice, &config.bootloader) {
        (Some(sd), Some(bl)) => {
            // A SoftDevice and bootloader are merged into a single image.
            let sd_fw = load(&sd.path)?;
            let bl_fw = load(&bl.path)?;
            let command = InitCommand {
                fw_type: FwType::SoftDeviceBootloader,
                fw_version: bl.version,
                sd_req: &config.sd_req,
                sd_size: size(&sd_fw)?,
                bl_size: size(&bl_fw)?,
                app_size: 0,
                // A boot validation signature covers only the SoftDevice part.
                boot_validation: vec![
                    boot_validation(config, sd.boot_validation, &sd_fw.data)?,
                    (BootValidation::Crc, Vec::new()),
                ],
            };
            // The sizes let DFU controllers split the merged image again.
            let sizes = Value::object([
                ("bl_size", command.bl_size.into()),
                ("sd_size", command.sd_size.into()),
            ]);
            let data = [sd_fw.data, bl_fw.data].concat();
            let mut image = image(
                config,
                Role::SoftDeviceBootloader,
                SD_BL_STEM.to_owned(),
                data,
                &command,
            )?;
            image
                .manifest_fields
                .insert("info_read_only_metadata", sizes);
            images.push(image);
        }
        (Some(sd), None) => {
            let fw = load(&sd.path)?;
            let command = InitCommand {
                fw_type: FwType::SoftDevice,
                fw_version: SD_FW_VERSION,
                sd_req: &config.sd_req,
                sd_size: size(&fw)?,
                bl_size: 0,
                app_size: 0,
                boot_validation: vec![boot_validation(config, sd.boot_validation, &fw.data)?],
            };
            images.push(image(config, Role::SoftDevice, fw.stem, fw.data, &command)?);
        }
        (None, Some(bl)) => {
            let fw = load(&bl.path)?;
            let command = InitCommand {
                fw_type: FwType::Bootloader,
                fw_version: bl.version,
                sd_req: &config.sd_req,
                sd_size: 0,
                bl_size: size(&fw)?,
                app_size: 0,
                boot_validation: vec![(BootValidation::Crc, Vec::new())],
            };
            images.push(image(config, Role::Bootloader, fw.stem, fw.data, &command)?);
        }
        (None, None) => {}
    }

    if let Some(app) = &config.application {
        let fw = load(&app.path)?;
        let command = InitCommand {
            fw_type: if app.external {
                FwType::ExternalApplication
            } else {
                FwType::Application
            },
            fw_version: app.version,
            sd_req: &config.app_sd_req,
            sd_size: 0,
            bl_size: 0,
            app_size: size(&fw)?,
            boot_validation: vec![boot_validation(config, app.boot_validation, &fw.data)?],
        };
        images.push(image(
            config,
            Role::Application,
            fw.stem,
            fw.data,
            &command,
        )?);
    }

    package::archive(&images, BTreeMap::new())
}

fn load(path: &Path) -> Result<Firmware> {
    firmware::load(path, MbrHandling::Discard)
}

fn size(fw: &Firmware) -> Result<u32> {
    u32::try_from(fw.data.len()).context("image is larger than 4 GiB")
}

fn boot_validation(
    config: &Config,
    kind: BootValidation,
    data: &[u8],
) -> Result<(BootValidation, Vec<u8>)> {
    // The bootloader computes CRCs and hashes itself; only a signature has to be supplied.
    let bytes = if kind == BootValidation::EcdsaP256Sha256 {
        let key = config
            .signing_key
            .as_ref()
            .context("ECDSA boot validation requires a signing key")?;
        key.sign(data)?.to_le_bytes().to_vec()
    } else {
        Vec::new()
    };
    Ok((kind, bytes))
}

fn image(
    config: &Config,
    role: Role,
    stem: String,
    bin: Vec<u8>,
    command: &InitCommand,
) -> Result<Image> {
    let dat = init_packet(config, command, &bin)?;
    Ok(Image {
        role,
        stem,
        bin,
        dat,
        manifest_fields: BTreeMap::new(),
    })
}

/// Encodes the `.dat` file: a `Packet` holding a plain or signed `Command`.
fn init_packet(config: &Config, command: &InitCommand, data: &[u8]) -> Result<Vec<u8>> {
    // nrfutil stores the digest in little-endian byte order, as the bootloader expects.
    let mut hash: [u8; 32] = Sha256::digest(data).into();
    hash.reverse();
    let sd_req = if command.sd_req.is_empty() {
        vec![SD_ANY]
    } else {
        pyset::set_order(command.sd_req)
    };

    let mut init = Message::new()
        .uint32(1, command.fw_version)
        .uint32(2, config.hw_version)
        .packed_uint32(3, &sd_req)
        .uint32(4, command.fw_type as u32)
        .uint32(5, command.sd_size)
        .uint32(6, command.bl_size)
        .uint32(7, command.app_size)
        .message(
            8,
            Message::new().uint32(1, HASH_TYPE_SHA256).bytes(2, &hash),
        )
        .bool(9, config.debug_mode);
    for (kind, bytes) in &command.boot_validation {
        init = init.message(
            10,
            Message::new().uint32(1, kind.proto_value()).bytes(2, bytes),
        );
    }
    let init = init.into_bytes();

    let command = Message::new().uint32(1, OP_CODE_INIT).bytes(2, &init);
    let packet = match &config.signing_key {
        None => Message::new().message(1, command),
        Some(key) => {
            let signed = Message::new()
                .message(1, command)
                .uint32(2, SIGNATURE_TYPE_ECDSA_P256_SHA256)
                .bytes(3, &key.sign(&init)?.to_le_bytes());
            Message::new().message(2, signed)
        }
    };
    Ok(packet.into_bytes())
}
