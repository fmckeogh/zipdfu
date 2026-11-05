//! The package: `manifest.json`, plus a binary image (`.bin`) and an init packet (`.dat`) for each
//! firmware.

use crate::firmware::{self, Firmware};
use crate::{Args, DfuVersion};
use color_eyre::eyre::{Result, WrapErr};
use crc::{CRC_16_IBM_3740, Crc};
use serde_json::{Value, json};
use std::fs;
use std::io::{Cursor, Write};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

/// CRC-16/CCITT-FALSE, which the bootloader uses to check the image (`crc16_compute()` in the SDK).
const CRC16: Crc<u16> = Crc::<u16>::new(&CRC_16_IBM_3740);

pub fn create(args: &Args) -> Result<()> {
    // The images in update order, with their manifest key and, if merged, the SoftDevice and
    // bootloader sizes.
    let mut images = Vec::new();
    match (&args.softdevice, &args.bootloader) {
        (Some(sd), Some(bl)) => {
            let (sd, bl) = (firmware::load(sd)?, firmware::load(bl)?);
            let sizes = (sd.data.len(), bl.data.len());
            let merged = Firmware {
                name: "sd_bl".into(),
                data: [sd.data, bl.data].concat(),
            };
            images.push(("softdevice_bootloader", merged, Some(sizes)));
        }
        (Some(sd), None) => images.push(("softdevice", firmware::load(sd)?, None)),
        (None, Some(bl)) => images.push(("bootloader", firmware::load(bl)?, None)),
        (None, None) => {}
    }
    if let Some(app) = &args.application {
        images.push(("application", firmware::load(app)?, None));
    }

    let dfu_version = match args.dfu_ver {
        DfuVersion::V0_5 => 0.5,
        DfuVersion::V0_6 => 0.6,
    };
    let mut manifest = json!({ "dfu_version": dfu_version });
    let mut files = Vec::new();
    for (key, firmware, sizes) in images {
        let (dat, init_packet_data) = init_packet(args, &firmware.data)?;
        let bin_file = format!("{}.bin", firmware.name);
        let dat_file = format!("{}.dat", firmware.name);
        manifest[key] = json!({
            "bin_file": bin_file,
            "dat_file": dat_file,
            "init_packet_data": init_packet_data,
        });
        if let Some((sd_size, bl_size)) = sizes {
            manifest[key]["sd_size"] = sd_size.into();
            manifest[key]["bl_size"] = bl_size.into();
        }
        files.push((bin_file, firmware.data));
        files.push((dat_file, dat));
    }
    let manifest = serde_json::to_vec_pretty(&json!({ "manifest": manifest }))?;

    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (name, data) in [("manifest.json".to_owned(), manifest)]
        .into_iter()
        .chain(files)
    {
        zip.start_file(&name, options)
            .wrap_err_with(|| format!("cannot add '{name}' to the package"))?;
        zip.write_all(&data)?;
    }
    let archive = zip.finish()?.into_inner();
    fs::write(&args.zipfile, archive)
        .wrap_err_with(|| format!("cannot write '{}'", args.zipfile.display()))
}

/// Encodes an image's init packet (`dfu_init_packet_t` in the SDK, little-endian) and describes it
/// for the manifest.
fn init_packet(args: &Args, image: &[u8]) -> Result<(Vec<u8>, Value)> {
    let mut packet = Vec::new();
    let mut fields = json!({});
    if let Some(dev_type) = args.dev_type.0 {
        packet.extend(dev_type.to_le_bytes());
        fields["device_type"] = dev_type.into();
    }
    if let Some(dev_revision) = args.dev_revision.0 {
        packet.extend(dev_revision.to_le_bytes());
        fields["device_revision"] = dev_revision.into();
    }
    if let Some(app_version) = args.application_version.0 {
        packet.extend(app_version.to_le_bytes());
        fields["application_version"] = app_version.into();
    }
    let sd_req = args.sd_req.0.as_deref().unwrap_or_default();
    packet.extend(
        u16::try_from(sd_req.len())
            .wrap_err("too many SoftDevice IDs")?
            .to_le_bytes(),
    );
    for id in sd_req {
        packet.extend(id.to_le_bytes());
    }
    fields["softdevice_req"] = json!(sd_req);
    if args.dfu_ver == DfuVersion::V0_6 {
        // The extended packet ID 0 means that a CRC-16 follows.
        packet.extend(0u32.to_le_bytes());
        fields["ext_packet_id"] = 0.into();
    }
    let crc = CRC16.checksum(image);
    packet.extend(crc.to_le_bytes());
    fields["firmware_crc16"] = crc.into();
    Ok((packet, fields))
}
