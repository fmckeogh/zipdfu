//! The layout shared by both package formats: `manifest.json`, plus a binary image (`.bin`) and
//! an init packet (`.dat`) for each firmware in the package.

use std::collections::BTreeMap;
use std::fmt;

use anyhow::{Result, bail};

use crate::json::Value;
use crate::zip;

/// What a firmware image in a package is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// A SoftDevice and bootloader, merged into one image.
    SoftDeviceBootloader,
    SoftDevice,
    Bootloader,
    Application,
}

impl Role {
    fn manifest_key(self) -> &'static str {
        match self {
            Role::SoftDeviceBootloader => "softdevice_bootloader",
            Role::SoftDevice => "softdevice",
            Role::Bootloader => "bootloader",
            Role::Application => "application",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Role::SoftDeviceBootloader => "SoftDevice and bootloader",
            Role::SoftDevice => "SoftDevice",
            Role::Bootloader => "bootloader",
            Role::Application => "application",
        })
    }
}

/// Name of the merged SoftDevice and bootloader image, as chosen by nrfutil.
pub const SD_BL_STEM: &str = "sd_bl";

#[derive(Debug)]
pub struct Image {
    pub role: Role,
    /// The files are stored as `<stem>.bin` and `<stem>.dat`.
    pub stem: String,
    pub bin: Vec<u8>,
    pub dat: Vec<u8>,
    /// Format-specific fields of the image's manifest entry, besides `bin_file` and `dat_file`.
    pub manifest_fields: BTreeMap<&'static str, Value>,
}

impl Image {
    fn bin_name(&self) -> String {
        format!("{}.bin", self.stem)
    }

    fn dat_name(&self) -> String {
        format!("{}.dat", self.stem)
    }
}

/// Builds the archive: `manifest.json` first, then each image's `.bin` and `.dat`.
///
/// The manifest has an entry per image, plus the given top-level fields.
pub fn archive(
    images: &[Image],
    manifest_fields: BTreeMap<&'static str, Value>,
) -> Result<Vec<u8>> {
    // Names must not collide, even on case-insensitive file systems where packages get unpacked.
    // (nrfutil silently packages the wrong image or leaves files out in that case.)
    for (i, image) in images.iter().enumerate() {
        if let Some(other) = images[..i]
            .iter()
            .find(|o| o.stem.to_lowercase() == image.stem.to_lowercase())
        {
            bail!(
                "the {} and the {} would both be stored as '{}' in the package; rename one of the input files",
                other.role,
                image.role,
                image.bin_name(),
            );
        }
    }

    let manifest = manifest(images, manifest_fields).to_json();
    let names: Vec<[String; 2]> = images
        .iter()
        .map(|i| [i.bin_name(), i.dat_name()])
        .collect();
    let mut entries: Vec<(&str, &[u8])> = vec![("manifest.json", manifest.as_bytes())];
    for (image, [bin, dat]) in images.iter().zip(&names) {
        entries.push((bin, &image.bin));
        entries.push((dat, &image.dat));
    }
    zip::build(&entries)
}

fn manifest(images: &[Image], mut fields: BTreeMap<&'static str, Value>) -> Value {
    for image in images {
        let mut entry = image.manifest_fields.clone();
        entry.insert("bin_file", image.bin_name().into());
        entry.insert("dat_file", image.dat_name().into());
        fields.insert(image.role.manifest_key(), Value::Object(entry));
    }
    Value::object([("manifest", Value::Object(fields))])
}
