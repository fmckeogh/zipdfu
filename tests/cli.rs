//! End-to-end tests of the `zipdfu` binary.
//!
//! The main test re-creates every package listed in `tests/fixtures/cases.txt` and compares it
//! with the package nrfutil or adafruit-nrfutil created from the same command line
//! (`tests/fixtures/expected/`). See `tests/fixtures/README.md`.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::io::{Cursor, Read};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// An empty directory for a test's output.
fn out_dir(test: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(test);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Runs zipdfu in the fixture inputs directory.
fn zipdfu(args: &[&str], zipfile: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zipdfu"))
        .args(args.iter().map(OsStr::new).chain([zipfile.as_os_str()]))
        .current_dir(fixtures().join("inputs"))
        .output()
        .unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The files in a ZIP archive, in archive order. Reading them also checks their CRCs.
fn unzip(path: &Path) -> Vec<(String, Vec<u8>)> {
    let mut zip = zip::ZipArchive::new(Cursor::new(fs::read(path).unwrap())).unwrap();
    (0..zip.len())
        .map(|i| {
            let mut file = zip.by_index(i).unwrap();
            assert_eq!(file.compression(), zip::CompressionMethod::Stored);
            let mut data = Vec::new();
            file.read_to_end(&mut data).unwrap();
            (file.name().unwrap().into_owned(), data)
        })
        .collect()
}

fn verifying_key(pem_file: &str) -> VerifyingKey {
    let pem = fs::read_to_string(fixtures().join("inputs").join(pem_file)).unwrap();
    let start = pem
        .find("-----BEGIN EC PRIVATE KEY-----")
        .or_else(|| pem.find("-----BEGIN PRIVATE KEY-----"))
        .unwrap();
    let secret = p256::SecretKey::from_pem(pem[start..].trim_end()).unwrap();
    *p256::ecdsa::SigningKey::from(secret).verifying_key()
}

/// A field of a protocol buffers message: number, value and the value's byte range.
enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

fn fields(message: &[u8]) -> Vec<(u64, Value<'_>, Range<usize>)> {
    fn varint(bytes: &[u8], pos: &mut usize) -> u64 {
        let mut value = 0;
        for shift in (0..).step_by(7) {
            let byte = bytes[*pos];
            *pos += 1;
            value |= u64::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                break;
            }
        }
        value
    }
    let mut pos = 0;
    let mut out = Vec::new();
    while pos < message.len() {
        let key = varint(message, &mut pos);
        let start = pos;
        let value = match key & 7 {
            0 => Value::Varint(varint(message, &mut pos)),
            2 => {
                let len = varint(message, &mut pos) as usize;
                let range = pos..pos + len;
                pos += len;
                out.push((key >> 3, Value::Bytes(&message[range.clone()]), range));
                continue;
            }
            wire => panic!("unexpected wire type {wire}"),
        };
        out.push((key >> 3, value, start..pos));
    }
    out
}

fn bytes_field(message: &[u8], number: u64) -> (&[u8], Range<usize>) {
    fields(message)
        .into_iter()
        .find_map(|(n, value, range)| match value {
            Value::Bytes(bytes) if n == number => Some((bytes, range)),
            _ => None,
        })
        .unwrap_or_else(|| panic!("field {number} missing"))
}

fn varint_field(message: &[u8], number: u64) -> u64 {
    fields(message)
        .into_iter()
        .find_map(|(n, value, _)| match value {
            Value::Varint(v) if n == number => Some(v),
            _ => None,
        })
        .unwrap_or_else(|| panic!("field {number} missing"))
}

/// Checks a signature in nRF5 SDK byte order (`r` and `s` little-endian).
fn verify_le(key: &VerifyingKey, message: &[u8], signature: &[u8]) {
    let mut be = signature.to_vec();
    be[..32].reverse();
    be[32..].reverse();
    key.verify(message, &Signature::from_slice(&be).unwrap())
        .expect("valid signature");
}

/// Verifies all signatures in a Secure DFU init packet, then zeroes them for comparison.
fn mask_signatures(dat: &[u8], key: &VerifyingKey, bin: &[u8]) -> Vec<u8> {
    let mut masked = dat.to_vec();
    let (signed, signed_range) = bytes_field(dat, 2);
    let (command, command_range) = bytes_field(signed, 1);
    let (init, init_range) = bytes_field(command, 2);
    let (signature, signature_range) = bytes_field(signed, 3);
    verify_le(key, init, signature);
    masked[signed_range.start + signature_range.start..][..64].fill(0);

    let init_offset = signed_range.start + command_range.start + init_range.start;
    let sd_size = varint_field(init, 5) as usize;
    for (number, value, range) in fields(init) {
        if let (10, Value::Bytes(boot_validation)) = (number, value)
            && varint_field(boot_validation, 1) == 3
        {
            // An ECDSA boot validation signature, over the SoftDevice part of a merged image.
            let (signature, signature_range) = bytes_field(boot_validation, 2);
            verify_le(
                key,
                if sd_size > 0 { &bin[..sd_size] } else { bin },
                signature,
            );
            masked[init_offset + range.start + signature_range.start..][..64].fill(0);
        }
    }
    masked
}

fn show(data: &[u8]) -> String {
    match std::str::from_utf8(data) {
        Ok(text) => text.to_owned(),
        Err(_) => data.iter().map(|b| format!("{b:02x}")).collect(),
    }
}

#[test]
fn matches_reference_packages() {
    let out = out_dir("reference");
    let cases = fs::read_to_string(fixtures().join("cases.txt")).unwrap();
    let mut count = 0;
    for line in cases
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
    {
        let (name, command) = line.split_once(' ').unwrap();
        let args: Vec<&str> = command.split_whitespace().collect();
        let path = out.join(format!("{name}.zip"));
        let output = zipdfu(&args, &path);
        assert!(output.status.success(), "{name}: {}", stderr(&output));

        let actual = unzip(&path);
        assert_eq!(
            actual[0].0, "manifest.json",
            "{name}: manifest.json comes first"
        );
        let actual: BTreeMap<_, _> = actual.into_iter().collect();
        let expected: BTreeMap<_, _> = unzip(&fixtures().join(format!("expected/{name}.zip")))
            .into_iter()
            .collect();
        assert_eq!(
            actual.keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>(),
            "{name}"
        );

        let key = args
            .iter()
            .position(|&a| a == "--key-file")
            .map(|i| verifying_key(args[i + 1]));
        for (file, expected_data) in &expected {
            let (mut expected_data, mut actual_data) =
                (expected_data.clone(), actual[file].clone());
            if let (Some(key), Some(stem)) = (&key, file.strip_suffix(".dat")) {
                // nrfutil signs with random nonces, so compare everything but the signatures.
                assert_eq!(args[0], "pkg", "only Secure DFU packets are masked");
                let bin = format!("{stem}.bin");
                expected_data = mask_signatures(&expected_data, key, &expected[&bin]);
                actual_data = mask_signatures(&actual_data, key, &actual[&bin]);
            }
            assert!(
                actual_data == expected_data,
                "{name}: {file} differs\nexpected: {}\n  actual: {}",
                show(&expected_data),
                show(&actual_data),
            );
        }
        count += 1;
    }
    assert_eq!(count, 38);
}

#[test]
fn legacy_hash_and_signature_extensions() {
    // adafruit-nrfutil crashes on these under Python 3, so check the init packet layout directly.
    let out = out_dir("legacy_extensions");
    for (version, ext_packet_id) in [("0.7", 1u32), ("0.8", 2)] {
        let path = out.join(format!("{version}.zip"));
        let mut args = vec![
            "dfu",
            "genpkg",
            "--dev-type",
            "0x0052",
            "--dfu-ver",
            version,
            "--application",
            "app.hex",
        ];
        if version == "0.8" {
            args.extend(["--key-file", "test_key.pem"]);
        }
        let output = zipdfu(&args, &path);
        assert!(output.status.success(), "{}", stderr(&output));

        let files: BTreeMap<_, _> = unzip(&path).into_iter().collect();
        let (bin, dat) = (&files["app.bin"], &files["app.dat"]);
        // Device type, device revision, application version, and a single SoftDevice ID (0xFFFE).
        assert_eq!(
            dat[..12],
            [
                0x52, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 1, 0, 0xFE, 0xFF
            ]
        );
        assert_eq!(dat[12..16], ext_packet_id.to_le_bytes());
        assert_eq!(dat[16..20], (bin.len() as u32).to_le_bytes());
        let hash = Sha256::digest(bin);
        assert_eq!(dat[20..52], hash[..]);

        let manifest = String::from_utf8(files["manifest.json"].clone()).unwrap();
        let hash_hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        assert!(
            manifest.contains(&format!("\"dfu_version\": {version}\n")),
            "{manifest}"
        );
        assert!(
            manifest.contains(&format!("\"firmware_hash\": \"{hash_hex}\"")),
            "{manifest}"
        );
        assert!(
            manifest.contains(&format!("\"firmware_length\": {}", bin.len())),
            "{manifest}"
        );
        assert!(
            manifest.contains(&format!("\"ext_packet_id\": {ext_packet_id}")),
            "{manifest}"
        );

        if version == "0.8" {
            // A big-endian r || s signature of everything before it.
            assert_eq!(dat.len(), 116);
            let signature = Signature::from_slice(&dat[52..]).unwrap();
            verifying_key("test_key.pem")
                .verify(&dat[..52], &signature)
                .unwrap();
            let signature_hex: String = dat[52..].iter().map(|b| format!("{b:02x}")).collect();
            assert!(
                manifest.contains(&format!("\"init_packet_ecds\": \"{signature_hex}\"")),
                "{manifest}"
            );
        } else {
            assert_eq!(dat.len(), 52);
        }
    }
}

#[test]
fn usage_errors() {
    let out = out_dir("usage_errors");
    let pkg = ["pkg", "generate"];
    let app = ["--application", "app.hex", "--application-version", "1"];
    let base = [&pkg[..], &["--hw-version", "52", "--sd-req", "0xB6"]].concat();
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (
            base.clone(),
            "at least one of --application, --bootloader and --softdevice is required",
        ),
        (
            [
                &base[..],
                &app,
                &["--bootloader", "bl.hex", "--bootloader-version", "1"],
            ]
            .concat(),
            "use two packages",
        ),
        (
            [&pkg[..], &["--sd-req", "0xB6"], &app].concat(),
            "--hw-version is required",
        ),
        (
            [
                &pkg[..],
                &["--hw-version", "none", "--sd-req", "0xB6"],
                &app,
            ]
            .concat(),
            "--hw-version is required",
        ),
        (
            [&pkg[..], &["--hw-version", "52"], &app].concat(),
            "--sd-req is required",
        ),
        (
            [&pkg[..], &["--hw-version", "52", "--sd-req", "none"], &app].concat(),
            "--sd-req is required",
        ),
        (
            [&base[..], &["--application", "app.hex"]].concat(),
            "--application-version or --application-version-string",
        ),
        (
            [&base[..], &["--bootloader", "bl.hex"]].concat(),
            "--bootloader-version is required",
        ),
        (
            [
                &base[..],
                &[
                    "--bootloader",
                    "bl.hex",
                    "--bootloader-version",
                    "1",
                    "--application-version",
                    "1",
                ],
            ]
            .concat(),
            "without --application",
        ),
        (
            [
                &base[..],
                &["--softdevice", "sd.hex", "--bootloader-version", "1"],
            ]
            .concat(),
            "without --bootloader",
        ),
        (
            [&base[..], &app, &["--softdevice", "sd.hex"]].concat(),
            "--sd-id is required",
        ),
        (
            [
                &base[..],
                &app,
                &[
                    "--softdevice",
                    "sd.hex",
                    "--sd-id",
                    "0xCA",
                    "--external-app",
                ],
            ]
            .concat(),
            "only possible for packages containing just an application",
        ),
        (
            [
                &base[..],
                &[
                    "--bootloader",
                    "bl.hex",
                    "--bootloader-version",
                    "1",
                    "--external-app",
                ],
            ]
            .concat(),
            "--external-app requires --application",
        ),
        (
            [
                &base[..],
                &app,
                &["--app-boot-validation", "VALIDATE_ECDSA_P256_SHA256"],
            ]
            .concat(),
            "--key-file is required",
        ),
        (
            [&base[..], &app, &["--app-boot-validation", "CRC"]].concat(),
            "invalid value 'CRC'",
        ),
        (
            [&base[..], &app, &["--sd-req", "0xCA"]].concat(),
            "cannot be used multiple times",
        ),
        (
            [
                &base[..],
                &[
                    "--application",
                    "app.hex",
                    "--application-version-string",
                    "1.2",
                ],
            ]
            .concat(),
            "must be in the format X.Y.Z",
        ),
        (
            [
                &base[..],
                &[
                    "--application",
                    "app.hex",
                    "--application-version-string",
                    "1.0.100",
                ],
            ]
            .concat(),
            "at most 99",
        ),
        (
            [
                &base[..],
                &[
                    "--application",
                    "app.hex",
                    "--application-version",
                    "0x100000000",
                ],
            ]
            .concat(),
            "out of range",
        ),
        (
            [&pkg[..], &["--hw-version", "08", "--sd-req", "0xB6"], &app].concat(),
            "a leading 0 denotes an octal number",
        ),
        (
            [&pkg[..], &["--hw-version", "52", "--sd-req", "0xB6,"], &app].concat(),
            "'' is not a valid integer",
        ),
        (
            vec!["dfu", "genpkg"],
            "at least one of --application, --bootloader and --softdevice is required",
        ),
        (
            vec![
                "dfu",
                "genpkg",
                "--application",
                "app.hex",
                "--dfu-ver",
                "0.9",
            ],
            "supported versions are 0.5, 0.6, 0.7 and 0.8",
        ),
        (
            vec![
                "dfu",
                "genpkg",
                "--application",
                "app.hex",
                "--dfu-ver",
                "0.8",
            ],
            "--dfu-ver 0.8 requires --key-file",
        ),
        (
            vec![
                "dfu",
                "genpkg",
                "--application",
                "app.hex",
                "--dev-type",
                "0x10000",
            ],
            "out of range (the maximum is 0xFFFF)",
        ),
        (
            vec![
                "dfu",
                "genpkg",
                "--application",
                "app.hex",
                "--sd-req",
                "0x10000",
            ],
            "out of range (the maximum is 0xFFFF)",
        ),
    ];
    for (args, message) in cases {
        let path = out.join("unused.zip");
        let output = zipdfu(&args, &path);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains(message),
            "{args:?}: expected {message:?} in:\n{}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains("try '--help'"),
            "{}",
            stderr(&output)
        );
        assert!(!path.exists(), "{args:?}");
    }
}

#[test]
fn input_errors() {
    let out = out_dir("input_errors");
    let write = |name: &str, contents: &[u8]| {
        let path = out.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, contents).unwrap();
        path.to_str().unwrap().to_owned()
    };
    let bad_hex = write("bad.hex", b":0100000000FE\n");
    let empty_bin = write("empty.bin", b"");
    let other_app = write(
        "other/app.hex",
        &fs::read(fixtures().join("inputs/app.hex")).unwrap(),
    );
    let upper_app = write(
        "upper/APP.hex",
        &fs::read(fixtures().join("inputs/app.hex")).unwrap(),
    );
    let pkg = [
        "pkg",
        "generate",
        "--hw-version",
        "52",
        "--sd-req",
        "0xB6",
        "--application-version",
        "1",
    ];

    let cases: Vec<(Vec<&str>, String)> = vec![
        ([&pkg[..], &["--application", "missing.hex"]].concat(), "cannot read 'missing.hex'".into()),
        ([&pkg[..], &["--application", &bad_hex]].concat(), format!("'{bad_hex}' is not a valid Intel HEX file: line 1: checksum mismatch")),
        ([&pkg[..], &["--application", &empty_bin]].concat(), format!("cannot use '{empty_bin}': the file is empty")),
        (
            [&pkg[..], &["--application", "app.hex", "--key-file", "app.hex"]].concat(),
            "cannot use 'app.hex' as a signing key: no \"EC PRIVATE KEY\" or \"PRIVATE KEY\" PEM block found".into(),
        ),
        (
            [&pkg[..], &["--application", "app.hex", "--softdevice", &other_app, "--sd-id", "0xCA"]].concat(),
            "the SoftDevice and the application would both be stored as 'app.bin'".into(),
        ),
        (
            vec!["dfu", "genpkg", "--bootloader", &upper_app, "--application", "app.hex"],
            "the bootloader and the application would both be stored as 'app.bin'".into(),
        ),
    ];
    for (args, message) in cases {
        let path = out.join("unused.zip");
        let output = zipdfu(&args, &path);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(
            stderr(&output).contains(&format!("error: {message}")),
            "{args:?}: expected {message:?} in:\n{}",
            stderr(&output)
        );
        assert!(!path.exists(), "{args:?}");
    }
}

#[test]
fn warnings() {
    let out = out_dir("warnings");
    let app = ["--application", "app.hex", "--application-version", "1"];
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (
            [
                &["pkg", "generate", "--hw-version", "52", "--sd-req", "0xB6"],
                &app[..],
            ]
            .concat(),
            "warning: no --key-file given",
        ),
        (
            [&["pkg", "generate", "--debug-mode"], &app[..]].concat(),
            "warning: --debug-mode sets the debug flag",
        ),
        (
            [
                &[
                    "pkg",
                    "generate",
                    "--hw-version",
                    "52",
                    "--sd-req",
                    "0xB6",
                    "--application-version-string",
                    "1.2.3",
                ],
                &app[..],
            ]
            .concat(),
            "warning: both --application-version-string and --application-version given",
        ),
        (
            vec![
                "dfu",
                "genpkg",
                "--application",
                "app.hex",
                "--dev-type",
                "none",
            ],
            "warning: --dev-type none leaves the field out",
        ),
        (
            vec![
                "dfu",
                "genpkg",
                "--application",
                "app.hex",
                "--key-file",
                "test_key.pem",
            ],
            "note: --key-file given, so using --dfu-ver 0.8",
        ),
    ];
    for (args, message) in cases {
        let path = out.join("package.zip");
        let output = zipdfu(&args, &path);
        assert!(output.status.success(), "{args:?}: {}", stderr(&output));
        assert!(
            stderr(&output).contains(message),
            "{args:?}: expected {message:?} in:\n{}",
            stderr(&output)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            format!("Zip created at {}\n", path.display())
        );
    }

    // A real key produces no warning.
    let path = out.join("signed.zip");
    let output = zipdfu(
        &[
            &[
                "pkg",
                "generate",
                "--hw-version",
                "52",
                "--sd-req",
                "0xB6",
                "--key-file",
                "test_key.pem",
            ],
            &app[..],
        ]
        .concat(),
        &path,
    );
    assert!(
        output.status.success() && output.stderr.is_empty(),
        "{}",
        stderr(&output)
    );
}

#[test]
fn deterministic_output() {
    let out = out_dir("deterministic");
    let commands: [&[&str]; 2] = [
        &[
            "pkg",
            "generate",
            "--hw-version",
            "52",
            "--sd-req",
            "0xB6",
            "--sd-id",
            "0xCA",
            "--softdevice",
            "sd.hex",
            "--bootloader",
            "bl.hex",
            "--bootloader-version",
            "2",
            "--application",
            "app.hex",
            "--application-version",
            "1",
            "--sd-boot-validation",
            "VALIDATE_ECDSA_P256_SHA256",
            "--key-file",
            "test_key.pem",
        ],
        &[
            "dfu",
            "genpkg",
            "--application",
            "app.hex",
            "--key-file",
            "test_key.pem",
        ],
    ];
    for args in commands {
        let packages: Vec<Vec<u8>> = (0..2)
            .map(|i| {
                let path = out.join(format!("{i}.zip"));
                assert!(zipdfu(args, &path).status.success());
                fs::read(path).unwrap()
            })
            .collect();
        assert_eq!(packages[0], packages[1], "{args:?}");
    }
}

#[test]
fn archive_layout() {
    let path = out_dir("layout").join("package.zip");
    let args = [
        "pkg",
        "generate",
        "--hw-version",
        "52",
        "--sd-req",
        "0xB6",
        "--sd-id",
        "0xCA",
        "--application",
        "app.hex",
        "--application-version",
        "1",
        "--bootloader",
        "bl.hex",
        "--bootloader-version",
        "2",
        "--softdevice",
        "sd.hex",
    ];
    assert!(zipdfu(&args, &path).status.success());
    let names: Vec<String> = unzip(&path).into_iter().map(|(name, _)| name).collect();
    // The manifest first, then the images in the order DFU applies them.
    assert_eq!(
        names,
        [
            "manifest.json",
            "sd_bl.bin",
            "sd_bl.dat",
            "app.bin",
            "app.dat"
        ]
    );

    let zip = zip::ZipArchive::new(Cursor::new(fs::read(&path).unwrap())).unwrap();
    assert!(zip.comment().is_empty());
}

#[test]
fn help_and_version() {
    for args in [
        &["--help"][..],
        &["pkg", "generate", "--help"],
        &["dfu", "genpkg", "--help"],
        &["--version"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_zipdfu"))
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success(), "{args:?}");
        assert!(!output.stdout.is_empty());
    }
}
