//! Tests of the zipdfu binary against packages created by adafruit-nrfutil (see
//! `tests/fixtures/README.md`).

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Runs zipdfu in the fixture inputs directory.
fn zipdfu(args: &[&str], zipfile: &Path) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_zipdfu"));
    command
        .args(args)
        .arg(zipfile)
        .current_dir(fixtures().join("inputs"));
    command.output().unwrap()
}

/// The files in a ZIP archive. `manifest.json` is normalized, as only its formatting differs.
fn unzip(path: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut zip = zip::ZipArchive::new(fs::File::open(path).unwrap()).unwrap();
    (0..zip.len())
        .map(|i| {
            let mut file = zip.by_index(i).unwrap();
            let mut data = Vec::new();
            file.read_to_end(&mut data).unwrap();
            let name = file.name().unwrap().into_owned();
            if name == "manifest.json" {
                let manifest: serde_json::Value = serde_json::from_slice(&data).unwrap();
                data = manifest.to_string().into_bytes();
            }
            (name, data)
        })
        .collect()
}

#[test]
fn matches_adafruit_nrfutil() {
    let cases = fs::read_to_string(fixtures().join("cases.txt")).unwrap();
    let cases: Vec<_> = cases
        .lines()
        .filter(|line| !line.starts_with('#'))
        .collect();
    assert_eq!(cases.len(), 15);
    for case in cases {
        let (name, options) = case.split_once(' ').unwrap();
        let zipfile = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}.zip"));
        let output = zipdfu(&options.split_whitespace().collect::<Vec<_>>(), &zipfile);
        assert!(
            output.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected = unzip(&fixtures().join(format!("expected/{name}.zip")));
        assert_eq!(unzip(&zipfile), expected, "{name}");
    }
}

#[test]
fn reports_errors() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("errors");
    fs::create_dir_all(dir.join("other")).unwrap();
    let bad_hex = dir.join("bad.hex");
    fs::write(&bad_hex, ":00000001FE\n").unwrap();
    let other_app = dir.join("other/app.hex");
    fs::copy(fixtures().join("inputs/app.hex"), &other_app).unwrap();
    let (bad_hex, other_app) = (bad_hex.to_str().unwrap(), other_app.to_str().unwrap());

    let cases: [(&[&str], i32, &str); 7] = [
        (&[], 2, "the following required arguments were not provided"),
        (
            &["--application", "app.hex", "--dfu-ver", "0.8"],
            2,
            "invalid value '0.8' for '--dfu-ver <VERSION>'",
        ),
        (
            &["--application", "app.hex", "--dev-type", "0x10000"],
            2,
            "'0x10000' is out of range",
        ),
        (
            &["--application", "app.hex", "--sd-req", "0xB6,x"],
            2,
            "'x' is not a valid integer",
        ),
        (
            &["--application", "missing.hex"],
            1,
            "cannot read 'missing.hex'",
        ),
        (&["--application", bad_hex], 1, "invalid record 1"),
        (
            &["--bootloader", other_app, "--application", "app.hex"],
            1,
            "cannot add 'app.bin' to the package",
        ),
    ];
    for (args, code, message) in cases {
        let zipfile = dir.join("package.zip");
        let output = zipdfu(args, &zipfile);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(code), "{args:?}: {stderr}");
        assert!(
            stderr.contains(message),
            "{args:?}: expected {message:?} in {stderr}"
        );
        assert!(!zipfile.exists(), "{args:?}");
    }
}
