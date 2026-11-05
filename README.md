# zipdfu

Creates DFU `.zip` packages for nRF5 SDK 11 based bootloaders, such as the Adafruit nRF52
bootloader. It replaces `adafruit-nrfutil dfu genpkg` and takes the same options:

```sh
zipdfu --dev-type 0x0052 --sd-req 0xFFFE --application app.hex app_dfu.zip
```

The `.bin` and `.dat` files in the package are identical to those adafruit-nrfutil creates.
`manifest.json` has the same contents, formatted differently. `cargo test` checks this against 15
packages created with adafruit-nrfutil 0.5.3.post16 (see [tests/fixtures](tests/fixtures/README.md)).

Differences from adafruit-nrfutil:

- `--dfu-ver` accepts 0.5 and 0.6. With 0.7, 0.8 or `--key-file`, adafruit-nrfutil crashes, so
  zipdfu has no such options.
- If two images would be stored under the same name in the package (e.g. `a/fw.hex` and `b/fw.hex`),
  or no image is given, zipdfu fails instead of creating a broken or empty package.
- Package files are named after the input with its extension replaced, so `fw.hex` becomes `fw.bin`
  and `fw.dat`. adafruit-nrfutil replaces every `.hex` in the name, and produces a broken package
  unless the name ends in exactly `.hex` or `.bin`.

## Building

`cargo build --release`, or `nix build` with the flake.
