# zipdfu

Creates DFU `.zip` packages for Nordic nRF5 bootloaders. It replaces the package creation of
two Python tools that are hard to install nowadays:

| zipdfu                | replaces                                                                     | for                                                        |
|-----------------------|------------------------------------------------------------------------------|------------------------------------------------------------|
| `zipdfu pkg generate` | `nrfutil pkg generate` (pc-nrfutil 6.1.7)                                    | Secure DFU bootloaders, nRF5 SDK 12 and later              |
| `zipdfu dfu genpkg`   | `adafruit-nrfutil dfu genpkg` (0.5.3.post16; same as pc-nrfutil 0.5)         | legacy DFU: nRF5 SDK 11 and earlier, Adafruit nRF52 bootloader |

The options are the same, so existing commands only need the program name changed:

```sh
zipdfu pkg generate --hw-version 52 --sd-req 0x0100 \
    --application app.hex --application-version 1 --key-file private.pem app_dfu.zip

zipdfu dfu genpkg --dev-type 0x0052 --sd-req 0xFFFE --application app.hex app_dfu.zip
```

Only package creation is implemented: not DFU itself, `nrfutil keys`, settings pages, or Zigbee
packages (`--zigbee*` options). To create a signing key, run
`openssl ecparam -name prime256v1 -genkey -noout -out private.pem`, which gives the same format as
`nrfutil keys generate`.

## Compatibility

zipdfu writes the same `manifest.json`, `.bin` and `.dat` files as the original tools, byte for
byte. The exceptions are ECDSA signatures, which nrfutil computes with random nonces, and ZIP
metadata such as timestamps. `cargo test` checks this against 38 packages that were created with
nrfutil and adafruit-nrfutil (see [tests/fixtures](tests/fixtures/README.md)), and it verifies
every signature.

zipdfu differs from the original tools on purpose in the following ways:

- **Reproducible output.** All ZIP entries have the same timestamp (1980-01-01) and permissions, and
  signatures use deterministic nonces (RFC 6979), so the same inputs give the same package.
- **Errors instead of broken packages.** nrfutil silently packages the wrong image, or leaves files
  out, when two inputs have the same file name (e.g. `a/fw.hex` and `b/fw.hex`). It also writes an
  empty package when no image is given, and lets `--application-version-string 1.0.100` turn into
  1.1.0. zipdfu rejects all three, and also any `--dfu-ver` other than 0.5, 0.6, 0.7 or 0.8.
- **Fixes for adafruit-nrfutil crashes.** Under Python 3, adafruit-nrfutil crashes with
  `--dfu-ver 0.7`, `--dfu-ver 0.8` and `--key-file`. zipdfu implements them as in its source code.
- **Package file names** are the input's name with the extension replaced: `fw.hex` becomes `fw.bin`
  and `fw.dat`, as before. For other names, nrfutil replaces every `.hex` in the name, and produces a
  broken package unless the name ends in exactly `.hex` or `.bin`. zipdfu accepts any name, and
  treats files ending in `.bin` (in any case) as raw binaries.
- **Input parsing is a bit more lenient.** zipdfu accepts spaces in lists (`0xB6, 0xCA`), `none` in any
  case, and whitespace around Intel HEX records.
- **Messages.** Warnings go to stderr as one line each, not as ASCII-art banners. Errors in the options
  exit with status 2, other errors with 1. `manifest.json` is the first file in the archive.

## Building

`cargo build --release`, or `nix build` with the flake.
