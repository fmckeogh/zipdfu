# Test fixtures

`expected/` holds packages created by the reference tools from the commands in `cases.txt`, run
in `inputs/`:

- `pkg generate` cases: `nrfutil pkg generate` from pc-nrfutil 6.1.7 (the last Python release),
  on CPython 3.10.
- `dfu genpkg` cases: `adafruit-nrfutil dfu genpkg` from adafruit-nrfutil 0.5.3.post16, on
  CPython 3.11.

`tests/cli.rs` runs each command with zipdfu and compares the archive contents with these
packages. ECDSA signatures differ on every run of nrfutil, so for signed packages it verifies
each signature and compares everything else.

`inputs/` holds small synthetic images (random bytes) that exercise these conversions:

| file                     | contents                                                                                      |
|--------------------------|-----------------------------------------------------------------------------------------------|
| `app.hex`                | application with a gap and an odd length; CRLF line endings, some lowercase records, a start address record |
| `app.bin`                | raw binary of odd length                                                                      |
| `app_ünï.hex`            | non-ASCII file name                                                                           |
| `sd.hex`                 | SoftDevice: MBR data (dropped) and the info structure magic at 0x3004; extended segment addresses |
| `sd132.hex`              | early S132 layout: the magic at 0x4004 means the image starts at 0x3000                       |
| `bl.hex`                 | bootloader with UICR records (dropped)                                                        |
| `mbrgap.hex`             | data in the MBR region and after a gap, where the two tools disagree on the image start        |
| `test_key*.pem`          | throwaway P-256 keys made with OpenSSL: SEC1, PKCS#8, and SEC1 preceded by `EC PARAMETERS`     |

`cpython_set_order.txt` holds `list(set(xs))` for random lists of integers, as printed by
CPython 3.10, 3.11 and 3.14 (the output was the same). nrfutil de-duplicates SoftDevice IDs this
way, so zipdfu reproduces the order (`src/pyset.rs`).
