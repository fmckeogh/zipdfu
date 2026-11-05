# Test fixtures

`expected/` holds packages that adafruit-nrfutil 0.5.3.post16 (on CPython 3.11) created from the
options in `cases.txt`, run in `inputs/`. `tests/cli.rs` runs zipdfu with the same options and
compares the archive contents with them.

`inputs/` holds small synthetic images (random bytes) that exercise these conversions:

| file          | contents                                                                                     |
|---------------|----------------------------------------------------------------------------------------------|
| `app.hex`     | application with a gap and an odd length; CRLF line endings, some lowercase records, a start address record |
| `app.bin`     | raw binary of odd length                                                                     |
| `app_ünï.hex` | non-ASCII file name                                                                          |
| `sd.hex`      | SoftDevice: MBR data (dropped) and the info structure magic at 0x3004; extended segment addresses |
| `sd132.hex`   | early S132 layout: the magic at 0x4004 means the image starts at 0x3000                      |
| `bl.hex`      | bootloader with UICR records (dropped)                                                       |
| `mbrgap.hex`  | data in the MBR region and after a gap, so the image starts at the end of the MBR            |
