# Hantek DSO3254A NAND dump

This repository contains a 128 MiB NAND dump from a Hantek DSO3254A oscilloscope, together with notes from a local firmware analysis. The image contains U-Boot, an ARM Linux 3.2.35 kernel, and UBIFS filesystems.

Original image: `dso3254a_nand_dump.bin`

```text
Size:    134217728 bytes
SHA-256: 085d7e070042be62eeff0f0d2d4164d0b34a1ad90388401b4470eb165b91543d
```

The original dump has been preserved unchanged. The findings below come from static analysis unless stated otherwise.

## Warning: calibration data

This dump contains calibration files at the following paths in the instrument's filesystem:

- `/config/calbration.dat`

### Recalibrating a unit with missing calibration data

Calibration parameters can be rebuilt through self-calibration and adjusted manually using an accurate reference source.

1. Power on the instrument and let it warm up for at least 20 minutes.
2. Disconnect all probes and cables from the input connectors.
3. In the PC software, select **Utility → Calibration** and follow the prompts until it completes.

See [the official manual, section 1.9](https://www.hantek.com/Product/DSO3000%28A%29/DSO3000%28A%29_Manual_EN.pdf) for the self-calibration procedure.

## 1. USB maintenance script hooks

The acquisition executable, `/dso/app/core`, contains a function named `check_sys_running()` at ARM virtual address `0x000388D4`. A utility thread calls this function to check for maintenance files on a mounted USB drive.

| Marker file | Action found in the executable |
| --- | --- |
| `/mnt/udisk/run_text1.txt` | Calls `system("./mnt/udisk/runok.sh")`, removes the marker, and requests a reboot. |
| `/mnt/udisk/run_text.txt` | Deletes `/config/attr.dat`, removes the marker, and requests a reboot. This resets the saved settings. |

The script command really does start with `./mnt/`, rather than `/mnt/`. Successful execution therefore depends on the process working directory, as well as the USB mount and file permissions. This hook was confirmed in the call chain, but has not been tested on the instrument.

There is also a startup hook in `/dso/app/app`: if `/do_something` exists, the shell script makes it executable, runs it, and removes it. The inspected startup chain launches these processes as root without an intervening user change.

## 2. Firmware update passphrase

Both `/dso/etc/update_system.sh` and `/dso/etc/update_sdcard.sh` contain a hard-coded GPG passphrase:

```text
dso3000b
```

For example, the USB update script runs:

```sh
gpg --passphrase dso3000b --output /tmp/update/dso3kb.tar.gz -d /mnt/udisk/dso3kb*.up
```

The scripts then unpack the decrypted archive and a nested TAR archive, make `packet/update.sh` executable, and run it. The SD-card variant reads the update from `/mnt/sd/` instead.

No separate update package was available for a decryption test. Finding this passphrase alone does not establish whether other parts of the update process perform authentication.

## Corrupted data locations

Five UBIFS data nodes fail their stored CRC-32 checks. All dump offsets below are **absolute byte offsets in the original file**. File block numbers are zero-based, with 4096 uncompressed bytes per block.

| UBIFS node offset | File | File block | ELF section / significance |
| --- | --- | --- | --- |
| `0x01A21000` | `/bin/busybox` | 38 | `.text`: executable code; original LZO decompression fails. |
| `0x01B61000` | `/dso/bin/dbus-daemon` | 52 | `.text`: executable code; decompresses to 4096 bytes, but the code is corrupted. |
| `0x01B81000` | `/dso/bin/dbus-daemon` | 292 | `.strtab`: ordinary symbol names, not a runtime-loaded section; decompression produces 4094 bytes instead of 4096. |
| `0x01CE1000` | `/dso/sbin/gpg` | 199 | `.ARM.exidx`: runtime stack-unwind metadata; decompression produces 4095 bytes instead of 4096. |
| `0x052C1000` | `/dso/app/usb_check.txt` | 0 | An older node containing 1493 uncompressed bytes; a later CRC-valid node provides the recovered one-byte file. |

The acquisition executable and the recovered calibration files were not affected by these five failures. The dump alone does not establish whether the inconsistencies originated in the NAND device or during acquisition of the dump.

## Calculated repairs for the two code blocks

The repairs below change bytes in the **LZO-compressed payloads**, not directly in the uncompressed ARM instructions. Both programs declare ARMv4T code in their ELF attributes.

| Property | BusyBox | D-Bus daemon |
| --- | --- | --- |
| UBIFS node offset | `0x01A21000` | `0x01B61000` |
| Total node length, including header | 2840 bytes | 2655 bytes |
| Compressed payload starts at | `0x01A21030` | `0x01B61030` |
| Uncompressed file offset | `0x00026000` | `0x00034000` |
| ARM virtual address | `0x0002E000` | `0x0003C000` |
| Uncompressed block length | 4096 bytes | 4096 bytes |
| Stored original CRC | `0x82231A1D` | `0xB24DECF0` |
| Calculated CRC before repair | `0x7A234028` | `0x9E19E71D` |
| Calculated CRC after repair | `0x82231A1D` | `0xB24DECF0` |
| Modified bytes / restored bits | 14 bytes / 15 bits | 7 bytes / 7 bits |

Every selected correction changes a zero bit back to one. The stored CRC fields, UBIFS headers, and compressed lengths remain unchanged.

### Repair method and confidence

For D-Bus, the image also contains an intact shared library with matching functions. Comparing its ARM instructions with the daemon exposed incorrect register operands, condition flags, immediate offsets, and an LZO back-reference. Branch relocations and literal-pool addresses were treated separately because the executables have different layouts. Seven bit corrections restore the original node CRC.

For BusyBox, LZO tracing mapped damaged output instructions back to compressed literals and back-references. Candidate corrections were checked against ARM instruction alignment, control flow, register use, function prologues/epilogues, and structure-field offsets. For example, the selected repair restores a `CMPNE` / `MOVEQ` / `MOVNE` sequence, balanced function returns, and `MOV lr, pc; BX ip` indirect calls. The remaining CRC-constrained candidates were checked for consistent pointer and field offsets.

A candidate that matched the CRC and decompressed successfully was rejected because it broke stack balance. **A matching CRC alone is not sufficient to identify the original bytes.** The selected repairs have strong supporting evidence, but no independent pristine firmware image was available to prove exact equivalence.

### Exact byte replacements and reproduction

The following standalone Python script contains all calculated replacement values as `(absolute dump offset, original byte, repaired byte)` tuples. Original and repaired bytes use eight-bit `0b` binary notation to show the restored bits. It checks the original image hash, applies the replacements to a copy, and validates both original stored CRCs without rewriting them.

Run it from the directory containing the dump. It creates `dso3254a_nand_dump.code_repaired.bin` and leaves the original file unchanged.

```python
from pathlib import Path
import hashlib
import struct
import zlib

source = Path("dso3254a_nand_dump.bin")
output = Path("dso3254a_nand_dump.code_repaired.bin")
image = bytearray(source.read_bytes())
assert len(image) == 134217728
assert hashlib.sha256(image).hexdigest() == (
    "085d7e070042be62eeff0f0d2d4164d0b34a1ad90388401b4470eb165b91543d"
)

patches = [
    # BusyBox: 14 bytes, 15 restored bits.
    (0x01A21214, 0b00001000, 0b00001100),
    (0x01A21255, 0b01001001, 0b01001101),
    (0x01A21264, 0b00010010, 0b00010011),
    (0x01A212A5, 0b00000101, 0b10000101),
    (0x01A21315, 0b01101110, 0b01101111),
    (0x01A21355, 0b01011100, 0b01011110),
    (0x01A2138A, 0b00101000, 0b00101100),
    (0x01A213E5, 0b00011100, 0b11011100),
    (0x01A2160B, 0b00000000, 0b00001000),
    (0x01A216A5, 0b01011001, 0b01111001),
    (0x01A21714, 0b11010011, 0b11011011),
    (0x01A2174B, 0b00100010, 0b00100011),
    (0x01A2178A, 0b00010111, 0b00011111),
    (0x01A217CB, 0b00011101, 0b10011101),
    # D-Bus daemon: 7 bytes, 7 restored bits.
    (0x01B610E0, 0b10010100, 0b10010110),
    (0x01B611E0, 0b01000010, 0b01010010),
    (0x01B61238, 0b00110001, 0b00110101),
    (0x01B612B9, 0b01100001, 0b11100001),
    (0x01B61338, 0b01100111, 0b01101111),
    (0x01B61421, 0b10010100, 0b10110100),
    (0x01B614E0, 0b10011110, 0b10011111),
]

for offset, before, after in patches:
    assert image[offset] == before, hex(offset)
    image[offset] = after

for offset, expected_crc in [
    (0x01A21000, 0x82231A1D),
    (0x01B61000, 0xB24DECF0),
]:
    stored_crc = struct.unpack_from("<I", image, offset + 4)[0]
    node_length = struct.unpack_from("<I", image, offset + 16)[0]
    calculated_crc = (
        zlib.crc32(image[offset + 8 : offset + node_length]) ^ 0xFFFFFFFF
    )
    assert stored_crc == calculated_crc == expected_crc

with output.open("xb") as destination:
    destination.write(image)
print(output, hashlib.sha256(image).hexdigest())
```

The resulting image differs from the original at **21 byte offsets, restoring 22 bits**. Its SHA-256 is:

```text
2c30e432384f50b2993500de56219de8861038f48ec19dc4874e94196ccb283a
```
