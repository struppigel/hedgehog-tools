# Ren’Py Archive Extractor

This script extracts files from **RenPy archive formats** (`.rpa`, `.rpi`).

RenPy is a visual novel engine that bundles game assets (scripts, images, audio, etc.) into RPA archives. These archives may contain compiled script files (`.rpyc`) which are relevant for malware analysis.

## Supported formats

- RPA v1 (`.rpi`)
- RPA v2 (`RPA-2.0`)
- RPA v3 (`RPA-3.0`, XOR-obfuscated index)

## Usage

```
python extract_rpa.py <archive.rpa> <output_dir>
```

Decompile the resulting `.rpyc` files with [unrpyc](https://github.com/CensoredUsername/unrpyc)

## Test sample

SHA-256 3c086e76942fb9fd3d1e4384e9c1228c227c00c78dc29fca512ed95ee919ee5e

This file is malicious. It contains the RenPy archive in `data/archive.rpa`