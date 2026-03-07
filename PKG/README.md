# pkg_vfs_extract.py

`pkg_vfs_extract.py` extracts and inspects the embedded Virtual Filesystem (VFS) from Node.js executables built with `vercel/pkg`.

It parses the bundled prelude and recovers:
- `VIRTUAL_FILESYSTEM` entries
- `DICT` path dictionary
- `DEFAULT_ENTRYPOINT`
- `SYMLINKS`
- `DOCOMPRESS` (`0=none`, `1=gzip`, `2=brotli`)

The tool supports both metadata inspection and payload extraction.

## Requirements

- Python 3.10+
- Optional: `brotli` Python package (needed to decompress brotli content during extraction)

Install optional dependency:

```bash
pip install -r requirements.txt
```

## Usage

```bash
python pkg_vfs_extract.py <binary> [options]
```

### Arguments

- `<binary>`: path to a pkg-compiled Node.js executable.

### Options

- `--json`: print decoded VFS metadata as JSON.
- `--tree`: print a directory tree view.
- `--tree-depth N`: max depth for tree view (`-1` = unlimited).
- `--extract-to DIR`: extract file content payload to `DIR`.
- `--filter PATTERN`: glob filter for entries (example: `*/axios/*`).
- `--stats`: print summary statistics only.
- `--packages`: print only detected npm package names.
- `--interesting`: print analyst-oriented file shortlist.

## Examples

Print default table view:

```bash
python pkg_vfs_extract.py sample.exe
```

Show stats only:

```bash
python pkg_vfs_extract.py sample.exe --stats
```

Dump decoded JSON:

```bash
python pkg_vfs_extract.py sample.exe --json > vfs.json
```

List packages only:

```bash
python pkg_vfs_extract.py sample.exe --packages
```

Show tree view with depth limit:

```bash
python pkg_vfs_extract.py sample.exe --tree --tree-depth 3
```

Extract files to disk:

```bash
python pkg_vfs_extract.py sample.exe --extract-to ./out_vfs
```

Extract only matching files:

```bash
python pkg_vfs_extract.py sample.exe --extract-to ./out_vfs --filter "*/node_modules/axios/*"
```

Show interesting files:

```bash
python pkg_vfs_extract.py sample.exe --interesting
```

## Output Modes

### Default mode (table)

Prints one line per VFS entry:
- decoded path
- inferred type (`DIR`, `FILE`, `BYTECODE`, `JS+BYTECODE`, `META`)
- stores present (`BLOB`, `CONTENT`, `LINKS`, `STAT`)
- total size

### JSON mode (`--json`)

Returns a single JSON object with:
- file metadata (`file`, `file_size`, `prelude_offset`)
- runtime metadata (`entrypoint`, `compression`, `symlinks`)
- dictionary stats (`dictionary_size`)
- decoded VFS map (`vfs`)
- raw dictionary map (`dictionary`)

### Stats mode (`--stats`)

Prints:
- offsets and compression type
- counts by entry type
- aggregate payload sizes
- number of npm packages

## How Extraction Works

When extracting payload content (`--extract-to`), the tool resolves payload start using:
1. `PAYLOAD_POSITION` from bootstrap code (if patched into the binary)
2. PE overlay fallback (section-header based), when available

If neither method works, the tool cannot recover raw file content and will fail extraction while still allowing metadata views (`--stats`, `--tree`, `--json`, etc.).

## Notes and Limits

- Designed for `pkg` prelude formats used by v4/v5-style binaries.
- Requires recognizable prelude signature; otherwise parsing fails early.
- Brotli payload decompression needs the optional `brotli` Python package.
- Path decoding relies on the embedded `DICT`; malformed or custom prelude variants may not parse.

## Exit Behavior

- Exit code `0`: successful execution.
- Exit code `1`: parse failures, missing input file, unsupported format, or extraction preconditions not met.
