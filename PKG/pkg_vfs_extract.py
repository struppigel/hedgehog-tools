#!/usr/bin/env python3
"""
pkg_vfs_extract.py — Extract and display the Virtual Filesystem (VFS)
from Node.js executables compiled with vercel/pkg.

Parses the embedded prelude IIFE to recover:
  - VIRTUAL_FILESYSTEM  (file/dir entries with payload offsets)
  - DICT                (short-code ↔ real-name dictionary)
  - DEFAULT_ENTRYPOINT  (application entry point)
  - SYMLINKS            (symlink map)
  - DOCOMPRESS          (compression mode: 0=none, 1=gzip, 2=brotli)

Works generically on any pkg-compiled binary (pkg v4/v5).

Usage:
    python3 pkg_vfs_extract.py <binary> [options]

Options:
    --json              Output raw JSON instead of formatted table
    --tree              Display as directory tree
    --extract-to DIR    Extract file contents to DIR (requires payload)
    --filter PATTERN    Only show entries matching glob pattern
    --stats             Show summary statistics only
    --interesting       Show files likely to be analyst-relevant
"""

import argparse
import fnmatch
import json
import os
import re
import struct
import sys
import zlib
from collections import defaultdict

# ── pkg VFS constants ────────────────────────────────────────────────
STORE_BLOB = "0"     # V8 bytecode / JIT-compiled native code
STORE_CONTENT = "1"  # File content (source / data)
STORE_LINKS = "2"    # Directory listing (child entries)
STORE_STAT = "3"     # File metadata (stat info)

STORE_NAMES = {
    STORE_BLOB: "BLOB (V8 bytecode)",
    STORE_CONTENT: "CONTENT (file data)",
    STORE_LINKS: "LINKS (directory)",
    STORE_STAT: "STAT (metadata)",
}

COMPRESS_NAMES = {0: "none", 1: "gzip", 2: "brotli"}

# ── Prelude detection signatures ─────────────────────────────────────
# The inner IIFE function signature in the prelude
PRELUDE_SIG = (
    b"(function(process, require, console, EXECPATH_FD, "
    b"PAYLOAD_POSITION, PAYLOAD_SIZE)"
)
PRELUDE_SIG_ALT = (
    b"(function (process, require, console, EXECPATH_FD, "
    b"PAYLOAD_POSITION, PAYLOAD_SIZE)"
)

# The bootstrap that loads the prelude from the binary
BOOTSTRAP_SIG = b"var __require__ = require;"


def find_prelude(data: bytes) -> int | None:
    """Find the offset of the pkg prelude IIFE in the binary."""
    for sig in [PRELUDE_SIG, PRELUDE_SIG_ALT]:
        idx = data.find(sig)
        if idx >= 0:
            return idx
    return None


def find_bootstrap(data: bytes) -> int | None:
    """Find the bootstrap readPrelude function."""
    idx = data.find(BOOTSTRAP_SIG)
    return idx if idx >= 0 else None


def extract_payload_position(data: bytes, bootstrap_offset: int) -> int | None:
    """Try to extract PAYLOAD_POSITION from the patched bootstrap."""
    region = data[bootstrap_offset:bootstrap_offset + 1024].decode(
        "utf-8", errors="replace"
    )
    m = re.search(r"PAYLOAD_POSITION\s*=\s*(\d+)", region)
    if m:
        val = int(m.group(1))
        if val > 0:
            return val
    return None


def pe_overlay_offset(data: bytes) -> int | None:
    """Compute PE overlay start from section headers (fallback for unpatched PAYLOAD_POSITION)."""
    if data[:2] != b"MZ":
        return None
    try:
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_off:pe_off + 4] != b"PE\x00\x00":
            return None
        num_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
        opt_size = struct.unpack_from("<H", data, pe_off + 4 + 16)[0]
        sec_start = pe_off + 4 + 20 + opt_size
        max_end = 0
        for i in range(num_sections):
            off = sec_start + i * 40
            rawsize = struct.unpack_from("<I", data, off + 16)[0]
            rawaddr = struct.unpack_from("<I", data, off + 20)[0]
            end = rawaddr + rawsize
            if end > max_end:
                max_end = end
        return max_end if max_end > 0 else None
    except (struct.error, IndexError):
        return None


def extract_vfs_components(data: bytes, prelude_offset: int):
    """
    Extract VFS, DICT, entrypoint, symlinks, and compression flag
    from the prelude IIFE arguments.

    Returns dict with keys: vfs, dict, entrypoint, symlinks, compress,
                            prelude_offset, vfs_offset, dict_offset
    """
    # Read from prelude to end of file
    text = data[prelude_offset:].decode("utf-8", errors="replace")

    # ── Step 1: Parse backwards from end to identify arg boundaries ──
    # The file/prelude ends with: ...DICT}\n,\nDOCOMPRESS\n);\n})
    # Find the compression flag at the very end
    end_match = re.search(r"\}\n,\n(\d+)\n\);\n\}\)$", text)
    if not end_match:
        # Try alternate endings
        end_match = re.search(r"\}\n,\n(\d+)\n\);?\n?\}?\)?$", text.rstrip())
    if not end_match:
        raise ValueError(
            "Cannot find DOCOMPRESS flag at end of prelude. "
            "File may not be a pkg binary or format is unsupported."
        )

    docompress = int(end_match.group(1))
    compress_end = end_match.start()  # position of } before \n,\nN

    # ── Step 2: Extract DICT ──
    # DICT is a JSON object ending at compress_end (the } char)
    dict_end = compress_end  # inclusive }
    brace_count = 0
    dict_start = None
    for i in range(dict_end, -1, -1):
        if text[i] == "}":
            brace_count += 1
        elif text[i] == "{":
            brace_count -= 1
            if brace_count == 0:
                dict_start = i
                break

    if dict_start is None:
        raise ValueError("Cannot find DICT JSON boundaries")

    dict_json = text[dict_start : dict_end + 1]
    dictionary = json.loads(dict_json)

    # ── Step 3: Extract SYMLINKS ──
    # Before DICT: ...\n,\nSYMLINKS\n,\nDICT
    # Walk backwards from dict_start to find SYMLINKS
    pre_dict = text[:dict_start].rstrip()
    if pre_dict.endswith(","):
        pre_dict = pre_dict[:-1].rstrip()

    # SYMLINKS is a JSON object (often {})
    sym_end = len(pre_dict) - 1
    brace_count = 0
    sym_start = None
    for i in range(sym_end, -1, -1):
        if pre_dict[i] == "}":
            brace_count += 1
        elif pre_dict[i] == "{":
            brace_count -= 1
            if brace_count == 0:
                sym_start = i
                break

    if sym_start is None:
        raise ValueError("Cannot find SYMLINKS JSON boundaries")

    symlinks = json.loads(pre_dict[sym_start : sym_end + 1])

    # ── Step 4: Extract DEFAULT_ENTRYPOINT ──
    # Before SYMLINKS: ...\n,\n"entrypoint"\n,\nSYMLINKS
    pre_sym = pre_dict[:sym_start].rstrip()
    if pre_sym.endswith(","):
        pre_sym = pre_sym[:-1].rstrip()

    # Entrypoint is a quoted string
    ep_match = re.search(r'"([^"]+)"$', pre_sym)
    if not ep_match:
        ep_match = re.search(r"'([^']+)'$", pre_sym)
    if not ep_match:
        raise ValueError("Cannot find DEFAULT_ENTRYPOINT string")

    entrypoint = ep_match.group(1).replace("\\\\", "\\")
    ep_start_in_presym = ep_match.start()

    # ── Step 5: Extract VIRTUAL_FILESYSTEM ──
    # Before entrypoint: ...\n,\nVFS_JSON\n,\n"entrypoint"
    pre_ep = pre_sym[:ep_start_in_presym].rstrip()
    if pre_ep.endswith(","):
        pre_ep = pre_ep[:-1].rstrip()

    # VFS JSON ends here
    vfs_end = len(pre_ep) - 1
    brace_count = 0
    vfs_start = None
    for i in range(vfs_end, -1, -1):
        if pre_ep[i] == "}":
            brace_count += 1
        elif pre_ep[i] == "{":
            brace_count -= 1
            if brace_count == 0:
                vfs_start = i
                break

    if vfs_start is None:
        raise ValueError("Cannot find VFS JSON boundaries")

    vfs_json = pre_ep[vfs_start : vfs_end + 1]
    vfs = json.loads(vfs_json)

    # Calculate absolute offsets for reference
    # dict_start is relative to prelude_offset in the text
    dict_abs = prelude_offset + dict_start
    vfs_abs = prelude_offset + vfs_start

    return {
        "vfs": vfs,
        "dict": dictionary,
        "entrypoint": entrypoint,
        "symlinks": symlinks,
        "compress": docompress,
        "prelude_offset": prelude_offset,
        "vfs_offset": vfs_abs,
        "dict_offset": dict_abs,
    }


def decode_path(encoded_path: str, rev_dict: dict) -> str:
    """Decode a VFS path using the reverse dictionary."""
    parts = encoded_path.split("/")
    decoded = []
    for part in parts:
        decoded.append(rev_dict.get(part, part))
    return "\\".join(decoded) if decoded and decoded[0].endswith(":") else "/".join(decoded)


def classify_entry(stores: dict) -> str:
    """Classify a VFS entry based on which stores it has."""
    has_blob = STORE_BLOB in stores
    has_content = STORE_CONTENT in stores
    has_links = STORE_LINKS in stores

    if has_links:
        return "DIR"
    if has_blob and has_content:
        return "JS+BYTECODE"
    if has_blob:
        return "BYTECODE"
    if has_content:
        return "FILE"
    return "META"


def format_size(size: int) -> str:
    """Format byte size in human-readable form."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    else:
        return f"{size / (1024 * 1024):.1f} MB"


def extract_packages(vfs: dict, rev_dict: dict) -> set:
    """Extract the set of npm package names from VFS paths."""
    packages = set()
    for encoded_path in vfs:
        decoded = decode_path(encoded_path, rev_dict)
        parts = re.split(r"[/\\]", decoded)
        for i, part in enumerate(parts):
            if part == "node_modules" and i + 1 < len(parts):
                pkg_name = parts[i + 1]
                if pkg_name.startswith("@") and i + 2 < len(parts):
                    pkg_name = f"{pkg_name}/{parts[i + 2]}"
                packages.add(pkg_name)
    return packages


def build_tree(entries: list) -> dict:
    """Build a nested dict tree from decoded path entries."""
    tree = {}
    for path, info in entries:
        parts = re.split(r"[/\\]", path)
        node = tree
        for part in parts[:-1]:
            existing = node.get(part)
            if existing is None or not isinstance(existing, dict):
                node[part] = {}
            node = node[part]
        # Leaf node stores classification (don't overwrite a subtree)
        existing = node.get(parts[-1])
        if not isinstance(existing, dict):
            node[parts[-1]] = info
    return tree


def print_tree(tree: dict, prefix: str = "", is_last: bool = True, depth: int = 0,
               max_depth: int = -1):
    """Print a directory tree with box-drawing characters."""
    items = sorted(tree.items(), key=lambda x: (not isinstance(x[1], dict), x[0]))
    for i, (name, subtree) in enumerate(items):
        is_last_item = i == len(items) - 1
        connector = "└── " if is_last_item else "├── "
        if isinstance(subtree, dict) and any(isinstance(v, dict) for v in subtree.values()):
            # Directory node
            print(f"{prefix}{connector}{name}/")
            if max_depth < 0 or depth < max_depth:
                extension = "    " if is_last_item else "│   "
                print_tree(subtree, prefix + extension, is_last_item, depth + 1, max_depth)
        elif isinstance(subtree, dict):
            # Directory with only file children
            print(f"{prefix}{connector}{name}/")
            if max_depth < 0 or depth < max_depth:
                extension = "    " if is_last_item else "│   "
                print_tree(subtree, prefix + extension, is_last_item, depth + 1, max_depth)
        else:
            # File leaf
            entry_type, total_size = subtree
            size_str = format_size(total_size) if total_size > 0 else ""
            tag = f" [{entry_type}]" if entry_type != "FILE" else ""
            pad = f"  ({size_str})" if size_str else ""
            print(f"{prefix}{connector}{name}{tag}{pad}")


def extract_files(data: bytes, vfs: dict, rev_dict: dict,
                  payload_pos: int, compress: int, output_dir: str,
                  filter_pattern: str | None = None):
    """Extract file contents from the payload to disk."""
    try:
        import brotli as brotli_mod
        has_brotli = True
    except ImportError:
        has_brotli = False

    os.makedirs(output_dir, exist_ok=True)
    extracted = 0
    skipped = 0

    for encoded_path, stores in vfs.items():
        decoded = decode_path(encoded_path, rev_dict)
        # Strip Windows drive letter prefix (e.g. "C:\snapshot\..." → "snapshot\...")
        rel = decoded.replace("\\", "/")
        if len(rel) >= 2 and rel[1] == ":":
            rel = rel[2:].lstrip("/")

        if filter_pattern and not fnmatch.fnmatch(rel, filter_pattern):
            skipped += 1
            continue

        if STORE_LINKS in stores:
            # Directory entry — create dir
            dir_path = os.path.join(output_dir, rel.replace("/", os.sep))
            os.makedirs(dir_path, exist_ok=True)
            continue

        if STORE_CONTENT not in stores:
            skipped += 1
            continue

        offset, size = stores[STORE_CONTENT]
        abs_offset = payload_pos + offset

        if abs_offset + size > len(data):
            print(f"  [!] Out of bounds: {decoded} (offset={abs_offset}, size={size})",
                  file=sys.stderr)
            skipped += 1
            continue

        content = data[abs_offset : abs_offset + size]

        # Decompress if needed
        if compress == 1:
            try:
                content = zlib.decompress(content, 16 + zlib.MAX_WBITS)
            except zlib.error:
                pass  # may not be compressed
        elif compress == 2 and has_brotli:
            try:
                content = brotli_mod.decompress(content)
            except Exception:
                pass

        out_path = os.path.join(output_dir, rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(out_path), exist_ok=True)

        with open(out_path, "wb") as fout:
            fout.write(content)
        extracted += 1

    print(f"\nExtracted {extracted} files, skipped {skipped}")


def print_stats(vfs: dict, rev_dict: dict, entrypoint: str, compress: int,
                symlinks: dict, prelude_offset: int):
    """Print summary statistics."""
    total = len(vfs)
    types = defaultdict(int)
    total_blob_size = 0
    total_content_size = 0
    total_links = 0

    packages = extract_packages(vfs, rev_dict)

    for encoded_path, stores in vfs.items():
        entry_type = classify_entry(stores)
        types[entry_type] += 1

        if STORE_BLOB in stores:
            total_blob_size += stores[STORE_BLOB][1]
        if STORE_CONTENT in stores:
            total_content_size += stores[STORE_CONTENT][1]
        if STORE_LINKS in stores:
            total_links += 1

    print("=" * 70)
    print("pkg VFS Summary")
    print("=" * 70)
    print(f"  Prelude offset:    0x{prelude_offset:x} ({prelude_offset:,} bytes)")
    print(f"  Entrypoint:        {entrypoint}")
    print(f"  Compression:       {COMPRESS_NAMES.get(compress, f'unknown ({compress})')}")
    print(f"  Symlinks:          {len(symlinks)} entries")
    print(f"  Dictionary:        {len(rev_dict)} name mappings")
    print()
    print(f"  Total VFS entries: {total:,}")
    print(f"    Directories:     {types['DIR']:,}")
    print(f"    JS + Bytecode:   {types['JS+BYTECODE']:,}")
    print(f"    Bytecode only:   {types['BYTECODE']:,}")
    print(f"    Files:           {types['FILE']:,}")
    print(f"    Metadata only:   {types['META']:,}")
    print()
    print(f"  Payload sizes (compressed):")
    print(f"    BLOB store:      {format_size(total_blob_size)}")
    print(f"    CONTENT store:   {format_size(total_content_size)}")
    print()
    print(f"  npm packages:      {len(packages)}")
    print("=" * 70)


def find_interesting(vfs: dict, rev_dict: dict, entrypoint: str) -> list[dict]:
    """
    Identify VFS entries that are likely analyst-relevant.

    Heuristics (each entry gets a list of reason tags):
      1. ENTRYPOINT   — the default entrypoint file
      2. ROOT_FILE    — files outside node_modules/ (author's own code)
      3. NATIVE_ADDON — .node prebuilt binaries (always extractable)
      4. JS_NO_BYTECODE — .js files stored as CONTENT only (recoverable source)
      5. ROOT_MANIFEST — package.json at project root (reveals deps/scripts)
      6. SIZE_OUTLIER  — CONTENT size in the top 1% for its category
      7. NESTED_PACKAGE_JSON — package.json with notable fields
    """
    results = []

    # Decode all paths and collect content sizes for percentile calc
    decoded_entries = []
    js_content_sizes = []
    for encoded_path, stores in vfs.items():
        decoded = decode_path(encoded_path, rev_dict)
        parts = re.split(r"[/\\]", decoded)
        entry_type = classify_entry(stores)
        content_size = stores[STORE_CONTENT][1] if STORE_CONTENT in stores else 0
        decoded_entries.append((encoded_path, decoded, parts, stores, entry_type, content_size))
        if entry_type in ("JS+BYTECODE", "FILE") and decoded.endswith(".js"):
            js_content_sizes.append(content_size)

    # Compute top-1% threshold for size outliers
    js_content_sizes.sort()
    size_threshold = 0
    if js_content_sizes:
        p99_idx = int(len(js_content_sizes) * 0.99)
        size_threshold = js_content_sizes[min(p99_idx, len(js_content_sizes) - 1)]

    # Identify the snapshot root prefix (e.g. "C:\snapshot\myth" or "/snapshot/app")
    # by finding the shortest path that contains node_modules
    root_prefix = None
    for _, decoded, parts, _, _, _ in decoded_entries:
        if "node_modules" in parts:
            nm_idx = parts.index("node_modules")
            candidate = "\\".join(parts[:nm_idx]) if "\\" in decoded else "/".join(parts[:nm_idx])
            if root_prefix is None or len(candidate) < len(root_prefix):
                root_prefix = candidate

    # Normalize entrypoint for comparison
    ep_normalized = entrypoint.replace("\\\\", "\\")

    for encoded_path, decoded, parts, stores, entry_type, content_size in decoded_entries:
        if entry_type == "DIR":
            continue

        reasons = []

        # 1. Is this the entrypoint?
        if decoded == ep_normalized or decoded.replace("/", "\\") == ep_normalized:
            reasons.append("ENTRYPOINT")

        # 2. Root-level file (not inside any node_modules)?
        in_node_modules = "node_modules" in parts
        is_root_file = not in_node_modules and root_prefix and decoded.startswith(root_prefix)
        if is_root_file:
            reasons.append("ROOT_FILE")

        # 3. Native addon (.node file)?
        if decoded.endswith(".node"):
            reasons.append("NATIVE_ADDON")

        # 4. JS file without bytecode (recoverable source)?
        #    Inside node_modules, most unbytecoded .js files are standard
        #    npm dist/lib/esm bundles — not custom malware code.
        #    Only flag as interesting if outside node_modules, or if the
        #    file looks non-standard (not from a typical npm path pattern).
        if decoded.endswith(".js") and STORE_CONTENT in stores and STORE_BLOB not in stores:
            if not in_node_modules:
                reasons.append("JS_NO_BYTECODE")
            else:
                reasons.append("JS_NO_BYTECODE_MINOR")

        # 5. Root-level package.json?
        if is_root_file and parts[-1] == "package.json":
            reasons.append("ROOT_MANIFEST")

        # 6. Size outlier (top 1% content size for JS files)?
        if decoded.endswith(".js") and content_size >= size_threshold and size_threshold > 0:
            reasons.append("SIZE_OUTLIER")

        # 7. Suspicious or notable filenames?
        basename = parts[-1].lower() if parts else ""
        suspicious_names = {
            "config.js", "config.json", "settings.js", "settings.json",
            "payload.js", "inject.js", "injection.js", "hook.js",
            "stealer.js", "grab.js", "grabber.js", "token.js",
            "discord.js", "startup.js", "persist.js", "loader.js",
            "bot.js", "c2.js", "exfil.js", "keylog.js",
        }
        if basename in suspicious_names and in_node_modules:
            # Only flag if it's NOT a standard part of a known package
            # (e.g., discord.js is a legit package name)
            reasons.append("SUSPICIOUS_NAME")

        if reasons:
            total_size = sum(s[1] for s in stores.values())
            results.append({
                "path": decoded,
                "type": entry_type,
                "reasons": reasons,
                "content_size": content_size,
                "total_size": total_size,
                "stores": stores,
            })

    # Sort: entrypoint first, then root files, then by reason count desc, then size desc
    def sort_key(entry):
        r = entry["reasons"]
        priority = 0
        if "ENTRYPOINT" in r:
            priority = -3
        elif "ROOT_FILE" in r:
            priority = -2
        elif "JS_NO_BYTECODE" in r:
            priority = -1
        return (priority, -len(r), -entry["content_size"])

    results.sort(key=sort_key)
    return results


def print_interesting(entries: list):
    """Print interesting VFS entries grouped by category."""
    if not entries:
        print("  No interesting entries found.")
        return

    # Group by primary reason
    groups = defaultdict(list)
    for entry in entries:
        primary = entry["reasons"][0]
        groups[primary].append(entry)

    group_order = [
        ("ENTRYPOINT", "Entrypoint"),
        ("ROOT_FILE", "Root-level files (author code)"),
        ("ROOT_MANIFEST", "Root-level files (author code)"),  # merge with ROOT_FILE
        ("JS_NO_BYTECODE", "JS without bytecode (recoverable source)"),
        ("NATIVE_ADDON", "Native addons (.node binaries)"),
        ("SUSPICIOUS_NAME", "Suspicious filenames"),
        ("SIZE_OUTLIER", "Size outliers (top 1% content)"),
        ("JS_NO_BYTECODE_MINOR", "JS without bytecode — noise (dist/test/browser bundles)"),
    ]

    printed_headers = set()
    for reason_key, header in group_order:
        if reason_key not in groups:
            continue
        # Merge ROOT_MANIFEST into ROOT_FILE display
        if reason_key == "ROOT_MANIFEST" and "ROOT_FILE" in printed_headers:
            continue
        if header in printed_headers:
            continue
        printed_headers.add(header)

        section_entries = groups[reason_key]
        # Also pull in ROOT_MANIFEST entries when showing ROOT_FILE
        if reason_key == "ROOT_FILE" and "ROOT_MANIFEST" in groups:
            seen = {e["path"] for e in section_entries}
            for e in groups["ROOT_MANIFEST"]:
                if e["path"] not in seen:
                    section_entries.append(e)

        print(f"\n--- {header} ---")

        # Summary-only categories: show count + total size instead of full listing
        summary_only = {"NATIVE_ADDON", "SIZE_OUTLIER", "SUSPICIOUS_NAME",
                        "JS_NO_BYTECODE_MINOR"}
        if reason_key in summary_only:
            total_size = sum(e["content_size"] for e in section_entries)
            print(f"  {len(section_entries)} files, {format_size(total_size)} total")
            continue

        for entry in section_entries:
            path = entry["path"]
            etype = entry["type"]
            size = format_size(entry["content_size"]) if entry["content_size"] else "-"
            tags = ", ".join(entry["reasons"])
            # Truncate path for display
            if len(path) > 75:
                path = "..." + path[-72:]
            print(f"  {path:<76} {etype:<13} {size:>10}  [{tags}]")


def print_table(vfs: dict, rev_dict: dict, filter_pattern: str | None = None):
    """Print VFS entries as a formatted table."""
    print(f"{'Decoded Path':<80} {'Type':<13} {'Stores':<30} {'Total Size':>12}")
    print("-" * 137)

    for encoded_path, stores in sorted(vfs.items()):
        decoded = decode_path(encoded_path, rev_dict)

        if filter_pattern and not fnmatch.fnmatch(decoded.replace("\\", "/"), filter_pattern):
            continue

        entry_type = classify_entry(stores)

        store_parts = []
        total_size = 0
        for skey in sorted(stores.keys()):
            offset, size = stores[skey]
            store_parts.append(f"{STORE_NAMES.get(skey, skey).split()[0]}:{format_size(size)}")
            total_size += size

        stores_str = ", ".join(store_parts)
        total_str = format_size(total_size)

        # Truncate long paths
        display_path = decoded
        if len(display_path) > 79:
            display_path = "..." + display_path[-76:]

        print(f"{display_path:<80} {entry_type:<13} {stores_str:<30} {total_str:>12}")


def main():
    parser = argparse.ArgumentParser(
        description="Extract and display pkg VFS from Node.js executables"
    )
    parser.add_argument("binary", help="Path to pkg-compiled Node.js executable")
    parser.add_argument("--json", action="store_true",
                        help="Output raw JSON (VFS + DICT + metadata)")
    parser.add_argument("--tree", action="store_true",
                        help="Display as directory tree")
    parser.add_argument("--tree-depth", type=int, default=-1,
                        help="Max tree depth (-1 = unlimited)")
    parser.add_argument("--extract-to", metavar="DIR",
                        help="Extract file contents to directory")
    parser.add_argument("--filter", metavar="PATTERN",
                        help="Filter entries by glob pattern (e.g. '*/axios/*')")
    parser.add_argument("--stats", action="store_true",
                        help="Show summary statistics only")
    parser.add_argument("--packages", action="store_true",
                        help="List npm packages only")
    parser.add_argument("--interesting", action="store_true",
                        help="Show analyst-relevant files (entrypoints, "
                             "root files, native addons, recoverable JS, "
                             "size outliers)")

    args = parser.parse_args()

    # ── Read binary ──────────────────────────────────────────────────
    binary_path = args.binary
    if not os.path.isfile(binary_path):
        print(f"Error: File not found: {binary_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Reading {binary_path} ...", file=sys.stderr)
    with open(binary_path, "rb") as f:
        data = f.read()

    file_size = len(data)
    print(f"[*] File size: {format_size(file_size)} ({file_size:,} bytes)", file=sys.stderr)

    # ── Locate pkg structures ────────────────────────────────────────
    prelude_offset = find_prelude(data)
    if prelude_offset is None:
        print("[!] Could not find pkg prelude IIFE signature.", file=sys.stderr)
        print("    This may not be a pkg-compiled binary.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Prelude IIFE at offset 0x{prelude_offset:x}", file=sys.stderr)

    bootstrap_offset = find_bootstrap(data)
    payload_pos = None
    if bootstrap_offset is not None:
        print(f"[*] Bootstrap at offset 0x{bootstrap_offset:x}", file=sys.stderr)
        payload_pos = extract_payload_position(data, bootstrap_offset)
        if payload_pos:
            print(f"[*] PAYLOAD_POSITION = {payload_pos} (0x{payload_pos:x})", file=sys.stderr)

    if payload_pos is None:
        overlay = pe_overlay_offset(data)
        if overlay is not None:
            payload_pos = overlay
            print(f"[*] PAYLOAD_POSITION via PE overlay = {payload_pos} (0x{payload_pos:x})",
                  file=sys.stderr)

    # ── Extract VFS components ───────────────────────────────────────
    print("[*] Parsing prelude arguments ...", file=sys.stderr)
    try:
        result = extract_vfs_components(data, prelude_offset)
    except (ValueError, json.JSONDecodeError) as e:
        print(f"[!] Failed to parse VFS: {e}", file=sys.stderr)
        sys.exit(1)

    vfs = result["vfs"]
    dictionary = result["dict"]
    entrypoint = result["entrypoint"]
    symlinks = result["symlinks"]
    compress = result["compress"]

    # Build reverse dictionary (short code → real name)
    rev_dict = {v: k for k, v in dictionary.items()}

    print(f"[*] VFS entries: {len(vfs):,}", file=sys.stderr)
    print(f"[*] Dictionary:  {len(dictionary):,} mappings", file=sys.stderr)
    print(f"[*] Entrypoint:  {entrypoint}", file=sys.stderr)
    print(f"[*] Compression: {COMPRESS_NAMES.get(compress, str(compress))}", file=sys.stderr)
    print(f"[*] Symlinks:    {len(symlinks)}", file=sys.stderr)
    print(file=sys.stderr)

    # ── Output ───────────────────────────────────────────────────────
    if args.json:
        # Decode all paths for JSON output
        decoded_vfs = {}
        for encoded_path, stores in vfs.items():
            decoded = decode_path(encoded_path, rev_dict)
            decoded_vfs[decoded] = stores

        output = {
            "file": os.path.basename(binary_path),
            "file_size": file_size,
            "prelude_offset": prelude_offset,
            "entrypoint": entrypoint,
            "compression": COMPRESS_NAMES.get(compress, str(compress)),
            "symlinks": symlinks,
            "dictionary_size": len(dictionary),
            "vfs_entry_count": len(vfs),
            "vfs": decoded_vfs,
            "dictionary": dictionary,
        }

        print(json.dumps(output, indent=2))

    elif args.stats:
        print_stats(vfs, rev_dict, entrypoint, compress, symlinks, prelude_offset)

    elif args.packages:
        packages = extract_packages(vfs, rev_dict)
        print(f"npm packages ({len(packages)}):")
        for pkg in sorted(packages):
            print(f"  {pkg}")

    elif args.interesting:
        entries = find_interesting(vfs, rev_dict, entrypoint)
        print_interesting(entries)

    elif args.tree:
        entries = []
        for encoded_path, stores in vfs.items():
            decoded = decode_path(encoded_path, rev_dict)
            if args.filter and not fnmatch.fnmatch(decoded.replace("\\", "/"), args.filter):
                continue
            entry_type = classify_entry(stores)
            total_size = sum(s[1] for s in stores.values())
            entries.append((decoded, (entry_type, total_size)))

        tree = build_tree(entries)
        print_tree(tree, max_depth=args.tree_depth)

    elif args.extract_to:
        if payload_pos is None:
            print("[!] PAYLOAD_POSITION not found in bootstrap (unpatched).",
                  file=sys.stderr)
            print("    Cannot extract file contents without payload offset.",
                  file=sys.stderr)
            print("    Try: --stats or --tree for metadata-only analysis.",
                  file=sys.stderr)
            sys.exit(1)
        extract_files(data, vfs, rev_dict, payload_pos, compress, args.extract_to,
                      args.filter)

    else:
        # Default: table view
        print_table(vfs, rev_dict, args.filter)


if __name__ == "__main__":
    main()
