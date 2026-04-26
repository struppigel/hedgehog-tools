#!/usr/bin/env python3
"""
QBFC (Quick Batch File Compiler) Batch Script Extractor

Extracts and decrypts the embedded batch script from QBFC-compiled executables.
QBFC encrypts the batch script using XXTEA in ECB mode (32-byte blocks) with a
hardcoded key, stored in the MAN RCDATA resource (type 5).

Algorithm reversed from the QBFC Delphi runtime:
  - FUN_0055be50: resource loader + block-level ECB decryption (32-byte blocks)
  - FUN_0055b850: per-block XXTEA wrapper
  - FUN_0055b6a0: XXTEA core (Corrected Block TEA)
  - FUN_0055b650: XXTEA round function (MX)
  - FUN_0055b490: byte array → uint32 array conversion
  - DAT_005877b0: XXTEA delta constant (0x9E3779B9)
  - DAT_0055c178: hardcoded 20-byte key string

Tested against QBFC version "(C) Copyright 2001-2024 AbyssMedia.com."
The key is compiled into the QBFC runtime stub; it may differ across versions.

Usage:
    python3 qbfc_extract.py <qbfc_executable> [output.bat]
"""

import struct
import sys

try:
    import pefile
except ImportError:
    sys.exit("Error: pefile required. Install with: pip install pefile")

import re

# XXTEA delta constant (confirmed at DAT_005877b0)
DELTA = 0x9E3779B9
MASK = 0xFFFFFFFF

# XXTEA block size used by QBFC (0x20 bytes = 8 uint32 words)
BLOCK_SIZE = 32

# Fallback key from QBFC 2024 version (DAT_0055c178)
QBFC_KEY_FALLBACK = b"0opjc821dqdds(Y&^%ad"


def bytes_to_words(data: bytes) -> list:
    """Convert byte array to uint32 LE array (FUN_0055b490 with param_3=0)."""
    n_words = (len(data) + 3) // 4
    words = []
    for i in range(n_words):
        word = 0
        for j in range(4):
            idx = i * 4 + j
            if idx < len(data):
                word |= data[idx] << (j * 8)
        words.append(word & MASK)
    return words


def words_to_bytes(words: list) -> bytes:
    """Convert uint32 LE array back to bytes."""
    return b''.join(struct.pack('<I', w) for w in words)


def xxtea_decrypt_block(v: list, key: list) -> list:
    """Decrypt a single XXTEA block in-place.

    Matches FUN_0055b6a0 from the QBFC runtime.
    Reference: Correction to xtea, D.J. Wheeler and R.M. Needham (1998).

    Args:
        v: list of uint32 words (data block, >= 2 words)
        key: list of 4 uint32 words
    Returns:
        Decrypted list of uint32 words.
    """
    n = len(v)
    if n < 2:
        return v

    rounds = 52 // n + 6
    total = (rounds * DELTA) & MASK
    y = v[0]

    while total != 0:
        e = (total >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            # MX round function (FUN_0055b650)
            mx = ((((z >> 5) ^ ((y << 2) & MASK)) + (((y >> 3) & MASK) ^ ((z << 4) & MASK))) & MASK) ^ \
                 ((((total ^ y) & MASK) + ((key[(p & 3) ^ e] ^ z) & MASK)) & MASK)
            v[p] = (v[p] - mx) & MASK
            y = v[p]
        # Handle index 0: z = v[n-1]
        z = v[n - 1]
        mx = ((((z >> 5) ^ ((y << 2) & MASK)) + (((y >> 3) & MASK) ^ ((z << 4) & MASK))) & MASK) ^ \
             ((((total ^ y) & MASK) + ((key[0 ^ e] ^ z) & MASK)) & MASK)
        v[0] = (v[0] - mx) & MASK
        y = v[0]
        total = (total - DELTA) & MASK

    return v


def xxtea_decrypt_ecb(data: bytes, key_bytes: bytes) -> bytes:
    """Decrypt data using XXTEA in ECB mode with 32-byte blocks.

    Matches the block loop in FUN_0055be50:
      while (0x1f < resource_size - offset):
          memcpy(temp, src, 0x20)
          xxtea_decrypt(temp, key)
          memcpy(dst, temp, 0x20)
          offset += 0x20

    Args:
        data: encrypted data (MAN resource contents)
        key_bytes: key as byte string
    Returns:
        Decrypted data as bytes.
    """
    # Convert key to uint32 words (FUN_0055b490)
    key_words = bytes_to_words(key_bytes)
    # XXTEA uses key[(p&3)^e] so only indices 0-3 matter
    while len(key_words) < 4:
        key_words.append(0)

    result = bytearray()
    offset = 0

    while offset + BLOCK_SIZE <= len(data):
        block = data[offset:offset + BLOCK_SIZE]
        v = bytes_to_words(block)
        v = xxtea_decrypt_block(v, key_words)
        result.extend(words_to_bytes(v))
        offset += BLOCK_SIZE

    # Any remaining bytes (< 32) are not encrypted per FUN_0055be50
    if offset < len(data):
        result.extend(data[offset:])

    return bytes(result)


def extract_xxtea_key(pe: pefile.PE) -> bytes:
    """Extract the XXTEA key from the QBFC runtime code.

    Strategy: The resource loader function (FUN_0055be50) loads resource type 5
    (RCDATA) via FindResourceW, then loads the decryption key with:

        LEA  RCX, [RBP + ??]          ;; 48 8D 4D xx
        LEA  RDX, [RIP + offset]      ;; 48 8D 15 xx xx xx xx  <-- key addr
        CALL key_loader               ;; E8 xx xx xx xx

    This sequence appears after "MOV R8D, 5" (41 C7 C0 05 00 00 00) which sets
    the resource type for FindResourceW, and after two JZ (0F 84) branches that
    guard the FindResourceW/LoadResource return values.

    We search the .text section for this byte pattern and resolve the
    RIP-relative LEA to get the key address.
    """
    # Pattern:
    #   0F 84 xx xx xx xx        JZ (guard after LoadResource)
    #   48 8D 4D xx              LEA RCX, [RBP + ??]
    #   48 8D 15 (xx xx xx xx)  LEA RDX, [RIP + offset]  <-- capture group
    #   E8 xx xx xx xx           CALL key_loader
    #
    # The two JZ guards and MOV R8D,5 make this unique in QBFC binaries.
    pattern = re.compile(
        b'\\x0f\\x84.{4}'           # JZ rel32 (LoadResource null check)
        b'\\x48\\x8d\\x4d.'          # LEA RCX, [RBP + imm8]
        b'\\x48\\x8d\\x15(.{4})'     # LEA RDX, [RIP + imm32] — key offset
        b'\\xe8.{4}',                # CALL key_loader
        re.DOTALL
    )

    pe_data = pe.__data__
    image_base = pe.OPTIONAL_HEADER.ImageBase

    for section in pe.sections:
        if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            sec_data = pe_data[section.PointerToRawData:
                               section.PointerToRawData + section.SizeOfRawData]
            for m in pattern.finditer(sec_data):
                # Resolve RIP-relative offset
                # The LEA RDX instruction is at file offset:
                #   section.PointerToRawData + m.start() + 10 (offset of 48 8D 15)
                # RIP points to the next instruction (after the 7-byte LEA):
                #   lea_rva = section.VirtualAddress + (m.start() + 10) + 7
                lea_file_offset = section.PointerToRawData + m.start() + 10
                rel_offset = struct.unpack_from('<i', m.group(1))[0]
                lea_rva = section.VirtualAddress + (m.start() + 10) + 7
                key_rva = lea_rva + rel_offset

                # Convert RVA to file offset and read null-terminated key
                key_file_offset = pe.get_offset_from_rva(key_rva)
                if key_file_offset is None:
                    continue

                # Read key until null terminator (max 64 bytes)
                key_region = pe_data[key_file_offset:key_file_offset + 64]
                null_pos = key_region.find(b'\x00')
                if null_pos <= 0:
                    continue
                key = key_region[:null_pos]

                # Sanity check: key should be printable ASCII, 8-40 bytes
                if 8 <= len(key) <= 40 and all(0x20 <= b < 0x7f for b in key):
                    print(f"Extracted XXTEA key: \"{key.decode('ascii')}\" "
                          f"({len(key)} bytes) at RVA 0x{key_rva:x}",
                          file=sys.stderr)
                    return key

    return None


def extract_qbfc_script(pe_path: str) -> bytes:
    """Extract and decrypt the batch script from a QBFC executable."""
    pe = pefile.PE(pe_path)

    marker_found = False
    man_data = None

    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id == 99:
            for e2 in entry.directory.entries:
                for e3 in e2.directory.entries:
                    data = pe.get_data(e3.data.struct.OffsetToData, e3.data.struct.Size)
                    if data == b'QUICKBFC':
                        marker_found = True

        elif entry.id == 5:  # RCDATA
            for e2 in entry.directory.entries:
                name = str(e2.name) if e2.name else ''
                if name == 'MAN':
                    for e3 in e2.directory.entries:
                        man_data = pe.get_data(e3.data.struct.OffsetToData, e3.data.struct.Size)

    if not marker_found:
        print("Warning: QUICKBFC marker not found — may not be a QBFC executable",
              file=sys.stderr)

    if man_data is None:
        print("Error: MAN resource not found", file=sys.stderr)
        sys.exit(1)

    print(f"MAN resource: {len(man_data)} bytes ({len(man_data) // BLOCK_SIZE} "
          f"full blocks, {len(man_data) % BLOCK_SIZE} remainder)", file=sys.stderr)

    # Extract key from the QBFC runtime code, fall back to known key
    key = extract_xxtea_key(pe)
    if key is None:
        key = QBFC_KEY_FALLBACK
        print(f"Warning: could not extract key from code, using fallback: "
              f"\"{key.decode('ascii')}\"", file=sys.stderr)

    # Decrypt using XXTEA-ECB with 32-byte blocks
    decrypted = xxtea_decrypt_ecb(man_data, key)

    # Padding removal (FUN_0055be50):
    #   pad_len = decrypted[resource_size - 1]   (last byte)
    #   script_len = resource_size - pad_len - 1
    if len(decrypted) > 0:
        pad_len = decrypted[len(man_data) - 1]
        script_len = len(man_data) - pad_len - 1
        if 0 < script_len <= len(decrypted):
            decrypted = decrypted[:script_len]
            print(f"Padding byte: 0x{pad_len:02x} ({pad_len}), "
                  f"script length: {script_len} bytes", file=sys.stderr)
        else:
            print(f"Warning: unexpected padding byte 0x{pad_len:02x} "
                  f"(script_len would be {script_len}), returning raw output",
                  file=sys.stderr)

    return decrypted


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <qbfc_executable> [output.bat]")
        sys.exit(1)

    pe_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else None

    script = extract_qbfc_script(pe_path)

    if out_path:
        with open(out_path, 'wb') as f:
            f.write(script)
        print(f"Written to {out_path}", file=sys.stderr)
    else:
        sys.stdout.buffer.write(script)
        sys.stdout.buffer.write(b'\n')


if __name__ == '__main__':
    main()
