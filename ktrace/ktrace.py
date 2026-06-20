#!/usr/bin/env python3
"""ktrace — Speakeasy-based kernel-mode driver API tracer.

Usage:
    ktrace.py <driver.sys> [--out OUTDIR] [options]

Works on x86 + x64 Windows kernel drivers. Outputs:
  - <OUTDIR>/<basename>.log      human-readable trace
  - <OUTDIR>/<basename>.jsonl    one JSON object per traced event
  - <OUTDIR>/<basename>.meta     small text summary (counts, status)

Per-driver quirks are kept in profiles.py, indexed by SHA-256.

Module layout (see README):
    ktrace.py   — CLI + bootstrap + orchestration  (this file)
    shim.py     — Speakeasy patches + stubs + intrinsics + fake-IO hooks
    decode.py   — semantic-arg decoding + symbol resolution
    events.py   — Phaser + RLE-aware Tracer (log/JSONL emission)
    discover.py — capstone-based IOCTL discovery
    invoke.py   — post-DriverEntry callback / IRP synthesis
    irp.py      — x86 + x64 IRP / DriverObject layouts
    profiles.py — per-driver quirks (SHA-256 keyed)
"""
from __future__ import annotations
import argparse
import json
import struct
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import decode      # noqa: E402
import discover    # noqa: E402
import events      # noqa: E402
import invoke      # noqa: E402
import irp         # noqa: E402
import profiles    # noqa: E402
import shim        # noqa: E402


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('sample', help='Path to a Windows kernel driver (.sys).')
    p.add_argument('--out', default=None,
                   help='Output directory (default: ./ktrace_out).')
    p.add_argument('--timeout', type=int, default=300,
                   help='Speakeasy emulation timeout in seconds (default 300).')
    p.add_argument('--profile', default=None,
                   help='Force a profile by name (otherwise auto by SHA-256).')
    p.add_argument('--no-profile', action='store_true')
    p.add_argument('--symbols', default=None,
                   help='Optional JSON file: {"0xADDR": "name", ...}.')
    p.add_argument('--ioctl', action='append', default=[],
                   type=lambda x: int(x, 0),
                   help='IOCTL to fire after DriverEntry (repeatable).')
    p.add_argument('--ioctl-input', default='',
                   help='Hex bytes for the IOCTL input buffer.')
    p.add_argument(
        '--ioctl-only', type=lambda x: int(x, 0), default=None,
        metavar='CODE',
        help=(
            'Focus mode. Fire ONLY this single IOCTL, skip everything '
            'else that\'s skippable: no IOCTL fuzz, no extra IRP majors '
            '(PNP/POWER/SHUTDOWN/QUERY/SET/CLEANUP), no callback '
            'invocation, no reinit, no DriverUnload, no profile fake-'
            'driver IRPs. DriverEntry still runs (it has to, to set up '
            'MajorFunction[]). The simplest way to see what one IOCTL '
            'does without log clutter. Equivalent to: --ioctl CODE '
            '--no-ioctl-fuzz --no-more-irps --no-invoke-callbacks '
            '--no-reinit --no-unload.'))
    p.add_argument('--no-reinit', action='store_true')
    p.add_argument('--no-unload', action='store_true',
                   help='Skip invoking DriverObject->DriverUnload after IRP phase.')
    p.add_argument('--force-strstr-match', action='store_true',
                   help='Make strstr return haystack base on every miss. '
                        'Bypasses anti-emulation checks where a driver '
                        'looks for a runtime-derived fingerprint inside '
                        'its own install path.')
    p.add_argument('--fake-modules', default='',
                   help='Inject extra entries into NtQuerySystemInformation('
                        'SystemModuleInformation) results so anti-AV / EDR-'
                        'hunting drivers find their targets. Comma-separated. '
                        'Presets: av, defender, sysmon, common, all. You can '
                        'also pass raw driver names ("klif.sys") or paths.')
    p.add_argument('--fake-processes', default='',
                   help='Inject fake processes that PsLookupProcessByProcessId / '
                        'ZwQueryInformationProcess / PsGetProcessImageFileName '
                        'will return. Useful for AV-killer drivers that enumerate '
                        'PIDs and match image names. Presets: av, common, all. '
                        'Raw forms: "msmpeng.exe" or "0x1004:msmpeng.exe".')
    p.add_argument('--no-irp', action='store_true')
    p.add_argument('--quiet', action='store_true')
    p.add_argument(
        '--data-preview', type=int, default=20, metavar='N',
        help=('Max bytes to render inline for (data, length) buffer args '
              'in registry / file / IRP writes. REG_SZ / REG_DWORD / etc. '
              'are always decoded semantically; other buffers are shown '
              'as Python-bytes escaped previews of the first N bytes. '
              'Use 0 to disable previews for terser output (default 20).'))
    p.add_argument('--dump-mem', default=None, metavar='DIR',
                   help='Dump every emulated memory region into this folder.')
    p.add_argument(
        '--dump-files', default=None, metavar='DIR',
        help=('Capture every byte the driver passes to ZwWriteFile / '
              'NtWriteFile and write the accumulated content of each '
              'destination path to a file in DIR (filename = the '
              'sanitised kernel path, e.g. `\\??\\C:\\FileProtect.log` '
              '→ `C__FileProtect.log`). Multiple write/close cycles '
              'against the same path concatenate. Similar to '
              '`speakeasy -z DROP_PATH` for user-mode samples. '
              '`<basename>.meta` gets a `dumped_files` manifest with '
              'kernel path / size / on-disk path for each.'))
    p.add_argument('--fake-io', default='off',
                   choices=['off', 'auto', 'learn', 'replay'],
                   help=('off: real file/registry calls (most halt the trace early). '
                         'auto: every Zw/Nt* file/registry API returns success + '
                         'zero-filled output buffers. '
                         'learn: like auto, plus write <basename>.discovered_io.json '
                         'listing every file path / registry key the driver touched. '
                         'replay: like auto, but read content from the JSON supplied '
                         'via --fake-io-data.'))
    p.add_argument(
        '--fake-io-data', default=None, metavar='JSON',
        help=('Unified file + registry replay map. Top-level keys: '
              '`files`: {path: hex_bytes} — bytes returned when the driver reads '
              'any file whose path suffix-matches (case-insensitive); '
              '`registry`: {key_path: {value_name: {"type": INT, "data_hex": "..."}}} — '
              'value returned for ZwQueryValueKey / RtlQueryRegistryValues. '
              'Supplying any registry entries auto-escalates --fake-io off → auto.'))
    p.add_argument(
        '--fake-tdi-response', default=None, metavar='FILE',
        help=('Path to a binary file whose contents are fed back as the '
              'TDI / raw-socket response. Applies to both the IRP-level '
              'path (IRP_MJ_INTERNAL_DEVICE_CONTROL with IOCTL=TDI_RECEIVE '
              'or TDI_RECEIVE_DATAGRAM) and the higher-level path '
              '(ZwReadFile on a handle opened against \\Device\\Tcp / '
              '\\Device\\Udp / \\Device\\RawIp). Lets analysts feed a '
              'canned HTTP/binary reply so the driver\'s response-parsing / '
              'decryption / payload-unpacking path actually fires. Without '
              'this flag the faker serves a 4-byte JPEG-EOF stub for TCP '
              'and a generic DNS A-record reply for UDP, which is enough '
              'for "did the read succeed" probes but not for real unpacks.'))
    p.add_argument(
        '--prime-reg', action='append', default=[],
        metavar='KEY/VALUE=HEX[:TYPE]',
        help=(
            'Pre-seed a registry value so ZwQueryValueKey returns it. '
            'KEY is the full registry path or the sentinel `service` '
            '(== \\Registry\\Machine\\System\\CurrentControlSet\\Services\\<sha>). '
            'VALUE is the value name. HEX is hex-encoded raw data '
            '(little-endian for REG_DWORD; UTF-16-LE for REG_SZ — use '
            '`hex(s.encode("utf-16-le"))`). TYPE is the REG_TYPE int '
            '(default 4 = REG_DWORD; 1 = REG_SZ; 3 = REG_BINARY; '
            '2 = REG_EXPAND_SZ; 7 = REG_MULTI_SZ). Repeatable. '
            'Examples: `--prime-reg service/BI=07000000` (set d15\'s '
            'BootCount to 7 so the %%7 gate runs the main init path); '
            '`--prime-reg service/rephk=0100000000000000` (set d15\'s '
            'policy-active signal). For richer shapes (REG_SZ paths, '
            'REG_BINARY blobs) supply the `registry` section of '
            '--fake-io-data instead.'))
    p.add_argument(
        '--invoke-callbacks', action='store_true', default=True,
        help=('Default. After DriverEntry returns, fire every registered '
              'callback we can find: Ps*Notify routines, Ex/Cm/Ob callbacks, '
              'PsCreateSystemThread start routines, FLT pre-op callbacks, '
              'IoRegisterDriverReinitialization, and DriverUnload. '
              'Many drivers defer their real work to these — without this, '
              'the trace ends at the DriverEntry return.'))
    p.add_argument(
        '--no-invoke-callbacks', dest='invoke_callbacks',
        action='store_false',
        help=('Suppress ALL post-DriverEntry callback firing: Ps*Notify / '
              'Ex / Cm / Ob (the original invoke_callbacks family), FLT '
              'pre-op handlers, IoRegisterDriverReinitialization, and '
              'DriverUnload. Use when you only care about what DriverEntry '
              'itself does. Note: Speakeasy still runs PsCreateSystemThread '
              'start routines synchronously as part of DriverEntry '
              'emulation — this flag cannot suppress that. To skip just '
              'IRP synthesis, use --no-irp instead.'))
    p.add_argument('--ioctl-fuzz', action='store_true', default=True)
    p.add_argument('--no-ioctl-fuzz', dest='ioctl_fuzz', action='store_false')
    p.add_argument('--more-irps', action='store_true', default=True)
    p.add_argument('--no-more-irps', dest='more_irps', action='store_false')
    p.add_argument(
        '--prime-flag', action='append', default=[],
        metavar='ADDR=VAL[:SIZE]',
        help=(
            'After DriverEntry returns and before callback invocation, '
            'write VAL (integer, hex with 0x prefix supported) to ADDR '
            'with SIZE bytes (default 1). Repeatable. Used to set per-'
            'driver runtime "ready" / "active" flags that gate callback '
            'bodies — discovered statically from Ghidra. Example: '
            '--prime-flag 0x1400a3f2f=1 (the d14 SafeCenter "active" flag).'))
    p.add_argument(
        '--fake-driver', action='append', default=[],
        metavar='NAME',
        help=(
            'Register a synthetic DRIVER_OBJECT for this NT object name '
            '(e.g. "\\Driver\\nsiproxy"). ObReferenceObjectByName returns '
            'our fake driver for matching names; MajorFunction[] slots '
            'point at a 4-byte stub so when the sample reads +0xE0 to '
            'save "original" and then hooks +0xE0, the saved pointer is '
            'callable. ktrace logs the post-IRP +0xE0 value so any hook '
            'the sample installed is visible in the report. Repeatable. '
            'Use with --fake-driver-irp to actually fire an IRP through '
            'the hooked dispatcher.'))
    p.add_argument(
        '--fake-driver-irp', action='append', default=[],
        metavar='NAME:IOCTL=CODE,OUT=N[,IN=HEX]',
        help=(
            'After the regular IOCTL phase, fire an IRP_MJ_DEVICE_CONTROL '
            'through the named fake driver\'s +0xE0 dispatcher (whatever '
            'the sample has hooked it to). If the sample installed a '
            'completion routine on the IRP stack location, ktrace calls '
            'it manually so its body is traced and any buffer scrubbing '
            'is visible in the post-call SystemBuffer dump. Example for '
            'PoisonX-style nsiproxy hooks: '
            '`--fake-driver-irp \\Driver\\nsiproxy:IOCTL=0x12001B,OUT=0x70`. '
            'Repeatable.'))
    p.add_argument(
        '--trace-fn', action='append', default=[],
        metavar='ADDR[:NAME[:SPEC]]',
        help=(
            'Log entries to an internal function inside the sample '
            'itself, the same way kernel API calls are logged. ADDR is '
            'the absolute VA (hex with 0x prefix is fine). NAME is the '
            'display name (defaults to fn_0xADDR). SPEC is a comma-'
            'separated key=value list describing how to render each '
            'arg: `in=N` (arg N points at an input buffer; previewed '
            'as hex up to `len`), `len=N` (arg N is the length value), '
            '`out=N` (arg N points at an output buffer; ktrace '
            'snapshots its contents AFTER the function returns and '
            'logs as a smart-decoded string — useful for in-driver '
            'string decryptors, where the decrypted bytes only exist '
            'in OUT after the call), `wout=N` (same as out= but treats '
            'the OUT buffer as UTF-16-LE wide chars; reads 2×len '
            'bytes), `str=N` / `wstr=N` (arg N is a C / wide string '
            'pointer to dump), `hex=N` (arg N is shown as plain hex), '
            '`argc=N` (limit the displayed arg count; default 4). '
            'Args 0..3 map to RCX/RDX/R8/R9 on x64 and to stack '
            'positions on x86. Example for PoisonX\'s '
            'xor_decrypt_string(src, len, dst) — produces wide '
            'strings: `--trace-fn 0x1400013f8:xor_decrypt_string:'
            'in=0,len=1,wout=2,argc=3`. Repeatable.'))
    p.add_argument(
        '--fake-io-plausible-pe', action='store_true',
        help=(
            'When --fake-io auto/learn/replay returns content for a '
            'file read AND no explicit replay bytes match the path, '
            'return a minimal valid PE64 skeleton (MZ + PE header + '
            'one .text section, SizeOfImage > 0, AddressOfEntryPoint '
            'non-zero) instead of zeros. Unblocks memory-PE-loader '
            'samples that read their stage-2 payload from a file and '
            'abort with "not a PE / DOS sig check failed" against the '
            'default zero-filled buffer. Reads of <0x100 bytes still '
            'get zeros (those are typically size queries / config '
            'DWORDs that PE bytes would corrupt).'))
    p.add_argument(
        '--no-auto-fake-driver', action='store_true',
        help=(
            'Disable the automatic pre-emulation string scan for '
            '`\\Driver\\NAME` literals (ASCII + UTF-16-LE). By default, '
            'every `\\Driver\\NAME` string in the PE\'s readable sections '
            'is added to the fake-driver list so that any hook the sample '
            'tries to install via ObReferenceObjectByName(<that name>) '
            'has a callable target. Useful to keep on for rootkits '
            'targeting `\\Driver\\Tcpip`, `\\Driver\\Disk`, `\\Driver\\Volsnap`, '
            'input-class drivers (`\\Driver\\kbdclass`, `\\Driver\\mouclass`), '
            'etc. Pass this flag to revert to "fake-driver only when '
            'explicitly requested via --fake-driver or a profile".'))
    p.add_argument(
        '--ghidra-export', default=None, metavar='PATH',
        help=(
            'Emit a self-contained Ghidra Java script (GhidraScript) that '
            'ports the trace findings into your Ghidra db. Drop the .java '
            'into ghidra_scripts/ and run from Script Manager. Applies '
            'EOL comments at every traced API call site + labels for '
            'MajorFunction[] dispatchers and registered callbacks. '
            'Addresses are emitted as RVAs and resolved against the '
            'current program\'s ImageBase, so the script is robust '
            'against rebasing. A SHA-256 sanity check warns on mismatch.'))
    return p.parse_args(argv)


def detect_arch_bits(sample_path):
    """Peek at the PE header to decide 32 vs 64 bit."""
    with open(sample_path, 'rb') as f:
        dos = f.read(0x40)
        if dos[:2] != b'MZ':
            raise ValueError("not a PE (no MZ header)")
        e_lfanew = struct.unpack('<I', dos[0x3c:0x40])[0]
        f.seek(e_lfanew)
        if f.read(4) != b'PE\x00\x00':
            raise ValueError("not a PE (no PE signature)")
        f.seek(e_lfanew + 0x18)
        magic = struct.unpack('<H', f.read(2))[0]
        if magic == 0x10b:
            return 32
        if magic == 0x20b:
            return 64
        raise ValueError(f"unknown OptionalHeader Magic {magic:#x}")


def verify_is_driver(sample_path):
    """Sanity-check the sample looks like a Windows kernel-mode driver.

    Returns (is_driver: bool, reason: str). A negative reason is
    pre-formatted for inclusion in user-facing output ("not a driver: …").

    Heuristics (any one of which is sufficient to flag as non-driver):
      1. Subsystem != NATIVE (=1). Drivers are IMAGE_SUBSYSTEM_NATIVE;
         user-mode PEs are GUI (2), CONSOLE (3), etc. WDM drivers
         occasionally also see Subsystem 1 + the WINDOWS_BOOT_APPLICATION
         (16) variant — we accept both.
      2. No imports of any canonical kernel-mode DLL. Drivers virtually
         always import from ntoskrnl.exe or hal.dll (or, for KMDF,
         WDFLDR.SYS). User-mode PEs import from kernel32 / user32 /
         msvcrt / api-ms-win-* / d3d* / advapi32 / etc.

    The check is a *sanity gate*, not a security control — a determined
    sample author could fake both signals. Its purpose is to short-
    circuit early on samples accidentally placed in a driver corpus
    (GUI EXEs, user-mode payloads, signed installer stubs) so the
    analyst sees a clear "not a driver" message rather than the
    Speakeasy bootstrap failing with an inscrutable AttributeError
    400 lines into the load path.
    """
    try:
        import pefile
        pe = pefile.PE(str(sample_path), fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
    except Exception as e:
        return False, f"PE parse failed: {e}"

    sub = pe.OPTIONAL_HEADER.Subsystem
    # IMAGE_SUBSYSTEM constants from the PE spec:
    #   1 = NATIVE (drivers + bootloaders)
    #  16 = WINDOWS_BOOT_APPLICATION (also covered as not-user)
    if sub not in (1, 16):
        sub_names = {2: 'WINDOWS_GUI', 3: 'WINDOWS_CUI',
                     9: 'WINDOWS_CE_GUI', 10: 'EFI_APPLICATION',
                     11: 'EFI_BOOT_SERVICE_DRIVER',
                     12: 'EFI_RUNTIME_DRIVER',
                     13: 'EFI_ROM', 14: 'XBOX', 16: 'BOOT_APP'}
        # EFI boot-service / runtime drivers (11/12) are technically
        # drivers but Speakeasy doesn't model their environment, so we
        # still refuse. Pure user-mode subsystems (2/3/9) are obvious.
        return False, (f"Subsystem={sub} ({sub_names.get(sub, '?')}); "
                       f"a kernel-mode driver should have Subsystem=1 "
                       f"(IMAGE_SUBSYSTEM_NATIVE)")

    # Subsystem 1 + EFI variants slip through. Confirm by import set.
    kernel_dlls = {'ntoskrnl.exe', 'hal.dll', 'wdfldr.sys', 'ndis.sys',
                   'fltmgr.sys', 'netio.sys', 'tdi.sys', 'fwpkclnt.sys',
                   'ksecdd.sys', 'classpnp.sys', 'storport.sys',
                   'tcpip.sys', 'nsiproxy.sys', 'wdmaud.sys',
                   'portcls.sys', 'usbd.sys', 'msrpc.sys'}
    user_dlls = {'kernel32.dll', 'user32.dll', 'msvcrt.dll', 'gdi32.dll',
                 'shell32.dll', 'advapi32.dll', 'ole32.dll', 'oleaut32.dll',
                 'wininet.dll', 'urlmon.dll'}
    seen_kernel = False
    seen_user = False
    try:
        for entry in (getattr(pe, 'DIRECTORY_ENTRY_IMPORT', None) or []):
            try:
                dll = entry.dll.decode('latin-1', errors='ignore').lower()
            except Exception:
                continue
            if dll in kernel_dlls or dll.endswith('.sys'):
                seen_kernel = True
            elif dll in user_dlls or dll.startswith('api-ms-win-crt-'):
                seen_user = True
    except Exception:
        pass

    if not seen_kernel and seen_user:
        return False, ("imports user-mode DLLs (kernel32 / user32 / "
                       "api-ms-win-crt-* / etc.) with no ntoskrnl / hal / "
                       "WDFLDR / NDIS / FLTMGR import — this is a user-"
                       "mode PE, not a kernel driver")

    return True, 'ok'


def _scan_driver_object_names(sample_path, max_results=8):
    r"""Scan the PE's readable sections for \Driver\<name> string literals
    (ASCII + UTF-16-LE) and return them. Used to auto-populate the
    fake-driver list so any rootkit that hooks via ObReferenceObjectByName
    on a hardcoded driver name gets a callable target without the user
    having to spot the literal in `strings` output first.

    Filters:
      - skip the sample's own driver name (would self-hook, pointless)
      - require [A-Za-z0-9_] in the name (rejects garbage)
      - cap at `max_results` to bound the worst-case (default 8;
        rootkits typically hook 1-3 names — beyond that the literals
        are more likely AV/system-driver references the sample only
        compares against, not hooks)
      - skip entirely if the sample doesn't import any of the kernel
        APIs that consume a `\Driver\<name>` string at lookup time
        (`ObReferenceObjectByName`, `IoGetDeviceObjectPointer`).
        Without one of those, the literal can't be used as a hook
        anchor and the auto-allocations are pure overhead.
    """
    import re
    # Gate on imports — return early if no consumer API is present.
    try:
        import pefile
        pe = pefile.PE(str(sample_path), fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        CONSUMERS = (b'ObReferenceObjectByName',
                     b'IoGetDeviceObjectPointer')
        has_consumer = False
        for entry in (getattr(pe, 'DIRECTORY_ENTRY_IMPORT', None) or []):
            for imp in entry.imports:
                if imp.name and any(c in imp.name for c in CONSUMERS):
                    has_consumer = True
                    break
            if has_consumer:
                break
        if not has_consumer:
            return []
    except Exception:
        # If the import scan fails, fall through to the literal scan.
        # Worst case we still allocate a few fake drivers that can't be
        # hooked — bounded by max_results.
        pass
    found = []
    seen = set()
    sample_stem = sample_path.stem.lower() if hasattr(sample_path, 'stem') \
        else ''
    # Pattern: \Driver\ then 1..32 chars of [A-Za-z0-9_]
    ascii_pat = re.compile(rb'\\Driver\\([A-Za-z0-9_]{1,32})')
    wide_pat = re.compile(
        rb'\\\x00D\x00r\x00i\x00v\x00e\x00r\x00\\\x00'
        rb'(?:[A-Za-z0-9_]\x00){1,32}')
    try:
        data = sample_path.read_bytes()
    except Exception:
        return []
    for m in ascii_pat.finditer(data):
        name = m.group(0).decode('latin-1')
        if name.lower().endswith('\\driver\\' + sample_stem):
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        found.append(name)
        if len(found) >= max_results:
            break
    for m in wide_pat.finditer(data):
        try:
            name = m.group(0).decode('utf-16-le')
        except Exception:
            continue
        if name.lower().endswith('\\driver\\' + sample_stem):
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        found.append(name)
        if len(found) >= max_results:
            break
    return found


def _detect_protector(sample_path):
    """Heuristic protector / packer identification.

    Returns either None (no signal) or
        {'name': 'VMProtect (variant)', 'evidence': '<one-liner>'}

    Detection strategy is intentionally cheap (one PE-section scan + one
    file substring search) — the goal is "tell the analyst up front,
    don't waste their time", not "deobfuscate the binary".
    """
    try:
        import pefile
        pe = pefile.PE(str(sample_path), fast_load=True)
    except Exception:
        return None
    # Read the raw file once so we can grep for compiler markers.
    try:
        raw = sample_path.read_bytes()
    except Exception:
        raw = b''

    # --- VMProtect heuristics ---
    # 1. SDK markers `VxDualModeBegin` / `VxDualModeEnd` (used by VMP's
    #    `VMProtectBeginUltra`, `VMProtectEnd`, etc.). These are SDK
    #    string literals left in .rdata.
    # 2. Section name starting with `.vmp` (commonly `.vmp0` / `.vmp1`).
    # 3. INIT section with VirtualSize > 0x100000 and entropy in the
    #    "compressed but not encrypted" range (5.5 - 7.2). Truly
    #    encrypted regions have entropy >7.5; uncompressed code has
    #    entropy ~5; VMP Ultra compression lands around 6.0-7.0.
    has_vmp_marker = (b'VxDualModeBegin' in raw or b'VxDualModeEnd' in raw
                      or b'VMProtect' in raw)
    vmp_section = None
    bulky_init = None
    for s in pe.sections:
        nm = s.Name.decode(errors='replace').strip('\x00').strip()
        if nm.lower().startswith('.vmp'):
            vmp_section = (nm, s.Misc_VirtualSize, s.get_entropy())
        if nm == 'INIT' and s.Misc_VirtualSize >= 0x100000:
            bulky_init = (nm, s.Misc_VirtualSize, s.get_entropy())
    if has_vmp_marker or vmp_section:
        bits = []
        if vmp_section:
            bits.append(f"{vmp_section[0]}={vmp_section[1]:#x}B "
                        f"entropy={vmp_section[2]:.2f}")
        if has_vmp_marker:
            bits.append("VxDualModeBegin/End marker")
        if bulky_init and not vmp_section:
            bits.append(f"INIT={bulky_init[1]:#x}B "
                        f"entropy={bulky_init[2]:.2f}")
        return {'name': 'VMProtect', 'evidence': '; '.join(bits)}
    if bulky_init:
        # No explicit VMP marker but a >1 MB INIT with mid-range entropy
        # is the canonical VMP Ultra fingerprint on driver-class samples
        # (the rest of the protector's bytecode + dispatcher lives there
        # alongside the unpack stub). Less confident — call it likely.
        ent = bulky_init[2]
        if 5.5 <= ent <= 7.3:
            return {
                'name': 'VMProtect (likely)',
                'evidence': f"INIT={bulky_init[1]:#x}B entropy={ent:.2f} "
                            f"(no explicit marker, but section "
                            f"layout matches Ultra-mode fingerprint)",
            }

    # --- Themida / WinLicense ---
    # Section name starting with `.themida` / `.boot` / `.winlice`, or
    # the `Engine_Variables` marker.
    for s in pe.sections:
        nm = s.Name.decode(errors='replace').strip('\x00').strip().lower()
        if nm.startswith('.themida') or nm.startswith('.winlice'):
            return {
                'name': 'Themida / WinLicense',
                'evidence': f"section {nm!r}={s.Misc_VirtualSize:#x}B "
                            f"entropy={s.get_entropy():.2f}",
            }
    if b'Engine_Variables' in raw or b'PolyCryptPE' in raw:
        return {
            'name': 'Themida / WinLicense (variant)',
            'evidence': 'Engine_Variables/PolyCryptPE marker',
        }

    # --- UPX ---
    # Section names UPX0 / UPX1 / UPX2.
    for s in pe.sections:
        nm = s.Name.decode(errors='replace').strip('\x00').strip()
        if nm in ('UPX0', 'UPX1', 'UPX2'):
            return {
                'name': 'UPX',
                'evidence': f"section {nm!r}={s.Misc_VirtualSize:#x}B",
            }

    # --- Generic "non-standard big high-entropy section" fallback ---
    # Catches custom protectors that don't ship under a known signature.
    # Real-world examples in this corpus: `.borat10` (4.4 MB, ent 7.16 —
    # used by an MRP cheat variant). Heuristic: any section whose name
    # ISN'T one of the standard PE / driver section names AND has
    # VirtualSize >= 1 MB AND entropy >= 6.0 is almost certainly a
    # packer / protector payload. Confidence is lower than the named-
    # protector detectors so we tag it "unknown".
    STD_SECTIONS = {
        '.text', '.rdata', '.data', '.bss', '.tls', '.idata', '.edata',
        '.pdata', '.rsrc', '.reloc', '.didat', '.gfids', '.xdata',
        # Driver-specific
        'INIT', 'PAGE', 'PAGECODE', 'PAGEKD', 'PAGEDATA', 'PAGECONST',
        'PAGER32', 'PAGERA', 'PAGERV', 'PAGEKB',
        # MSVC EH + DBG
        '.00cfg', '.guard', '.giats', '.gehcont',
        # Padding / writable misc
        '.detourd', '.detourc',
    }
    for s in pe.sections:
        nm = s.Name.decode(errors='replace').strip('\x00').strip()
        if (nm and nm not in STD_SECTIONS
                and s.Misc_VirtualSize >= 0x100000
                and s.get_entropy() >= 6.0):
            return {
                'name': 'unknown packer/protector',
                'evidence': (f"non-standard section {nm!r}="
                             f"{s.Misc_VirtualSize:#x}B "
                             f"entropy={s.get_entropy():.2f} "
                             f"— not a known signature but the section "
                             f"layout indicates a custom packer/"
                             f"virtualizer"),
            }
    return None


def _canonical_dll_name(name):
    """Strip path + extension, lowercase. `FLTMGR.SYS` -> `fltmgr`."""
    base = name.rsplit('\\', 1)[-1].rsplit('/', 1)[-1]
    for ext in ('.sys', '.exe', '.dll'):
        if base.lower().endswith(ext):
            base = base[:-len(ext)]
            break
    return base.lower()


def build_iat_map(sample_path):
    """Parse the PE import table and return {function_name_lower: dll_short}.

    The mapping reflects which DLL the driver *imports* each symbol from,
    so the trace can display `FLTMGR.FltRegisterFilter` instead of
    `ntoskrnl.FltRegisterFilter` just because we registered the apihook
    under the ntoskrnl class. Returns an empty dict on any parsing error.
    """
    try:
        import pefile  # noqa: WPS433 (late import keeps cold-start fast)
        pe = pefile.PE(str(sample_path), fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        out = {}
        for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []) or []:
            dll = _canonical_dll_name(entry.dll.decode(errors='replace'))
            for imp in entry.imports:
                if imp.name:
                    out[imp.name.decode(errors='replace').lower()] = dll
        return out
    except Exception:
        return {}


def _bootstrap_emu(args, sample, sample_sha, arch_bits, prof, log,
                   resolve_addr):
    """Configure shim, instantiate Speakeasy, load module, map decoys,
    apply profile-specific shim (chain targets, IAT trampolines, MDL
    alias mirror). Returns (emu, mod, ntos, hal, alias_map, alias_writes,
    on_alias_write, dbgprint_state) or raises on fatal failure."""
    # Fake-IO replay + registry data: both come from a single JSON
    # supplied via --fake-io-data, with `files` and `registry` sections.
    replay_data = {}
    registry_data = {}
    if args.fake_io_data:
        try:
            blob = json.loads(Path(args.fake_io_data).read_text())
        except Exception as e:
            log(f"# WARNING: failed to load --fake-io-data: {e}")
            blob = {}
        if not isinstance(blob, dict):
            log("# WARNING: --fake-io-data root must be an object")
            blob = {}
        # Migration helper: the legacy `--fake-reg` JSON was a flat
        # `{key_path: {value_name: {...}}}` shape with no wrapper. If we
        # see top-level keys that look like registry paths and there's
        # no `files`/`registry` section, the user probably has an old
        # file. Loud-warn instead of silently producing an empty replay.
        if (blob and 'files' not in blob and 'registry' not in blob
                and any(isinstance(k, str)
                        and k.lower().startswith(('\\registry\\', '\\??\\'))
                        for k in blob)):
            log("# WARNING: --fake-io-data appears to use the OLD flat "
                "shape (legacy --fake-reg / --fake-io-replay format). "
                "Wrap your map in a `registry` or `files` section. "
                "Example: {\"registry\": { ...your existing object... }}")
        files = blob.get('files') or {}
        if files:
            try:
                replay_data = {k: bytes.fromhex(v) for k, v in files.items()}
                log(f"# Fake-I/O replay: loaded {len(replay_data)} file mappings.")
            except Exception as e:
                log(f"# WARNING: --fake-io-data files section bad: {e}")
        reg = blob.get('registry') or {}
        if reg:
            # Validate the shape so silent typos (bare string instead
            # of {type,data_hex}, "data" misspelled, non-hex bytes, …)
            # produce a clear warning rather than a downstream emulator
            # crash or a silently-empty replay.
            for key_path, bag in list(reg.items()):
                if not isinstance(bag, dict):
                    log(f"# WARNING: --fake-io-data: registry key "
                        f"{key_path!r} value must be an object mapping "
                        f"value-names to "
                        f'{{"type": INT, "data_hex": HEX}}; '
                        f"got {type(bag).__name__}; dropping.")
                    reg[key_path] = {}
                    continue
                for vname, vdef in list(bag.items()):
                    if not isinstance(vdef, dict):
                        log(f"# WARNING: --fake-io-data: value "
                            f"{vname!r} under {key_path!r} must be a "
                            f'{{"type": INT, "data_hex": HEX}} object; '
                            f"got {type(vdef).__name__} {vdef!r}; dropping.")
                        bag.pop(vname, None)
                        continue
                    dh = vdef.get('data_hex')
                    if dh is None or not isinstance(dh, str):
                        log(f"# WARNING: --fake-io-data: value "
                            f"{vname!r} under {key_path!r} missing "
                            f"`data_hex` (got keys={sorted(vdef.keys())}); "
                            f"using empty bytes.")
                        continue
                    try:
                        bytes.fromhex(dh)
                    except ValueError as e:
                        log(f"# WARNING: --fake-io-data: value "
                            f"{vname!r} under {key_path!r} has invalid "
                            f"data_hex {dh!r:.60s} ({e}). "
                            f"`data_hex` must be a HEX STRING — use "
                            f"e.g. Python's `b'example.txt'.hex()` "
                            f"(= '6578616d706c652e747874'), not the "
                            f"literal text. Treating as empty.")
            registry_data = reg
            n_vals = sum(len(v) for v in registry_data.values())
            log(f"# Fake-registry: {len(registry_data)} keys, "
                f"{n_vals} values loaded.")
    if args.fake_io == 'replay' and not replay_data:
        log("# WARNING: --fake-io replay but --fake-io-data has no `files` section")

    # Canned TDI response payload — fed to both IRP-level TDI_RECEIVE and
    # ZwReadFile-on-\Device\Tcp/Udp. Loaded once into EMU_OPTS; both code
    # paths look it up lazily so the value propagates regardless of
    # install-vs-set ordering. See shim_tdi_faker.py + shim_fake_io.py.
    if args.fake_tdi_response:
        try:
            tdi_bytes = Path(args.fake_tdi_response).read_bytes()
            shim.EMU_OPTS['canned_tdi_response'] = tdi_bytes
            log(f"# Fake-TDI response: loaded {len(tdi_bytes)} bytes from "
                f"{args.fake_tdi_response}")
        except Exception as e:
            log(f"# WARNING: failed to load --fake-tdi-response: {e}")

    # CLI-form registry pre-seeding: --prime-reg KEY/VALUE=HEX[:TYPE]
    # Merges into the same dict; CLI entries override JSON file entries
    # for the same (key,value). `service` is shorthand for the driver's
    # own service key under HKLM\System\CurrentControlSet\Services\<sha>.
    service_key = (r"\Registry\Machine\System\CurrentControlSet\Services"
                   "\\" + sample_sha)
    for spec in (args.prime_reg or []):
        try:
            lhs, rhs = spec.split('=', 1)
            if ':' in rhs:
                hex_str, type_str = rhs.rsplit(':', 1)
                v_type = int(type_str.strip(), 0)
            else:
                hex_str, v_type = rhs, 4  # REG_DWORD default
            # Allow user to drop spaces / 0x prefix in the hex.
            hex_clean = hex_str.replace(' ', '').strip()
            if hex_clean.lower().startswith('0x'):
                hex_clean = hex_clean[2:]
            data_bytes = bytes.fromhex(hex_clean)
            # Split KEY/VALUE on the LAST '/' (handles full registry paths
            # which contain backslashes, not slashes).
            if '/' not in lhs:
                log(f"# WARNING: --prime-reg {spec!r} — expected KEY/VALUE=...")
                continue
            key_part, value_name = lhs.rsplit('/', 1)
            key_path = (service_key if key_part.strip().lower() == 'service'
                        else key_part.strip())
            registry_data.setdefault(key_path, {})[value_name.strip()] = {
                'type': v_type,
                'data_hex': data_bytes.hex(),
            }
            log(f"# prime-reg: {key_path}\\{value_name} "
                f"= {data_bytes.hex()} (type={v_type}, "
                f"{len(data_bytes)} bytes)")
        except Exception as e:
            log(f"# WARNING: --prime-reg {spec!r} parse failed: {e}")

    effective_fake_io = args.fake_io
    if (registry_data or args.prime_reg) and effective_fake_io == 'off':
        effective_fake_io = 'auto'
        log("# registry seed supplied; escalating --fake-io off → auto.")
    if replay_data and effective_fake_io == 'off':
        effective_fake_io = 'auto'
        log("# --fake-io-data files supplied; escalating --fake-io off → auto.")
    if args.dump_files and effective_fake_io == 'off':
        effective_fake_io = 'auto'
        log("# --dump-files supplied; escalating --fake-io off → auto.")
    shim._reset_fake_io_state(
        mode=effective_fake_io,
        replay_data=replay_data,
        registry_data=registry_data,
        dump_files_dir=args.dump_files,
        plausible_pe=args.fake_io_plausible_pe)
    dbgprint_state = shim.install_shim(None, arch_bits, log_func=log)

    import speakeasy  # late import
    from speakeasy.common import PERM_MEM_RWX

    emu = speakeasy.Speakeasy()
    mod = emu.load_module(str(sample))  # may raise — caller catches
    emu.emu.timeout = args.timeout
    # Speakeasy's default max_api_count is 10000 — easily exhausted by
    # drivers that walk all PIDs at boot (d14: 25k+ APIs before
    # callback registration finishes; truncated DriverEntry means
    # ktrace's discover_callbacks misses everything past the
    # truncation). Scale with --timeout so longer runs get
    # proportionally more budget.
    emu.emu.max_api_count = max(emu.emu.max_api_count,
                                100000 + args.timeout * 1000)

    # Watchdog: Speakeasy's unicorn timeout occasionally doesn't fire
    # (e.g. drivers with PsCreateSystemThread loops). Use SIGALRM to
    # force-stop the underlying engine — Speakeasy then exits its run
    # loop normally so ktrace can flush partial trace + write the meta.
    # Margin must leave room for post-processing within the batch's
    # outer wall cap (run_batch.sh: 2× emu_timeout). Keep this small.
    import signal as _signal
    import time as _time
    _wd_margin = max(5, args.timeout // 3)
    _wall_deadline = [_time.time() + args.timeout + _wd_margin]
    _wd_fired = [False]

    def _wd(signum, frame):
        _wd_fired[0] = True
        try:
            emu.emu.emu_eng.stop()
        except Exception:
            pass
        log(f"# watchdog: forced emu stop at "
            f"{args.timeout + _wd_margin}s wall budget "
            f"(deadline reached)")

    try:
        _signal.signal(_signal.SIGALRM, _wd)
        _signal.alarm(args.timeout + _wd_margin)
    except Exception:
        pass

    def _rearm_watchdog():
        """Re-arm SIGALRM around post-DriverEntry phases. After the
        initial one-shot alarm fires (or the run_module returned
        before it could), subsequent emu.call() sites — invoke_*
        family — would otherwise run unbounded. Each call site
        rearms with the remaining wall budget; if the deadline has
        passed we stop the engine immediately so the next call
        short-circuits."""
        try:
            remaining = int(_wall_deadline[0] - _time.time())
            if remaining <= 0:
                _wd_fired[0] = True
                try:
                    emu.emu.emu_eng.stop()
                except Exception:
                    pass
                _signal.alarm(0)
                return False
            _signal.alarm(remaining)
            return True
        except Exception:
            return True

    # Hard ceiling so we never overrun the outer batch wrapper
    # (run_batch.sh wraps each sample in `timeout 2*emu_timeout`). Used
    # by _extend_watchdog to clamp post-DriverEntry phase budgets.
    _wall_started = _time.time()
    _wall_hard_cap = args.timeout * 2

    def _extend_watchdog(extra_seconds):
        """Grant a fresh wall slice — used when a critical post-
        DriverEntry phase (typically the deferred SystemThread that
        unpacks payload or sets the flag a DriverEntry poll loop is
        waiting on) needs to run after the initial watchdog fired.
        Caps total wall time at args.timeout*2 so the outer batch
        timeout still wins. Returns True if any time was actually
        granted."""
        try:
            elapsed = _time.time() - _wall_started
            slack = _wall_hard_cap - elapsed
            if slack <= 0:
                return False
            grant = min(extra_seconds, int(slack) - 1)
            if grant <= 0:
                return False
            _wall_deadline[0] = _time.time() + grant
            _wd_fired[0] = False
            _signal.alarm(grant)
            return True
        except Exception:
            return False

    # Expose to invoke.py / other phases.
    shim._rearm_watchdog = _rearm_watchdog
    shim._watchdog_expired = lambda: _wd_fired[0]
    shim._extend_watchdog = _extend_watchdog

    # Allocate the "fake object" page that output-pointer stubs hand out
    # for non-NULL but safely-dereferenceable returns.
    try:
        emu.emu.mem_map(0x1000, base=0x6f6b0000,
                        tag='ktrace.fake_obj', perms=PERM_MEM_RWX)
        emu.mem_write(0x6f6b0000, b'\x00' * 0x1000)
        dbgprint_state['fake_obj_addr'] = 0x6f6b0000
    except Exception as e:
        log(f"# fake-object page allocation failed: {e}")

    ntos = next(m for m in emu.get_sys_modules()
                if m.name.lower() == 'ntoskrnl')
    hal = next(m for m in emu.get_sys_modules() if m.name.lower() == 'hal')
    emu.emu.map_decoy(ntos)
    emu.emu.map_decoy(hal)
    shim.map_kernel_data_pages(emu, arch_bits=arch_bits)

    # IAT-slot trampolines (must run before rewrite_stubs).
    if prof.get('slot_trampolines'):
        nt_base = ntos.get_base()
        nt_old_end = nt_base + ntos.get_image_size()
        grow_start = (nt_old_end + 0xFFF) & ~0xFFF
        grow_by = 0x2000
        try:
            emu.emu.mem_map(grow_by, base=grow_start,
                            tag='emu.module.ntoskrnl_grow',
                            perms=PERM_MEM_RWX)
            import types
            def _patched_size(self): return grow_start + grow_by - nt_base
            ntos.get_image_size = types.MethodType(_patched_size, ntos)
            nt_tramp = grow_start + 0x10
            hal_end = hal.get_base() + hal.get_image_size()
            hal_tramp = hal_end - 0x40
            nt_off, hal_off = 0, 0
            for slot, (trigger, dll) in prof['slot_trampolines'].items():
                if dll == 'nt':
                    ta = nt_tramp + nt_off; nt_off += 5
                else:
                    ta = hal_tramp + hal_off; hal_off += 5
                rel32 = (trigger - (ta + 5)) & 0xFFFFFFFF
                emu.mem_write(ta, b'\xE9' + struct.pack('<I', rel32))
                emu.mem_write(prof['slot_base'] + slot * 4,
                              struct.pack('<I', ta))
            log(f"# Profile: planted {len(prof['slot_trampolines'])} "
                f"IAT-slot trampolines.")
        except Exception as e:
            log(f"# IAT-slot trampolines failed: {e}")

    n_nt = shim.rewrite_stubs(emu, ntos, 'ntoskrnl', arch_bits)
    n_hal = shim.rewrite_stubs(emu, hal, 'hal', arch_bits)
    log(f"# Shim: rewrote {n_nt} ntoskrnl + {n_hal} HAL export stubs.")

    # Chain-target redirects (VMP-style decrypted constants).
    if prof.get('chain_targets'):
        pages = {}
        for tgt, (mn, an) in prof['chain_targets'].items():
            pages.setdefault(tgt & ~0xFFF, []).append((tgt, mn, an))
        planted = 0
        for pb, entries in pages.items():
            try:
                emu.emu.mem_map(0x1000, base=pb,
                                tag=f'ktrace.chain_{pb:08x}',
                                perms=PERM_MEM_RWX)
                emu.mem_write(pb, b'\xcc' * 0x1000)
            except Exception:
                continue
            for tgt, mn, an in entries:
                try:
                    trigger = emu.emu.get_proc(mn, an)
                    rel32 = (trigger - (tgt + 5)) & 0xFFFFFFFF
                    emu.mem_write(tgt, b'\xE9' + struct.pack('<I', rel32))
                    planted += 1
                except Exception:
                    pass
        log(f"# Profile: planted {planted}/{len(prof['chain_targets'])} "
            f"chain-target redirects.")

    # MDL alias mirror (profile-supplied; auto-detect happens later).
    alias_map = []
    alias_writes = [0]

    def on_alias_write(emu_, access, addr, size, value, ctx):
        alias_writes[0] += 1
        if value is None:
            return
        for alo, ahi, olo in alias_map:
            if alo <= addr < ahi:
                orig = olo + (addr - alo)
                try:
                    emu_.mem_write(orig, value.to_bytes(size, 'little'))
                except Exception:
                    pass
                return

    if prof.get('mdl_alias'):
        ma = prof['mdl_alias']
        alias_map.append((ma['alias_lo'], ma['alias_hi'], ma['orig_lo']))
        try:
            emu.add_mem_write_hook(on_alias_write,
                                   ma['alias_lo'], ma['alias_hi'])
            log(f"# Profile: MDL alias mirror "
                f"0x{ma['alias_lo']:08x}..0x{ma['alias_hi']:08x}"
                f" -> 0x{ma['orig_lo']:08x}")
        except Exception as e:
            log(f"# alias hook install failed: {e}")

    return (emu, mod, ntos, hal, alias_map, alias_writes, on_alias_write,
            dbgprint_state)


def _auto_install_mdl_mirror(emu, alias_map, on_alias_write, log):
    """Walk the API report and install alias mirrors for any
    MmMapLockedPagesSpecifyCache return value we missed."""
    mdl_table = {}
    for ent in emu.get_report().get('entry_points', []):
        for a in ent.get('apis', []):
            nm = a.get('api_name', '').split('.')[-1]
            if nm == 'IoAllocateMdl':
                argv = a.get('args', [])
                try:
                    mdl_table[decode.as_int(a.get('ret_val'))] = (
                        decode.as_int(argv[0]), decode.as_int(argv[1]))
                except Exception:
                    pass
            elif nm == 'MmMapLockedPagesSpecifyCache':
                mdl = decode.as_int(a.get('args', [None])[0])
                alias_va = decode.as_int(a.get('ret_val'))
                if mdl in mdl_table and alias_va:
                    orig, ln = mdl_table[mdl]
                    if orig and ln and not any(
                            alo == alias_va for alo, _, _ in alias_map):
                        alias_map.append((alias_va, alias_va + ln, orig))
                        try:
                            emu.add_mem_write_hook(
                                on_alias_write, alias_va, alias_va + ln)
                            log(f"# MDL alias auto-mirror "
                                f"0x{alias_va:x}..+0x{ln:x} -> 0x{orig:x}")
                        except Exception:
                            pass


def _find_driver_object(emu, sample, log):
    """Match Speakeasy's `drivers` list against the sample basename.
    Returns (drvobj_addr, driver_instance_or_None)."""
    drvobj = 0
    matched = None
    try:
        drivers = getattr(emu.emu, 'drivers', [])
        sample_stem = sample.stem or sample.name
        sample_name = sample.name
        builtins = {'volmgr', 'Disk', 'Tcpip', 'Ndis'}
        for d in drivers:
            if not d.name:
                continue
            tail = d.name.rsplit('\\', 1)[-1]
            if tail in builtins:
                continue
            if tail and (tail == sample_stem or tail == sample_name):
                drvobj = d.address
                matched = d
                break
        if not drvobj:
            for d in drivers:
                tail = (d.name or '').rsplit('\\', 1)[-1]
                if tail and tail not in builtins:
                    drvobj = d.address
                    matched = d
                    break
        log("# drivers list: " + ', '.join(
            f"{(d.name or '<unnamed>').rsplit(chr(92), 1)[-1]}"
            f"@0x{d.address:x}" for d in drivers))
    except Exception as e:
        log(f"# driver lookup error: {e}")
    return drvobj, matched


def _collect_driver_devices(driver_inst, devobj_fallback):
    """Return list of (devobj_addr, label) for every DEVICE_OBJECT the
    driver created. Falls back to the single DeviceObject pointer if
    Speakeasy's `devices` list isn't available."""
    seen = []
    if driver_inst is not None:
        try:
            for i, dev in enumerate(driver_inst.devices):
                addr = getattr(dev, 'address', 0)
                if not addr:
                    continue
                label = getattr(dev, 'name', '') or f"dev{i}"
                # Strip the synthetic prefix Speakeasy adds.
                if '.' in label:
                    label = label.rsplit('.', 1)[-1]
                seen.append((addr, label))
        except Exception:
            pass
    if not seen and devobj_fallback:
        seen.append((devobj_fallback, 'dev0'))
    # De-dup while preserving order.
    out, ad = [], set()
    for a, n in seen:
        if a in ad:
            continue
        ad.add(a)
        out.append((a, n))
    return out


def _do_mem_dump(emu, sample, sample_sha, arch_bits, dump_dir, log):
    """Write every meaningful memory region into `dump_dir` + manifest."""
    import hashlib as _hashlib
    import re as _re
    dump_dir = Path(dump_dir).resolve()
    dump_dir.mkdir(parents=True, exist_ok=True)
    log('')
    log(f"# Dumping memory regions to {dump_dir}/ ...")
    manifest = []
    sample_stem = sample.stem.lower()
    skipped_empty = skipped_noise = written = 0
    try:
        for tag, base, size, is_free, proc, data in emu.get_memory_dumps():
            if is_free or not data:
                skipped_empty += 1
                continue
            tag = tag or 'unknown'
            tag_low = tag.lower()
            if (tag_low.startswith('emu.') and
                    sample_stem not in tag_low and
                    not tag_low.startswith('emu.shellcode.') and
                    not tag_low.startswith('emu.object.') and
                    not tag_low.startswith('ktrace.')):
                skipped_noise += 1
                continue
            if data.count(b'\x00') == len(data):
                skipped_empty += 1
                continue
            sha = _hashlib.sha256(data).hexdigest()[:16]
            safe = _re.sub(r'[^A-Za-z0-9._-]', '_', tag)[:80]
            fname = f"{safe}_0x{base:x}_{size:x}.bin"
            (dump_dir / fname).write_bytes(bytes(data))
            manifest.append({'file': fname, 'tag': tag, 'base': base,
                             'size': size, 'sha256_16': sha})
            written += 1
        (dump_dir / 'manifest.json').write_text(json.dumps({
            'sample': str(sample), 'sha256': sample_sha,
            'arch_bits': arch_bits, 'regions': manifest,
        }, indent=2))
        log(f"#   wrote {written} regions "
            f"(skipped {skipped_empty} empty, {skipped_noise} emu-internal)")
        return {'dir': str(dump_dir), 'regions_written': written,
                'regions_skipped': skipped_empty + skipped_noise}
    except Exception as e:
        log(f"# memory dump failed: {e}")
        return {'error': str(e)}


def _write_failure_meta(meta_path, sample, sample_sha, arch_bits, prof_name,
                        error):
    meta_path.write_text(json.dumps({
        'sample': str(sample), 'sha256': sample_sha,
        'arch_bits': arch_bits, 'profile': prof_name,
        'error': error,
        'apis_total': 0, 'apis_by_name': {}, 'pool_tags': {},
        'phases_seen': [], 'errors': [error],
        'mf_indices': [], 'driver_object': 0,
        'dbgprint_hits': 0, 'alias_writes': 0,
    }, indent=2))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main(argv=None):
    args = parse_args(argv)
    sample = Path(args.sample).resolve()
    if not sample.is_file():
        sys.exit(f"error: sample not found: {sample}")

    # --ioctl-only is sugar for the "see only this IOCTL" bundle. Apply
    # the suppressions now so downstream code sees a coherent args set.
    # Profile fake-driver-irps are gated separately at their fire site.
    if args.ioctl_only is not None:
        args.ioctl = [args.ioctl_only]
        args.ioctl_fuzz = False
        args.more_irps = False
        args.invoke_callbacks = False
        args.no_reinit = True
        args.no_unload = True

    out_dir = Path(args.out).resolve() if args.out \
        else (Path.cwd() / 'ktrace_out')
    out_dir.mkdir(parents=True, exist_ok=True)
    base = sample.name
    log_path = out_dir / f"{base}.log"
    json_path = out_dir / f"{base}.jsonl"
    meta_path = out_dir / f"{base}.meta"

    LOG = open(log_path, 'w', encoding='utf-8')
    JSONL = open(json_path, 'w', encoding='utf-8')

    def log(msg=''):
        LOG.write(msg + '\n')
        LOG.flush()
        if not args.quiet:
            print(msg)

    sample_sha = profiles.sha256_of(sample)
    try:
        arch_bits = detect_arch_bits(sample)
    except Exception as e:
        log(f"error: {e}")
        LOG.close(); JSONL.close()
        meta_path.write_text(json.dumps(
            {'sample': str(sample), 'error': str(e)}))
        return 2

    # Sanity-check the sample looks like a kernel driver before letting
    # Speakeasy try to boot it. Speakeasy's failure path for user-mode
    # PEs is a deep `'DecoyModule' object has no attribute '__data__'`
    # AttributeError 400 lines into the load — useless feedback. We
    # detect early and bail with a clear message.
    is_driver, reason = verify_is_driver(sample)
    if not is_driver:
        log(f"error: sample does not look like a kernel-mode driver — "
            f"{reason}")
        log(f"#       (To run anyway, ktrace doesn't support a "
            f"--no-driver-check escape hatch yet; the failure would "
            f"originate in Speakeasy's user-mode PE bootstrap.)")
        LOG.close(); JSONL.close()
        meta_path.write_text(json.dumps({
            'sample': str(sample), 'sha256': sample_sha,
            'error': 'not a kernel driver',
            'reason': reason,
        }, indent=2))
        if not args.quiet:
            print(f"[!] {sample.name}: not a kernel driver — {reason}")
        return 3

    prof_name, prof = (None, {})
    if not args.no_profile:
        prof_name, prof = profiles.resolve(sample, args.profile)

    log("# ktrace")
    log(f"# sample:   {sample}")
    log(f"# size:     {sample.stat().st_size} bytes")
    log(f"# sha256:   {sample_sha}")
    log(f"# arch:     {'x64' if arch_bits == 64 else 'x86'}")
    log(f"# profile:  {prof_name or '(none)'}"
        + (f"  — {prof.get('description','')}" if prof_name else ''))
    log(f"# output:   {out_dir}")

    # Parse the IAT so log lines can show the *actual* import DLL
    # (e.g. `FLTMGR.FltRegisterFilter`) rather than whatever module
    # Speakeasy happened to register the apihook under.
    iat_map = build_iat_map(sample)
    if iat_map:
        dlls = sorted({d for d in iat_map.values()})
        log(f"# imports:  {len(iat_map)} symbols from {len(dlls)} DLLs: "
            + ', '.join(dlls))
    # Protector / packer heuristic. Catches the common cases (VMProtect,
    # Themida) at the section-name + entropy + marker layer; doesn't try
    # to deobfuscate anything. The goal is just to tell the analyst
    # up-front "the trace stops here because of <X>" so they aren't
    # left wondering. Output: a log line AND a `protector` field in
    # the .meta for downstream tools.
    protector_info = _detect_protector(sample)
    if protector_info:
        log(f"# protector: {protector_info['name']} "
            f"({protector_info['evidence']})")
        log(f"#            deep code paths reside in the protected "
            f"region; the API-level trace surfaces the outer skeleton "
            f"only. See HANDOFF.md \"Not started\" / VMP for the "
            f"post-unpack region detection plan.")
    log('')

    # Build the PC -> symbol resolver
    SYMBOLS = dict(prof.get('symbols', {}))
    if args.symbols:
        try:
            raw = json.loads(Path(args.symbols).read_text())
            SYMBOLS.update({int(k, 0): v for k, v in raw.items()})
        except Exception as e:
            log(f"# WARNING: failed to load --symbols: {e}")

    def resolve_addr(pc):
        return decode.resolve_pc(pc, SYMBOLS)

    # ---- Bootstrap emulator (load module, shim, decoys, etc.) ----
    try:
        (emu, mod, ntos, hal,
         alias_map, alias_writes, on_alias_write,
         dbgprint_state) = _bootstrap_emu(
            args, sample, sample_sha, arch_bits, prof, log, resolve_addr)
    except Exception as e:
        log(f"# Speakeasy bootstrap failed: {e}")
        LOG.close(); JSONL.close()
        _write_failure_meta(meta_path, sample, sample_sha, arch_bits,
                            prof_name, f"bootstrap: {e}")
        return 4

    # Pre-emulation section snapshots (for dump-section diff).
    sect_pre = {}
    for label, lo, hi in prof.get('dump_sections', []):
        try:
            sect_pre[label] = (lo, hi, bytes(emu.mem_read(lo, hi - lo)))
        except Exception:
            pass

    # ---- Tracer + summary ----
    summary = {
        'apis_total': 0, 'apis_by_name': {},
        'errors': [], 'pool_tags': {}, 'pool_tags_sizes': {},
        'phases_seen': set(),
    }
    tracer = events.Tracer(log, JSONL, summary, resolve_addr,
                           emu, arch_bits, iat_map=iat_map)
    decode.reset_handle_state()
    shim._reset_flt_state()
    shim.set_force_strstr_match(args.force_strstr_match)
    shim.set_fake_modules(args.fake_modules)
    shim.set_fake_processes(args.fake_processes)
    # Synthetic DRIVER_OBJECTs for ObReferenceObjectByName-based hooks.
    # Sample-specific hook targets come from the matched profile's
    # 'fake_drivers' list (e.g. PoisonX → \Driver\nsiproxy); --fake-driver
    # CLI args union with that. Setter must run BEFORE install_shim so
    # the name-aware ObRef override sees the list.
    from shim_fake_driver import set_fake_drivers
    _fake_drivers = list(args.fake_driver) + list(prof.get('fake_drivers') or [])
    if not args.no_auto_fake_driver:
        try:
            auto_found = _scan_driver_object_names(sample)
        except Exception as e:
            log(f"# auto-fake-driver scan failed: {e}")
            auto_found = []
        # Only add names that aren't already present (case-insensitive).
        existing_lower = {n.lower() for n in _fake_drivers}
        added = [n for n in auto_found
                 if n.lower() not in existing_lower]
        if added:
            log(f"# auto-fake-driver: found {len(added)} \\Driver\\* "
                f"literal(s) in the PE; pre-allocating synthetic "
                f"DRIVER_OBJECTs so any ObReferenceObjectByName hooks "
                f"have callable targets ({', '.join(added)})")
            _fake_drivers.extend(added)
    set_fake_drivers(_fake_drivers)
    decode.set_data_preview(args.data_preview)
    tracer.phaser.force('driver_init')

    # Pre-map a writable shadow page above Speakeasy's stack_base so
    # `mov [rsp+small_offset], rcx` spills at function entry don't
    # hit the unmapped reservation. See shim.map_stack_shadow.
    _ok = shim.map_stack_shadow(emu)
    log(f"# stack-shadow map: {'ok' if _ok else 'FAILED'} "
        f"(stack_base=0x{getattr(emu.emu,'stack_base',0):x})")

    # Pre-allocate any fake DRIVER_OBJECTs + register their code hooks
    # NOW, before any emu.call/run_module fires. Code hooks added mid-
    # run don't take effect on later runs in this Speakeasy build, so
    # lazy allocation from inside the ObRef override misses the stub
    # firing.
    if _fake_drivers:
        from shim_fake_driver import prealloc_fake_drivers
        prealloc_fake_drivers(emu, arch_bits, log_func=log)

    # ---- --trace-fn: install internal-function hooks ----
    # Must run BEFORE run_module for the same reason fake-driver hooks
    # do: unicorn code hooks added mid-emulation don't take effect on
    # subsequent runs in this Speakeasy build.
    if args.trace_fn:
        from shim_trace_fn import parse_trace_fn_arg, install_trace_fns
        try:
            _tf_specs = [parse_trace_fn_arg(raw) for raw in args.trace_fn]
        except Exception as e:
            log(f"# --trace-fn: bad spec ({e}); ignoring all")
            _tf_specs = []
        if _tf_specs:
            install_trace_fns(emu, arch_bits, _tf_specs, log, JSONL,
                              resolve_addr)

    # ---- Run DriverEntry ----
    t0 = time.time()
    try:
        emu.run_module(mod)
    except Exception as e:
        log(f"  [emulator] DriverEntry exception: {e}")
        summary['errors'].append(f"run_module: {e}")
    n0 = tracer.replay_new()

    drvobj_ptr, drv_inst = _find_driver_object(emu, sample, log)
    log('')
    log(f"# DriverEntry: {n0} API calls; "
        f"DbgPrint hits={dbgprint_state['hits']}; "
        f"alias writes={alias_writes[0]}; "
        f"DriverObject=0x{drvobj_ptr:016x}; "
        f"elapsed {time.time() - t0:.1f}s")

    _auto_install_mdl_mirror(emu, alias_map, on_alias_write, log)

    # ---- DriverObject + MajorFunction[] ----
    mf_table = {}
    devobj = 0
    fields = {}
    if drvobj_ptr:
        try:
            mf_table = irp.read_major_function_table(emu, drvobj_ptr, arch_bits)
            fields = irp.read_driverobject_fields(emu, drvobj_ptr, arch_bits)
            devobj = fields.get('DeviceObject', 0)
            log('')
            log("# MajorFunction[] table:")
            for i, ptr in mf_table.items():
                name = (decode.IRP_MJ[i] if i < len(decode.IRP_MJ)
                        else f"IRP_MJ_{i}")
                log(f"  {name:<37s} -> 0x{ptr:016x}  ({resolve_addr(ptr)})")
            log("# DriverObject pointers:")
            for k in ('DriverStart', 'DriverInit', 'DriverStartIo',
                      'DriverUnload', 'DriverExtension'):
                v = fields.get(k, 0)
                if v:
                    log(f"  {k:<20s} -> 0x{v:016x}  ({resolve_addr(v)})")
        except Exception as e:
            log(f"# DriverObject read failed: {e}")

    # ---- Post-DriverEntry invocation: reinit + callbacks + IRPs ----
    # First prime any driver-internal "ready / active" state flags the
    # user supplied via --prime-flag. These are typically single-byte
    # flags set by some runtime path (user-mode IOCTL, WFP worker, etc.)
    # that gate callback bodies. Identifying their addresses is a
    # Ghidra-side task; ktrace just performs the write.
    if args.prime_flag:
        log('')
        for spec in args.prime_flag:
            try:
                lhs, rhs = spec.split('=', 1)
                addr = int(lhs.strip(), 0)
                if ':' in rhs:
                    val_str, size_str = rhs.split(':', 1)
                    size = int(size_str.strip(), 0)
                else:
                    val_str, size = rhs, 1
                val = int(val_str.strip(), 0)
                if size not in (1, 2, 4, 8):
                    log(f"# prime-flag: bad size {size} in {spec!r} "
                        f"(want 1/2/4/8)")
                    continue
                blob = (val & ((1 << (size * 8)) - 1)).to_bytes(
                    size, 'little')
                emu.emu.mem_write(addr, blob)
                log(f"# prime-flag: wrote {val:#x} ({size}B) -> {addr:#x}")
            except Exception as e:
                log(f"# prime-flag: failed for {spec!r}: {e}")
        log('')

    if args.invoke_callbacks and not args.no_reinit:
        invoke.invoke_reinit(emu, tracer, drvobj_ptr, log, resolve_addr)
    if args.invoke_callbacks:
        invoke.invoke_callbacks(emu, tracer, drvobj_ptr, arch_bits,
                                log, resolve_addr)

    # Auto-IOCTL discovery.
    dispatcher_devctl = mf_table.get(0x0E)
    discovered_ioctls = []
    if dispatcher_devctl and not args.ioctl \
            and not prof.get('default_ioctls'):
        discovered_ioctls = discover.discover_ioctls(
            emu, dispatcher_devctl, arch_bits)
        if discovered_ioctls:
            log('')
            log("# Auto-discovered IOCTL candidates in dispatcher: "
                + ', '.join(f"0x{c:08X}" for c in discovered_ioctls[:16])
                + (f" (+{len(discovered_ioctls)-16} more)"
                   if len(discovered_ioctls) > 16 else ''))
    ioctls = (args.ioctl
              or prof.get('default_ioctls', [])
              or discovered_ioctls[:8])
    ioctl_input = bytes.fromhex(args.ioctl_input) if args.ioctl_input else b''
    # Fall back to a profile-supplied default if --ioctl-input wasn't passed.
    if not ioctl_input and prof.get('default_ioctl_input'):
        ioctl_input = prof['default_ioctl_input']

    # Iterate every DEVICE_OBJECT the driver registered, not just the
    # one DriverObject.DeviceObject points at. Universal-dispatcher
    # drivers (filter / NDIS / TDI / FS minifilters) route the same
    # MajorFunction[] entry into per-device handlers; firing the IRP
    # suite at each device exposes those branches.
    dev_targets = _collect_driver_devices(drv_inst, devobj)
    if not args.no_irp:
        log('')
        log(f"# Synth IRPs against {len(dev_targets)} device object(s)")
    for devobj_addr, dev_label in dev_targets:
        invoke.synth_irp_sequence(
            emu, tracer, JSONL, log, resolve_addr, arch_bits,
            mf_table, devobj_addr, ioctls, ioctl_input,
            ioctl_fuzz=args.ioctl_fuzz, more_irps=args.more_irps,
            no_irp=args.no_irp, device_label=dev_label)

    # ---- Fake-driver hook-fire phase ----
    # Fire IRPs through fake DRIVER_OBJECTs' MajorFunction[+0xE0]
    # (whatever address the sample wrote there during the IOCTL phase)
    # and invoke the captured completion routine so the full hook chain
    # gets traced. Specs come from two sources:
    #   1. --fake-driver-irp CLI args (raw `NAME:IOCTL=…,OUT=…,IN=hex`)
    #   2. Profile's `fake_driver_irps`, which can reference a named
    #      INPUT_BUILDER in profiles.py for sample-specific buffer
    #      shapes (e.g. PoisonX's NSI TCP connection key array).
    parsed = []
    if args.fake_driver_irp:
        from shim_fake_driver import parse_irp_spec
        for raw in args.fake_driver_irp:
            try:
                parsed.append(parse_irp_spec(raw))
            except Exception as e:
                log(f"# --fake-driver-irp: bad spec {raw!r}: {e}")
    # Profile-supplied IRPs use a builder function to populate the
    # input buffer + any out-of-band dump regions.
    profile_irps = [] if args.ioctl_only is not None \
        else (prof.get('fake_driver_irps') or [])
    for pirp in profile_irps:
        builder_name = pirp.get('input_builder')
        builder = profiles.INPUT_BUILDERS.get(builder_name)
        if not builder:
            log(f"# profile fake-driver-irp: unknown input_builder "
                f"{builder_name!r}; skipping")
            continue
        try:
            input_bytes, extra_dumps = builder(
                emu, arch_bits, pirp.get('input_args') or {})
        except Exception as e:
            log(f"# profile fake-driver-irp builder {builder_name!r} "
                f"raised: {e}")
            continue
        parsed.append({
            'name': pirp['name'].lower(),
            'ioctl': pirp['ioctl'],
            'outlen': pirp['outlen'],
            'input': input_bytes,
            'extra_dumps': extra_dumps,
        })
    if parsed:
        from shim_fake_driver import (
            fire_fake_driver_irps, FAKE_DRV_STATE,
        )
        log('')
        log("# === Fake-driver hook-fire phase ===")
        if not FAKE_DRV_STATE:
            log("# (no fake DRIVER_OBJECTs were ever referenced — the "
                "sample never called ObReferenceObjectByName on any "
                f"name in fake-driver list: {_fake_drivers})")
        fire_fake_driver_irps(
            emu, tracer, log, resolve_addr,
            arch_bits, parsed, decode)

    # DriverUnload: surfaces cleanup APIs not reachable elsewhere
    # (IoDeleteSymbolicLink, IoDetachDevice, KeCancelTimer, etc.).
    # Synthetically invoke minifilter pre-operation callbacks.
    if args.invoke_callbacks:
        invoke.invoke_flt_callbacks(emu, tracer, arch_bits, log, resolve_addr)

    if args.invoke_callbacks and not args.no_unload:
        unload_fn = fields.get('DriverUnload', 0)
        invoke.invoke_unload(emu, tracer, drvobj_ptr, unload_fn,
                             log, resolve_addr)

    # ---- Section dumps (profile-driven, e.g. r2's .DRIVER0) ----
    for label, lo, hi in prof.get('dump_sections', []):
        try:
            post = bytes(emu.mem_read(lo, hi - lo))
            dump_path = out_dir / f"{base}.{label}.bin"
            dump_path.write_bytes(post)
            if label in sect_pre:
                _, _, pre = sect_pre[label]
                diff = sum(1 for a, b in zip(pre, post) if a != b)
                log(f"# {label}: {diff} changed bytes; saved {dump_path}")
        except Exception as e:
            log(f"# {label} dump failed: {e}")

    # ---- Pool tag + API frequency summary ----
    log('')
    log('# === Pool-tag summary ===')
    for tag, n in sorted(summary['pool_tags'].items(), key=lambda kv: -kv[1]):
        log(f"  tag={tag!r:<10s}  count={n:<3d}  "
            f"total_bytes=0x{summary['pool_tags_sizes'].get(tag, 0):x}")
    log('')
    log('# === API name frequency ===')
    for name, n in sorted(summary['apis_by_name'].items(),
                          key=lambda kv: (-kv[1], kv[0]))[:30]:
        log(f"  {n:<4d} {name}")

    # ---- Fake-I/O learn dump ----
    fake_io_info = {}
    if args.fake_io in ('learn', 'auto', 'replay'):
        fio_log = shim.FAKE_IO.get('log') or {}
        counts = {k: len(v) for k, v in fio_log.items()}
        log('')
        log(f"# Fake-I/O ({args.fake_io}): "
            + ', '.join(f"{k}={v}" for k, v in counts.items() if v))
        if args.fake_io == 'learn' and any(counts.values()):
            discovered_path = out_dir / f"{base}.discovered_io.json"
            discovered_path.write_text(json.dumps(fio_log, indent=2))
            log(f"#   -> {discovered_path}")
            fake_io_info = {'log_path': str(discovered_path),
                            'counts': counts}
        elif counts:
            fake_io_info = {'counts': counts}

    # ---- Flush dumped files (--dump-files DIR) ----
    dumped_files = []
    if args.dump_files:
        log('')
        log(f"# --dump-files: flushing captured ZwWriteFile payloads "
            f"-> {args.dump_files}")
        dumped_files = shim._flush_dumped_files(log_func=log)
        if not dumped_files:
            log("#   (no writes captured)")

    log('')
    log(f"# Total APIs traced: {summary['apis_total']}")
    log(f"# Phases reached:    {sorted(summary['phases_seen'])}")

    # ---- Optional memory dump ----
    mem_dump_info = {}
    if args.dump_mem:
        mem_dump_info = _do_mem_dump(emu, sample, sample_sha, arch_bits,
                                     args.dump_mem, log)

    LOG.close()
    JSONL.close()

    # ---- Inject a 5-line "Run summary" TOC at the top of the log so a
    # reader can tell at a glance what the run produced before having
    # to scroll. We do this AFTER closing the log because the counts
    # only exist at this point — read the file back, splice the TOC in
    # right after the existing header, write back.
    try:
        nm = summary['apis_by_name']
        callbacks_seen = []
        for cb_api in ('FltRegisterFilter', 'ObRegisterCallbacks',
                       'PsSetCreateProcessNotifyRoutine',
                       'PsSetCreateProcessNotifyRoutineEx',
                       'PsSetCreateThreadNotifyRoutine',
                       'PsSetLoadImageNotifyRoutine',
                       'CmRegisterCallback', 'CmRegisterCallbackEx',
                       'IoRegisterDriverReinitialization',
                       'IoRegisterBootDriverReinitialization',
                       'PsCreateSystemThread'):
            n_cb = nm.get(cb_api, 0)
            if n_cb:
                callbacks_seen.append(f"{n_cb}×{cb_api}")
        toc_lines = []
        toc_lines.append("# === Run summary ===")
        phases = sorted(summary['phases_seen'])
        toc_lines.append(f"# phases:    {' → '.join(phases) if phases else '(none reached)'}")
        toc_lines.append(f"# APIs:      {summary['apis_total']} traced  "
                         f"({len(nm)} distinct)")
        if callbacks_seen:
            toc_lines.append(f"# callbacks: {', '.join(callbacks_seen)}")
        n_devs = nm.get('IoCreateDevice', 0) + nm.get('IoCreateDeviceSecure', 0)
        n_syms = nm.get('IoCreateSymbolicLink', 0)
        if n_devs or n_syms:
            toc_lines.append(f"# devices:   {n_devs} IoCreateDevice, "
                             f"{n_syms} IoCreateSymbolicLink")
        if dumped_files:
            df_parts = [f"{d['size']}B → {d['dumped_to'].split('/')[-1]}"
                        for d in dumped_files]
            toc_lines.append(f"# dropped:   {', '.join(df_parts)}")
        if summary['errors']:
            toc_lines.append(f"# errors:    {len(summary['errors'])} "
                             f"(first: {summary['errors'][0][:80]})")
        else:
            toc_lines.append(f"# errors:    0")
        toc_block = '\n'.join(toc_lines) + '\n\n'

        with open(log_path, 'r', encoding='utf-8') as _f:
            body = _f.read()
        # Splice right before the blank line that follows the existing
        # `# imports:` header (the gap between header and `# Shim:`).
        anchor = '\n\n# Shim:'
        idx = body.find(anchor)
        if idx == -1:
            # Fallback: drop at the very top after the `# output:` line.
            anchor = '\n# output:'
            idx2 = body.find(anchor)
            if idx2 != -1:
                eol = body.find('\n', idx2 + len(anchor))
                if eol != -1:
                    body = body[:eol + 1] + '\n' + toc_block + body[eol + 1:]
        else:
            body = body[:idx + 1] + '\n' + toc_block + body[idx + 1:]
        with open(log_path, 'w', encoding='utf-8') as _f:
            _f.write(body)
    except Exception as _e:
        pass

    meta_path.write_text(json.dumps({
        'sample': str(sample), 'sha256': sample_sha,
        'arch_bits': arch_bits, 'profile': prof_name,
        'protector': protector_info,   # null if no protector detected
        'apis_total': summary['apis_total'],
        'apis_by_name': summary['apis_by_name'],
        'pool_tags': summary['pool_tags'],
        'phases_seen': sorted(summary['phases_seen']),
        'errors': summary['errors'],
        'mf_indices': sorted(mf_table.keys()),
        'driver_object': drvobj_ptr,
        'dbgprint_hits': dbgprint_state['hits'],
        'alias_writes': alias_writes[0],
        'mem_dump': mem_dump_info,
        'fake_io': fake_io_info,
        'dumped_files': dumped_files,
    }, indent=2))

    # ---- Optional Ghidra Java-script export -------------------------
    # (Runs AFTER log/JSONL close. Errors are printed, not logged.)
    if args.ghidra_export:
        try:
            from tools.ghidra_export import collect_annotations, emit
            try:
                cbs = invoke.discover_callbacks(emu, arch_bits)
            except Exception:
                cbs = []
            image_base = mod.get_base() if hasattr(mod, 'get_base') \
                else (0x140000000 if arch_bits == 64 else 0x10000)
            log_text = log_path.read_text(encoding='utf-8', errors='replace') \
                if log_path.exists() else ''
            comments, labels = collect_annotations(
                emu=emu, trace_log_text=log_text, mf_table=mf_table,
                drv_fields=fields, callbacks=cbs,
                image_base=image_base, sha256=sample_sha,
                jsonl_path=json_path if json_path.exists() else None)
            export_path = Path(args.ghidra_export)
            if export_path.suffix.lower() != '.java':
                export_path = export_path.with_suffix('.java')
            written = emit(export_path, comments, labels, sample_sha)
            if not args.quiet:
                print(f"[+] {written}  ({len(comments)} comments + "
                      f"{len(labels)} labels)")
        except Exception as e:
            if not args.quiet:
                import traceback as _tb
                print(f"[!] --ghidra-export failed: {e}")
                print(_tb.format_exc())

    if not args.quiet:
        print(f"[+] {log_path}")
        print(f"[+] {json_path}")
        print(f"[+] {meta_path}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
