"""Fake-IO state + hook installation. FAKE_IO is the per-run dict that
ktrace.py mutates before each driver run; _install_fake_io_hooks attaches
custom file/registry apihooks to Speakeasy's Ntoskrnl class so they fire
instead of the defaults. Imported by shim.py."""
from speakeasy.winenv.api import api as api_module
from speakeasy.winenv.api.kernelmode import ntoskrnl as ntos_mod
apihook = api_module.ApiHandler.apihook

FAKE_IO = {
    'mode': 'off',
    'replay_data': {},
    'registry_data': {},   # #1: {key_path: {value_name: {'type': INT, 'data_hex': '..'}}}
    'log': None,
    'handle_to_path': {},
    'next_handle': 0x80000000,
}


def _reset_fake_io_state(mode='off', replay_data=None, registry_data=None,
                         dump_files_dir=None, plausible_pe=False):
    """Called by ktrace.py before each driver run."""
    FAKE_IO['mode'] = mode
    FAKE_IO['replay_data'] = replay_data or {}
    FAKE_IO['registry_data'] = registry_data or {}
    FAKE_IO['plausible_pe'] = plausible_pe
    FAKE_IO['handle_to_path'] = {}
    FAKE_IO['next_handle'] = 0x80000000
    FAKE_IO['log'] = {
        'files_opened':  [],
        'files_read':    [],
        'files_written': [],
        'files_closed':  [],
        'keys_opened':   [],
        'values_queried': [],
        'values_set':    [],
    }
    # --dump-files target dir + per-path content accumulator. Keyed on
    # the file path string, not the handle, so multiple open/write/close
    # cycles to the same file concatenate (matches d3 / d11 's per-event
    # FileProtect.log appends).
    FAKE_IO['dump_files_dir'] = dump_files_dir
    FAKE_IO['file_writes'] = {}    # {path: bytearray}

def _build_plausible_pe64(want_size):
    """Return up to `want_size` bytes of a minimal valid PE64 image.

    Skeleton layout:
      0x00..0x40   IMAGE_DOS_HEADER  (e_magic='MZ', e_lfanew=0x80)
      0x40..0x80   stub (zeroed, doesn't run)
      0x80..0x84   PE\\0\\0 signature
      0x84..0x98   IMAGE_FILE_HEADER (Machine=AMD64, 1 section, …)
      0x98..0x188  IMAGE_OPTIONAL_HEADER64 (Magic=PE32+, AddressOfEntryPoint
                   non-zero, SizeOfImage=0x1000, Subsystem=NATIVE_DRIVER)
      0x188..0x1B0 one IMAGE_SECTION_HEADER ('.text')
      0x1B0..…     zero-filled padding

    Sized so the smallest read that lands a meaningful structure
    (the 0x40-byte DOS header) sees the MZ magic. Reads >= 0x1B0
    see a fully-formed PE64 header + one section.

    NOT executable — there's no real code at AddressOfEntryPoint,
    just zeroed pages. Drivers that only validate the PE structure
    (DOS sig check, PE+ magic, SizeOfImage > 0, bit-64 flag) will
    proceed past their gate; drivers that actually try to map +
    execute the file will get further but eventually crash on the
    zeroed code — which is still strictly more interesting than
    "bailed at MZ check".
    """
    import struct as _s
    blob = bytearray(0x1B0)
    # IMAGE_DOS_HEADER
    blob[0:2] = b'MZ'
    _s.pack_into('<I', blob, 0x3C, 0x80)         # e_lfanew
    # NT signature
    blob[0x80:0x84] = b'PE\x00\x00'
    # IMAGE_FILE_HEADER (20 bytes starting at 0x84)
    _s.pack_into('<H', blob, 0x84, 0x8664)        # Machine = AMD64
    _s.pack_into('<H', blob, 0x86, 1)             # NumberOfSections
    _s.pack_into('<I', blob, 0x88, 0)             # TimeDateStamp
    _s.pack_into('<I', blob, 0x8C, 0)             # PointerToSymbolTable
    _s.pack_into('<I', blob, 0x90, 0)             # NumberOfSymbols
    _s.pack_into('<H', blob, 0x94, 0xF0)          # SizeOfOptionalHeader
    _s.pack_into('<H', blob, 0x96,
                 0x2022)                          # Characteristics:
                                                  #   EXECUTABLE | LARGE_ADDRESS | DLL
    # IMAGE_OPTIONAL_HEADER64 (240 = 0xF0 bytes starting at 0x98)
    _s.pack_into('<H', blob, 0x98, 0x20B)         # Magic = PE32+
    _s.pack_into('<B', blob, 0x9A, 14)            # MajorLinkerVersion
    _s.pack_into('<B', blob, 0x9B, 0)             # MinorLinkerVersion
    _s.pack_into('<I', blob, 0x9C, 0x200)         # SizeOfCode
    _s.pack_into('<I', blob, 0xA0, 0)             # SizeOfInitializedData
    _s.pack_into('<I', blob, 0xA4, 0)             # SizeOfUninitializedData
    _s.pack_into('<I', blob, 0xA8, 0x1000)        # AddressOfEntryPoint
    _s.pack_into('<I', blob, 0xAC, 0x1000)        # BaseOfCode
    _s.pack_into('<Q', blob, 0xB0, 0x140000000)   # ImageBase
    _s.pack_into('<I', blob, 0xB8, 0x1000)        # SectionAlignment
    _s.pack_into('<I', blob, 0xBC, 0x200)         # FileAlignment
    _s.pack_into('<H', blob, 0xC0, 10)            # MajorOperatingSystemVersion
    _s.pack_into('<I', blob, 0xD0, 0x2000)        # SizeOfImage
    _s.pack_into('<I', blob, 0xD4, 0x200)         # SizeOfHeaders
    _s.pack_into('<H', blob, 0xDC, 1)             # Subsystem = NATIVE
    _s.pack_into('<H', blob, 0xDE, 0)             # DllCharacteristics
    _s.pack_into('<Q', blob, 0xE0, 0x100000)      # SizeOfStackReserve
    _s.pack_into('<Q', blob, 0xE8, 0x1000)        # SizeOfStackCommit
    _s.pack_into('<Q', blob, 0xF0, 0x100000)      # SizeOfHeapReserve
    _s.pack_into('<Q', blob, 0xF8, 0x1000)        # SizeOfHeapCommit
    _s.pack_into('<I', blob, 0x104, 0x10)         # NumberOfRvaAndSizes
    # IMAGE_SECTION_HEADER (40 bytes starting at 0x188)
    blob[0x188:0x190] = b'.text\x00\x00\x00'
    _s.pack_into('<I', blob, 0x190, 0x200)        # VirtualSize
    _s.pack_into('<I', blob, 0x194, 0x1000)       # VirtualAddress
    _s.pack_into('<I', blob, 0x198, 0x200)        # SizeOfRawData
    _s.pack_into('<I', blob, 0x19C, 0x200)        # PointerToRawData
    _s.pack_into('<I', blob, 0x1AC, 0x60000020)   # Characteristics: CODE|EXEC|READ

    if want_size <= len(blob):
        return bytes(blob[:want_size])
    return bytes(blob) + b'\x00' * (want_size - len(blob))


def _flush_dumped_files(log_func=None):
    """If --dump-files was enabled, write every captured file content
    to the target directory. Returns a manifest list of (path, size,
    out_path) suitable for the meta file."""
    out_dir = FAKE_IO.get('dump_files_dir')
    writes = FAKE_IO.get('file_writes') or {}
    if not out_dir or not writes:
        return []
    import os
    import re
    os.makedirs(out_dir, exist_ok=True)
    manifest = []
    for src_path, content in writes.items():
        # Sanitise the kernel path to a flat filename.
        # `\??\C:\FileProtect.log` -> `C__FileProtect.log`
        flat = src_path
        for prefix in ('\\??\\', '\\\\?\\', '\\DosDevices\\'):
            if flat.startswith(prefix):
                flat = flat[len(prefix):]
                break
        flat = re.sub(r'[\\/:*?"<>|]', '_', flat).strip('_') or 'unnamed'
        flat = flat[:200]
        # Avoid collisions when sanitised names overlap.
        out_path = os.path.join(out_dir, flat)
        suffix_idx = 0
        while os.path.exists(out_path):
            suffix_idx += 1
            out_path = os.path.join(out_dir, f"{flat}.{suffix_idx}")
        try:
            with open(out_path, 'wb') as f:
                f.write(bytes(content))
            manifest.append({
                'path': src_path, 'size': len(content),
                'dumped_to': out_path,
            })
            if log_func:
                log_func(f"#   dumped {len(content)} bytes "
                         f"from {src_path!r} -> {out_path}")
        except Exception as e:
            if log_func:
                log_func(f"#   WARNING: failed to dump {src_path!r}: {e}")
    return manifest


def _patch_pefile_decoymodule():
    """#5 (attempt): wrap DecoyModule.full_load with a try/except so the
    `OPTIONAL_HEADER missing` AttributeError doesn't kill map_decoy.
    A bare no-op breaks downstream get_memory_mapped_image() which
    actually needs full parse state, so we keep the original call and
    just swallow the exception. The downstream code still partly works
    on the basepe so we get a usable decoy for ~most cases."""
    try:
        from speakeasy.windows.common import DecoyModule
        _orig = DecoyModule.full_load
        def _safe_full_load(self):
            try:
                _orig(self)
            except AttributeError:
                pass
        DecoyModule.full_load = _safe_full_load
    except Exception:
        pass


def _install_fake_io_hooks(arch_bits, conv):
    """Install custom file + registry apihooks that override Speakeasy's
    defaults. Behaviour:

      * Open / Create file or key  -> STATUS_SUCCESS + fake handle
      * ReadFile                   -> STATUS_SUCCESS + zero-fill buffer
                                      (or replay_data[path] when mode=='replay')
      * WriteFile                  -> STATUS_SUCCESS + capture first 64 bytes
      * Close                      -> STATUS_SUCCESS
      * QueryValueKey              -> STATUS_OBJECT_NAME_NOT_FOUND
                                      (driver falls back to its defaults)

    All overrides record into FAKE_IO['log'] for the learn-mode dump.
    """
    import struct as _s
    state = FAKE_IO  # closure

    def _next_handle():
        state['next_handle'] += 1
        return state['next_handle']

    def _write_handle(emu, addr, handle):
        if not addr:
            return
        try:
            if arch_bits == 64:
                emu.mem_write(addr, _s.pack('<Q', handle))
            else:
                emu.mem_write(addr, _s.pack('<I', handle))
        except Exception:
            pass

    def _write_iosb(emu, addr, status, info):
        """Write IO_STATUS_BLOCK { NTSTATUS Status; ULONG_PTR Information; }.
        x86 layout: 4 + 4 = 8 bytes; x64: 4 + 4 pad + 8 = 16 bytes."""
        if not addr:
            return
        try:
            emu.mem_write(addr, _s.pack('<I', status & 0xFFFFFFFF))
            if arch_bits == 64:
                emu.mem_write(addr + 8, _s.pack('<Q', info & 0xFFFFFFFFFFFFFFFF))
            else:
                emu.mem_write(addr + 4, _s.pack('<I', info & 0xFFFFFFFF))
        except Exception:
            pass

    def _resolve_path(emu, attrs_addr):
        """Read OBJECT_ATTRIBUTES.ObjectName from emulator memory."""
        if not attrs_addr:
            return None
        try:
            # Inline the OBJECT_ATTRIBUTES.ObjectName lookup so we don't
            # have a cross-module circular import on decode.py.
            if arch_bits == 64:
                ptr_bytes = bytes(emu.mem_read(attrs_addr + 0x10, 8))
                name_ptr = _s.unpack('<Q', ptr_bytes)[0]
                ustr = bytes(emu.mem_read(name_ptr, 16))
                length = _s.unpack('<H', ustr[0:2])[0]
                buf = _s.unpack('<Q', ustr[8:16])[0]
            else:
                ptr_bytes = bytes(emu.mem_read(attrs_addr + 0x08, 4))
                name_ptr = _s.unpack('<I', ptr_bytes)[0]
                ustr = bytes(emu.mem_read(name_ptr, 8))
                length = _s.unpack('<H', ustr[0:2])[0]
                buf = _s.unpack('<I', ustr[4:8])[0]
            if not buf or length == 0 or length > 0x400:
                return None
            raw = bytes(emu.mem_read(buf, length))
            return raw.decode('utf-16-le', errors='replace').rstrip('\x00')
        except Exception:
            return None

    def _resolve_unicode_string(emu, addr):
        if not addr:
            return None
        try:
            if arch_bits == 64:
                hdr = bytes(emu.mem_read(addr, 16))
                length = _s.unpack('<H', hdr[0:2])[0]
                buf = _s.unpack('<Q', hdr[8:16])[0]
            else:
                hdr = bytes(emu.mem_read(addr, 8))
                length = _s.unpack('<H', hdr[0:2])[0]
                buf = _s.unpack('<I', hdr[4:8])[0]
            if not buf or length == 0 or length > 0x400:
                return None
            return bytes(emu.mem_read(buf, length)).decode('utf-16-le',
                                                           errors='replace').rstrip('\x00')
        except Exception:
            return None

    def _replay_lookup(path):
        if not path:
            return None
        # Collapse buggy doubled prefixes (\??\\??\X → \??\X etc.) so
        # a user-supplied \??\X entry still matches when the driver
        # builds a malformed path. Applied to both sides; idempotent.
        try:
            from decode import normalize_nt_path
            path = normalize_nt_path(path)
        except Exception:
            pass
        # Direct match
        if path in state['replay_data']:
            return state['replay_data'][path]
        # Case-insensitive on Windows paths
        lower = path.lower()
        for k, v in state['replay_data'].items():
            if k.lower() == lower:
                return v
        # Suffix match (driver sees full kernel path, user may store short)
        for k, v in state['replay_data'].items():
            if lower.endswith(k.lower()) or k.lower().endswith(lower):
                return v
        return None

    # ----- File handlers -----
    def _make_open_file():
        def fn(self, emu, argv, ctx={}):
            handle_addr = argv[0] if len(argv) > 0 else 0
            attrs_addr = argv[2] if len(argv) > 2 else 0
            iosb_addr = argv[3] if len(argv) > 3 else 0
            path = _resolve_path(emu, attrs_addr)
            h = _next_handle()
            if path:
                state['handle_to_path'][h] = path
                # Snapshot the resolved OA name into argv[2] so the
                # log line renders the path inline, not a stale
                # pointer. By format_call time the driver's stack
                # frame holding the UNICODE_STRING is often freed
                # and the original bytes are gone.
                argv[2] = path
            _write_handle(emu, handle_addr, h)
            _write_iosb(emu, iosb_addr, 0, 1)  # STATUS_SUCCESS, FILE_OPENED
            state['log']['files_opened'].append({
                'path': path or '<unknown>',
                'handle': hex(h),
                'access': hex(argv[1]) if len(argv) > 1 else None,
            })
            return 0
        return fn

    def _make_create_file():
        # CreateFile has 11 args; OBJECT_ATTRIBUTES is still at index 2.
        return _make_open_file()

    def _make_read_file():
        def fn(self, emu, argv, ctx={}):
            handle = argv[0] if len(argv) > 0 else 0
            iosb_addr = argv[4] if len(argv) > 4 else 0
            buf = argv[5] if len(argv) > 5 else 0
            length = argv[6] if len(argv) > 6 else 0
            # ULONG → mask to 32 bits; ZwReadFile takes a ULONG Length
            # (Speakeasy occasionally hands us a 64-bit value with
            # garbage in the high half — see decode.py U32 helper).
            if isinstance(length, int):
                length &= 0xFFFFFFFF
            path = state['handle_to_path'].get(handle, '<unknown>')
            replay = _replay_lookup(path) if state['mode'] == 'replay' else None
            # Auto-PE for paths that *look like* a PE image (.exe / .sys
            # / .dll / .ocx / .cpl / .drv). Many drivers scan process
            # images (PsLookup loop → ZwCreateFile on the image path →
            # ZwReadFile to check for AV/EDR signatures) or load a
            # stage-2 from disk. Returning zeros for these makes them
            # bail on the first DOS-signature check. The explicit
            # `--fake-io-plausible-pe` flag still applies for non-PE-
            # named paths (config files, encrypted blobs, etc.) the
            # analyst knows are also PE-shaped.
            pe_extensions = ('.exe', '.sys', '.dll', '.ocx', '.cpl',
                             '.drv', '.efi')
            auto_pe_by_ext = bool(path) and isinstance(path, str) and \
                path.lower().rstrip('\x00').endswith(pe_extensions)
            # TDI socket path: drivers commonly open \Device\Tcp /
            # \Device\Udp / \Device\RawIp via ZwCreateFile and then issue
            # ZwReadFile to receive the network payload. If the analyst
            # supplied --fake-tdi-response, serve those bytes.
            tdi_path = bool(path) and isinstance(path, str) and \
                any(s in path.lower() for s in
                    ('\\device\\tcp', '\\device\\udp', '\\device\\rawip'))
            canned_tdi = None
            try:
                import shim as _shim
                _tdi = _shim.EMU_OPTS.get('canned_tdi_response') if hasattr(
                    _shim, 'EMU_OPTS') else None
                if tdi_path and _tdi:
                    canned_tdi = _tdi
            except Exception:
                pass
            info = 0
            try:
                if buf and length and length < 0x4000000:
                    if canned_tdi is not None:
                        payload = canned_tdi[:length].ljust(length, b'\x00')
                        emu.mem_write(buf, payload)
                        info = min(len(canned_tdi), length)
                    elif replay is not None:
                        payload = replay[:length].ljust(length, b'\x00')
                        emu.mem_write(buf, payload)
                        info = min(len(replay), length)
                    elif auto_pe_by_ext or (state.get('plausible_pe')
                                            and length >= 0x100):
                        # PE-shaped path OR explicit plausible-PE flag
                        # for a large read: serve a minimal valid PE64
                        # skeleton (MZ + PE+ header + one .text section,
                        # SizeOfImage > 0). Tiny reads (4-byte size
                        # queries, magic peeks) get the prefix of that
                        # blob, which is `4d 5a 90 00 …` — i.e. the
                        # legitimate `MZ` magic, which is the right
                        # answer when the caller is checking "is this
                        # a PE?"
                        payload = _build_plausible_pe64(length)
                        emu.mem_write(buf, payload)
                        info = length
                    else:
                        emu.mem_write(buf, b'\x00' * length)
                        info = length
            except Exception:
                pass
            _write_iosb(emu, iosb_addr, 0, info)
            state['log']['files_read'].append({
                'path': path,
                'handle': hex(handle),
                'length': length,
                'used_replay': replay is not None,
            })
            return 0
        return fn

    def _make_write_file():
        def fn(self, emu, argv, ctx={}):
            handle = argv[0] if len(argv) > 0 else 0
            iosb_addr = argv[4] if len(argv) > 4 else 0
            buf = argv[5] if len(argv) > 5 else 0
            length = argv[6] if len(argv) > 6 else 0
            path = state['handle_to_path'].get(handle, '<unknown>')
            data = b''
            data_hex = None
            try:
                # When --dump-files is on we keep the FULL bytes so the
                # caller can flush them to disk. Otherwise just take a
                # 64-byte prefix for the discovered_io log.
                cap = 0x100000 if state.get('dump_files_dir') else 0x4000
                if buf and length and length < cap:
                    data = bytes(emu.mem_read(buf, length))
                    data_hex = data[:64].hex()
            except Exception:
                pass
            _write_iosb(emu, iosb_addr, 0, length)
            state['log']['files_written'].append({
                'path': path,
                'handle': hex(handle),
                'length': length,
                'data_prefix_hex': data_hex,
            })
            # Accumulate into the per-path buffer. d3/d11 reopen the
            # log file for every event (open+write+close), so keying on
            # path (not handle) yields a single concatenated dump.
            if state.get('dump_files_dir') and data and path != '<unknown>':
                state['file_writes'].setdefault(
                    path, bytearray()).extend(data)
            return 0
        return fn

    def _make_query_info_file():
        """ZwQueryInformationFile responder. Drivers that read a config
        file typically call this with FileStandardInformation(class=5)
        to learn the size before allocating + reading. Without a sane
        response they bail on STATUS_INVALID_PARAMETER and never call
        ZwReadFile — meaning --fake-io replay content is never asked
        for. For our fake handles, return the replay-content size (or
        a small synthetic default).

        NTSTATUS ZwQueryInformationFile(HANDLE, PIOSB,
                                         PVOID Info, ULONG Length,
                                         FILE_INFORMATION_CLASS Class)
        """
        def fn(self, emu, argv, ctx={}):
            if len(argv) < 5:
                return 0xC000000D  # STATUS_INVALID_PARAMETER
            handle, iosb, info, length, fic = argv[:5]
            path = state['handle_to_path'].get(handle)
            if path is None:
                return 0xC0000008  # STATUS_INVALID_HANDLE — not ours
            FileStandardInformation = 5
            FileBasicInformation = 4
            FilePositionInformation = 14
            FileEndOfFileInformation = 20
            FileNameInformation = 9
            replay = _replay_lookup(path) if state['mode'] == 'replay' else None
            size = len(replay) if replay is not None else (
                # In `auto` / `learn` modes, report a small default so
                # drivers progress to the read path. The discovered_io
                # log already has the open record; the small read of
                # zeros from --fake-io auto's ZwReadFile is harmless.
                64 if state['mode'] in ('auto', 'learn') else 0)
            try:
                if fic == FileStandardInformation:
                    # FILE_STANDARD_INFORMATION {LARGE_INTEGER Alloc,
                    #   LARGE_INTEGER EndOfFile, ULONG NumberOfLinks,
                    #   BOOLEAN DeletePending, BOOLEAN Directory}
                    blob = _s.pack('<QQIBB', size, size, 1, 0, 0)
                    blob += b'\x00\x00'  # pad to 0x18
                    if info and length >= len(blob):
                        emu.mem_write(info, blob[:length])
                    _write_iosb(emu, iosb, 0, len(blob))
                    return 0
                elif fic == FileBasicInformation:
                    # 5 × LARGE_INTEGER (Create/LastAccess/LastWrite/
                    # Change times + FileAttributes ULONG)
                    blob = _s.pack('<QQQQI', 0, 0, 0, 0, 0x20) + b'\x00' * 4
                    if info and length >= len(blob):
                        emu.mem_write(info, blob[:length])
                    _write_iosb(emu, iosb, 0, len(blob))
                    return 0
                elif fic == FilePositionInformation:
                    blob = _s.pack('<Q', 0)
                    if info and length >= len(blob):
                        emu.mem_write(info, blob)
                    _write_iosb(emu, iosb, 0, len(blob))
                    return 0
                elif fic == FileEndOfFileInformation:
                    blob = _s.pack('<Q', size)
                    if info and length >= len(blob):
                        emu.mem_write(info, blob)
                    _write_iosb(emu, iosb, 0, len(blob))
                    return 0
                elif fic == FileNameInformation:
                    name_w = path.encode('utf-16-le')
                    blob = _s.pack('<I', len(name_w)) + name_w
                    if info and length >= len(blob):
                        emu.mem_write(info, blob[:length])
                    _write_iosb(emu, iosb, 0, len(blob))
                    return 0
            except Exception:
                pass
            # Unknown class — zero-fill and succeed (most drivers accept it)
            try:
                if info and length:
                    emu.mem_write(info, b'\x00' * min(length, 0x100))
                _write_iosb(emu, iosb, 0, length)
            except Exception:
                pass
            return 0

        return fn

    def _make_close():
        def fn(self, emu, argv, ctx={}):
            handle = argv[0] if len(argv) > 0 else 0
            path = state['handle_to_path'].pop(handle, None)
            if path is not None:
                state['log']['files_closed'].append({
                    'handle': hex(handle), 'path': path})
            return 0
        return fn

    # ----- Registry handlers -----
    def _make_open_key():
        def fn(self, emu, argv, ctx={}):
            handle_addr = argv[0] if len(argv) > 0 else 0
            attrs_addr = argv[2] if len(argv) > 2 else 0
            path = _resolve_path(emu, attrs_addr)
            h = _next_handle()
            if path:
                state['handle_to_path'][h] = path
            _write_handle(emu, handle_addr, h)
            state['log']['keys_opened'].append({
                'path': path or '<unknown>',
                'handle': hex(h),
            })
            return 0
        return fn

    def _make_create_key():
        # NtCreateKey has a Disposition out arg at index 6.
        def fn(self, emu, argv, ctx={}):
            handle_addr = argv[0] if len(argv) > 0 else 0
            attrs_addr = argv[2] if len(argv) > 2 else 0
            disp_addr = argv[6] if len(argv) > 6 else 0
            path = _resolve_path(emu, attrs_addr)
            h = _next_handle()
            if path:
                state['handle_to_path'][h] = path
            _write_handle(emu, handle_addr, h)
            # Disposition = REG_OPENED_EXISTING_KEY (2)
            if disp_addr:
                try:
                    emu.mem_write(disp_addr, _s.pack('<I', 2))
                except Exception:
                    pass
            state['log']['keys_opened'].append({
                'path': path or '<unknown>',
                'handle': hex(h), 'created': True,
            })
            return 0
        return fn

    def _make_query_value_key():
        def fn(self, emu, argv, ctx={}):
            handle = argv[0] if len(argv) > 0 else 0
            name_addr = argv[1] if len(argv) > 1 else 0
            info_class = argv[2] if len(argv) > 2 else 0
            buf_addr = argv[3] if len(argv) > 3 else 0
            buf_len = argv[4] if len(argv) > 4 else 0
            ret_len_addr = argv[5] if len(argv) > 5 else 0
            name = _resolve_unicode_string(emu, name_addr)
            key_path = state['handle_to_path'].get(handle, '<unknown>')
            state['log']['values_queried'].append({
                'key_path': key_path, 'value_name': name or '<unknown>',
                'info_class': info_class,
            })
            # #1: try the registry replay map first. We support
            # KeyValueBasicInformation(0), KeyValueFullInformation(1) and
            # KeyValuePartialInformation(2), with #2 being the common case.
            reg = state['registry_data'] or {}
            val = None
            if name and reg:
                # Direct path match
                bag = reg.get(key_path)
                if not bag:
                    # Case-insensitive
                    low = (key_path or '').lower()
                    for k, v in reg.items():
                        if k.lower() == low:
                            bag = v
                            break
                if bag:
                    val = bag.get(name)
                    if val is None:
                        low_n = name.lower()
                        for k, v in bag.items():
                            if k.lower() == low_n:
                                val = v
                                break
            if val and info_class in (0, 1, 2):
                # Tolerate malformed user-supplied shapes — apihook is
                # not the right place to surface the diagnostic (no log
                # handle here); validation is done at load time in
                # ktrace.py and the malformed entry was already
                # warned-about and replaced with {} there.
                if not isinstance(val, dict):
                    val = {}
                val_type = int(val.get('type', 4))  # REG_DWORD default
                raw_hex = val.get('data_hex', '')
                if not isinstance(raw_hex, str):
                    raw_hex = ''
                try:
                    data = bytes.fromhex(raw_hex)
                except ValueError:
                    data = b''
                if info_class == 2:
                    # KEY_VALUE_PARTIAL_INFORMATION { ULONG TitleIndex;
                    # ULONG Type; ULONG DataLength; UCHAR Data[1]; }
                    blob = _s.pack('<III', 0, val_type, len(data)) + data
                elif info_class == 1:
                    # KEY_VALUE_FULL_INFORMATION { TitleIndex; Type;
                    # DataOffset; DataLength; NameLength; Name[1]; ...Data }
                    nm_utf16 = (name or '').encode('utf-16-le')
                    hdr_size = 0x14
                    data_off = (hdr_size + len(nm_utf16) + 3) & ~3
                    blob = (_s.pack('<IIIII', 0, val_type, data_off,
                                    len(data), len(nm_utf16))
                            + nm_utf16
                            + b'\x00' * (data_off - hdr_size - len(nm_utf16))
                            + data)
                else:  # 0 = basic
                    nm_utf16 = (name or '').encode('utf-16-le')
                    blob = (_s.pack('<III', 0, val_type, len(nm_utf16))
                            + nm_utf16)
                total = len(blob)
                if ret_len_addr:
                    try:
                        emu.mem_write(ret_len_addr, _s.pack('<I', total))
                    except Exception:
                        pass
                if not buf_addr or buf_len < total:
                    return 0xC0000023  # STATUS_BUFFER_TOO_SMALL
                try:
                    emu.mem_write(buf_addr, blob)
                except Exception:
                    pass
                return 0  # STATUS_SUCCESS
            # No replay match — let driver fall back to defaults.
            return 0xC0000034  # STATUS_OBJECT_NAME_NOT_FOUND
        return fn

    def _make_set_value_key():
        def fn(self, emu, argv, ctx={}):
            handle = argv[0] if len(argv) > 0 else 0
            name_addr = argv[1] if len(argv) > 1 else 0
            data_addr = argv[4] if len(argv) > 4 else 0
            data_len = argv[5] if len(argv) > 5 else 0
            name = _resolve_unicode_string(emu, name_addr)
            data_hex = None
            try:
                if data_addr and data_len and data_len < 0x1000:
                    data_hex = bytes(emu.mem_read(data_addr, data_len)).hex()
            except Exception:
                pass
            state['log']['values_set'].append({
                'key_path': state['handle_to_path'].get(handle, '<unknown>'),
                'value_name': name or '<unknown>',
                'type': argv[3] if len(argv) > 3 else None,
                'data_hex': data_hex,
                'data_len': data_len,
            })
            return 0
        return fn

    HOOKS = [
        # Name, argc, factory
        ('ZwOpenFile',         6,  _make_open_file),
        ('NtOpenFile',         6,  _make_open_file),
        ('IoCreateFile',      11,  _make_create_file),
        ('IoCreateFileEx',    12,  _make_create_file),
        ('ZwCreateFile',      11,  _make_create_file),
        ('NtCreateFile',      11,  _make_create_file),
        ('ZwReadFile',         9,  _make_read_file),
        ('NtReadFile',         9,  _make_read_file),
        ('ZwWriteFile',        9,  _make_write_file),
        ('NtWriteFile',        9,  _make_write_file),
        ('ZwQueryInformationFile', 5,  _make_query_info_file),
        ('NtQueryInformationFile', 5,  _make_query_info_file),
        ('ZwClose',            1,  _make_close),
        ('NtClose',            1,  _make_close),
        ('ZwOpenKey',          3,  _make_open_key),
        ('NtOpenKey',          3,  _make_open_key),
        ('ZwCreateKey',        7,  _make_create_key),
        ('NtCreateKey',        7,  _make_create_key),
        ('ZwQueryValueKey',    6,  _make_query_value_key),
        ('NtQueryValueKey',    6,  _make_query_value_key),
        ('ZwSetValueKey',      6,  _make_set_value_key),
        ('NtSetValueKey',      6,  _make_set_value_key),
    ]
    for name, ac, factory in HOOKS:
        setattr(ntos_mod.Ntoskrnl, name,
                apihook(name, argc=ac, conv=conv)(factory()))

