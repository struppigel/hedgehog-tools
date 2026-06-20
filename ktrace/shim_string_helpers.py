"""RtlUnicodeStringToAnsiString / RtlFreeAnsiString / RtlAnsiCharToUnicodeChar /
RtlCopyUnicodeString / sprintf_s. Speakeasy ships the unicode-only side; the
ansi-output side is missing and drivers that convert kernel paths/names
between encodings halt early without these."""
import struct as _struct
from speakeasy.winenv.api import api as api_module
from speakeasy.winenv import arch as _arch
apihook = api_module.ApiHandler.apihook


def install_string_helpers(arch_bits, ntos_mod):
    # ---- String conversion helpers Speakeasy doesn't ship ---------
    # Drivers that convert unicode<->ansi names (registry paths, device
    # names, file names) halt early without these; the unicode-only
    # variant is shipped but the ansi-output side isn't.
    is64 = (arch_bits == 64)
    _UFMT = '<Q' if is64 else '<I'
    _ULEN_OFF = 0  # UNICODE_STRING/ANSI_STRING both: Len@+0, Max@+2
    _UBUF_OFF = 8 if is64 else 4

    def _read_ustr_bytes(emu_arg, addr):
        if not addr:
            return b''
        try:
            hdr = bytes((getattr(emu_arg, 'mem_read', None) or
                         emu_arg.emu.mem_read)(addr, 16 if is64 else 8))
            length = _struct.unpack('<H', hdr[0:2])[0]
            buf = _struct.unpack(_UFMT, hdr[_UBUF_OFF:_UBUF_OFF + (8 if is64 else 4)])[0]
            if not buf or length == 0 or length > 0x2000:
                return b''
            return bytes((getattr(emu_arg, 'mem_read', None) or
                          emu_arg.emu.mem_read)(buf, length))
        except Exception:
            return b''

    def _write_ustr_header(emu_arg, addr, length, max_len, buf_addr):
        try:
            data = (_struct.pack('<H', length) +
                    _struct.pack('<H', max_len) +
                    (b'\x00\x00\x00\x00' if is64 else b'') +
                    _struct.pack(_UFMT, buf_addr))
            (getattr(emu_arg, 'mem_write', None) or
             emu_arg.emu.mem_write)(addr, data)
        except Exception:
            pass

    def _mem_map(emu_arg, sz):
        from speakeasy.common import PERM_MEM_RWX
        fn = (getattr(emu_arg, 'mem_map', None) or
              getattr(getattr(emu_arg, 'emu', None), 'mem_map', None))
        if not fn:
            return 0
        return fn(sz, base=None, tag='ktrace.rtl_str', perms=PERM_MEM_RWX)

    def _rtl_unicode_to_ansi(self, emu_arg, argv, ctx={}):
        # NTSTATUS RtlUnicodeStringToAnsiString(
        #   PANSI_STRING dst, PCUNICODE_STRING src, BOOLEAN allocate)
        if len(argv) < 3 or not argv[0] or not argv[1]:
            return 0xC0000001
        src = _read_ustr_bytes(emu_arg, argv[1])
        try:
            ansi = src.decode('utf-16-le', errors='replace').encode(
                'ascii', errors='replace')
        except Exception:
            ansi = src[:len(src) // 2]
        allocate = bool(argv[2])
        # Read existing dst header to find buffer if !allocate.
        buf_addr = 0
        max_len = 0
        if not allocate:
            try:
                hdr = bytes((getattr(emu_arg, 'mem_read', None) or
                             emu_arg.emu.mem_read)(argv[0], 16 if is64 else 8))
                max_len = _struct.unpack('<H', hdr[2:4])[0]
                buf_addr = _struct.unpack(
                    _UFMT,
                    hdr[_UBUF_OFF:_UBUF_OFF + (8 if is64 else 4)])[0]
            except Exception:
                pass
        if allocate or not buf_addr:
            # Allocate enough for content + NUL.
            buf_addr = _mem_map(emu_arg, max(len(ansi) + 1, 0x40))
            max_len = max(len(ansi) + 1, 0x40)
        # Truncate if larger than max_len-1 to keep room for NUL.
        ansi = ansi[:max(max_len - 1, 0)]
        try:
            (getattr(emu_arg, 'mem_write', None) or
             emu_arg.emu.mem_write)(buf_addr, ansi + b'\x00')
        except Exception:
            return 0xC0000023  # STATUS_BUFFER_TOO_SMALL
        _write_ustr_header(emu_arg, argv[0], len(ansi),
                           max(max_len, len(ansi) + 1), buf_addr)
        return 0

    def _rtl_free_ansi_string(self, emu_arg, argv, ctx={}):
        # VOID RtlFreeAnsiString(PANSI_STRING) — no-op (we don't track allocs).
        return 0

    def _rtl_ansichar_to_unicodechar(self, emu_arg, argv, ctx={}):
        # WCHAR RtlAnsiCharToUnicodeChar(PUCHAR *src). Reads byte through
        # *src, advances *src by 1, returns the byte as a wchar.
        if not argv:
            return 0
        try:
            ptr_size = 8 if is64 else 4
            buf = bytes((getattr(emu_arg, 'mem_read', None) or
                         emu_arg.emu.mem_read)(argv[0], ptr_size))
            src_addr = _struct.unpack(_UFMT, buf)[0]
            if not src_addr:
                return 0
            ch = bytes((getattr(emu_arg, 'mem_read', None) or
                        emu_arg.emu.mem_read)(src_addr, 1))[0]
            # advance the pointer in *src
            new_ptr = (src_addr + 1).to_bytes(ptr_size, 'little')
            (getattr(emu_arg, 'mem_write', None) or
             emu_arg.emu.mem_write)(argv[0], new_ptr)
            return ch
        except Exception:
            return 0

    def _sprintf_s(self, emu_arg, argv, ctx={}):
        # sprintf_s(buf, count, fmt, ...) — same as sprintf but with
        # explicit count. Delegate to existing sprintf if present;
        # otherwise return 0 (length).
        sprintf_h = getattr(ntos_mod.Ntoskrnl, 'sprintf', None)
        if sprintf_h is not None:
            try:
                # Shift args by one (drop count) and call.
                new_argv = [argv[0]] + list(argv[2:])
                return sprintf_h(self, emu_arg, new_argv, ctx)
            except Exception:
                pass
        return 0

    _rtl_conv = _arch.CALL_CONV_FASTCALL if arch_bits == 64 else _arch.CALL_CONV_STDCALL
    if not hasattr(ntos_mod.Ntoskrnl, 'RtlUnicodeStringToAnsiString'):
        ntos_mod.Ntoskrnl.RtlUnicodeStringToAnsiString = apihook(
            'RtlUnicodeStringToAnsiString', argc=3, conv=_rtl_conv)(
                _rtl_unicode_to_ansi)
    if not hasattr(ntos_mod.Ntoskrnl, 'RtlFreeAnsiString'):
        ntos_mod.Ntoskrnl.RtlFreeAnsiString = apihook(
            'RtlFreeAnsiString', argc=1, conv=_rtl_conv)(_rtl_free_ansi_string)
    if not hasattr(ntos_mod.Ntoskrnl, 'RtlAnsiCharToUnicodeChar'):
        ntos_mod.Ntoskrnl.RtlAnsiCharToUnicodeChar = apihook(
            'RtlAnsiCharToUnicodeChar', argc=1, conv=_rtl_conv)(
                _rtl_ansichar_to_unicodechar)
    if not hasattr(ntos_mod.Ntoskrnl, 'sprintf_s'):
        ntos_mod.Ntoskrnl.sprintf_s = apihook(
            'sprintf_s', argc=_arch.VAR_ARGS,
            conv=_arch.CALL_CONV_CDECL)(_sprintf_s)

    # Override RtlCopyUnicodeString with an explicit byte-copy impl.
    # Speakeasy's version reads/writes with internal helpers that
    # appear not to materialise the destination buffer contents in
    # some scenarios (drivers reading the dest immediately after see
    # zeros). The substring-match flow in AV-killer drivers depends
    # on this round-trip; verify it works by reading bytes back.
    def _rtl_copy_unicode_string(self, emu_arg, argv, ctx={}):
        # VOID RtlCopyUnicodeString(PUNICODE_STRING dst, PCUNICODE_STRING src)
        if len(argv) < 2 or not argv[0] or not argv[1]:
            return 0
        try:
            hdr_size = 16 if arch_bits == 64 else 8
            buf_off = 8 if arch_bits == 64 else 4
            mr = (getattr(emu_arg, 'mem_read', None) or
                  emu_arg.emu.mem_read)
            mw = (getattr(emu_arg, 'mem_write', None) or
                  emu_arg.emu.mem_write)
            # Read source UNICODE_STRING header
            src_hdr = bytes(mr(argv[1], hdr_size))
            src_len = _struct.unpack('<H', src_hdr[0:2])[0]
            src_maxlen = _struct.unpack('<H', src_hdr[2:4])[0]
            src_buf = _struct.unpack(_UFMT, src_hdr[buf_off:buf_off + (8 if arch_bits == 64 else 4)])[0]
            # Read dest UNICODE_STRING header
            dst_hdr = bytes(mr(argv[0], hdr_size))
            dst_maxlen = _struct.unpack('<H', dst_hdr[2:4])[0]
            dst_buf = _struct.unpack(_UFMT, dst_hdr[buf_off:buf_off + (8 if arch_bits == 64 else 4)])[0]
            if src_buf == 0 or dst_buf == 0:
                # Cap dst.Length at 0 and write back.
                new_hdr = (b'\x00\x00' + dst_hdr[2:])
                mw(argv[0], new_hdr)
                return 0
            to_copy = min(src_len, dst_maxlen)
            if to_copy:
                data = bytes(mr(src_buf, to_copy))
                mw(dst_buf, data)
                # Pad remaining dst.MaximumLength with zeros (matches
                # Windows RtlCopyUnicodeString documentation).
                # Strictly: doesn't NUL-pad beyond Length. Skip.
            # Update dest.Length only (do NOT change MaximumLength /
            # Buffer per spec).
            new_hdr = (_struct.pack('<H', to_copy) + dst_hdr[2:])
            mw(argv[0], new_hdr)
        except Exception:
            pass
        return 0

    setattr(ntos_mod.Ntoskrnl, 'RtlCopyUnicodeString',
            apihook('RtlCopyUnicodeString', argc=2, conv=_rtl_conv)(
                _rtl_copy_unicode_string))

    # RtlCreateUnicodeString — allocates a heap buffer, copies the
    # NUL-terminated source wide string into it, populates the
    # UNICODE_STRING destination. Required by rule-list builders that
    # turn parsed path strings into dispatchable UNICODE_STRINGs.
    # BOOLEAN RtlCreateUnicodeString(PUNICODE_STRING dst, PCWSTR src);
    def _rtl_create_unicode_string(self, emu_arg, argv, ctx={}):
        if len(argv) < 2 or not argv[0] or not argv[1]:
            return 0
        try:
            mr = (getattr(emu_arg, 'mem_read', None) or
                  emu_arg.emu.mem_read)
            mw = (getattr(emu_arg, 'mem_write', None) or
                  emu_arg.emu.mem_write)
            # Read NUL-terminated wide string (cap 0x2000 wchars).
            wchars = []
            for off in range(0, 0x4000, 2):
                w = bytes(mr(argv[1] + off, 2))
                if w == b'\x00\x00':
                    break
                wchars.append(w)
            data = b''.join(wchars)
            length = len(data)
            max_len = length + 2
            buf = _mem_map(emu_arg, max_len) if max_len else 0
            if buf:
                mw(buf, data + b'\x00\x00')
            _write_ustr_header(emu_arg, argv[0], length, max_len, buf)
            # Snapshot the source string into argv[1] so the trace shows
            # the actual string even after the caller frees the source
            # buffer. (decode.format_call recognises a string here and
            # quotes it; a bare int gets a PWSTR-deref that fails once
            # the page is unmapped.)
            try:
                argv[1] = data.decode('utf-16-le', errors='replace')
            except Exception:
                pass
            return 1  # BOOLEAN TRUE
        except Exception:
            return 0

    def _rtl_free_unicode_string(self, emu_arg, argv, ctx={}):
        # VOID RtlFreeUnicodeString(PUNICODE_STRING s); we don't actually
        # free the backing alloc (Speakeasy's emu memory persists for
        # the run), but we zero the header so the driver doesn't reuse
        # the stale buffer pointer.
        if not argv or not argv[0]:
            return 0
        try:
            _write_ustr_header(emu_arg, argv[0], 0, 0, 0)
        except Exception:
            pass
        return 0

    if not hasattr(ntos_mod.Ntoskrnl, 'RtlCreateUnicodeString'):
        setattr(ntos_mod.Ntoskrnl, 'RtlCreateUnicodeString',
                apihook('RtlCreateUnicodeString',
                        argc=2, conv=_rtl_conv)(_rtl_create_unicode_string))
    if not hasattr(ntos_mod.Ntoskrnl, 'RtlFreeUnicodeString'):
        setattr(ntos_mod.Ntoskrnl, 'RtlFreeUnicodeString',
                apihook('RtlFreeUnicodeString',
                        argc=1, conv=_rtl_conv)(_rtl_free_unicode_string))

    # RtlCompareUnicodeString / RtlEqualUnicodeString / RtlPrefixUnicodeString.
    # Speakeasy's LIKELY_STUBS list stubs these as `return 0`. For
    # RtlCompare that means "always equal", and any driver logic that
    # branches on "is rule.tag == 'Unknown'" misfires. Implement them
    # against the actual buffer contents.
    def _rtl_compare_unicode_string(self, emu_arg, argv, ctx={}):
        # LONG RtlCompareUnicodeString(PCUNICODE_STRING s1,
        #                              PCUNICODE_STRING s2, BOOLEAN ci);
        if len(argv) < 2:
            return 0
        b1 = _read_ustr_bytes(emu_arg, argv[0])
        b2 = _read_ustr_bytes(emu_arg, argv[1])
        ci = bool(argv[2]) if len(argv) > 2 else False
        try:
            s1 = b1.decode('utf-16-le', errors='replace')
            s2 = b2.decode('utf-16-le', errors='replace')
        except Exception:
            return 0
        # Stash the rendered strings in argv so format_call shows them
        # even after the source buffers might have been freed.
        try:
            argv[0] = s1
            argv[1] = s2
        except Exception:
            pass
        if ci:
            s1, s2 = s1.lower(), s2.lower()
        # Lexicographic compare. Windows returns the *byte* difference;
        # signum is what callers actually check.
        if s1 < s2:
            return 0xFFFFFFFF   # -1 as unsigned
        if s1 > s2:
            return 1
        return 0

    def _rtl_equal_unicode_string(self, emu_arg, argv, ctx={}):
        # BOOLEAN RtlEqualUnicodeString(s1, s2, ci) — strict equality.
        if len(argv) < 2:
            return 0
        b1 = _read_ustr_bytes(emu_arg, argv[0])
        b2 = _read_ustr_bytes(emu_arg, argv[1])
        ci = bool(argv[2]) if len(argv) > 2 else False
        try:
            s1 = b1.decode('utf-16-le', errors='replace')
            s2 = b2.decode('utf-16-le', errors='replace')
        except Exception:
            return 0
        try:
            argv[0] = s1
            argv[1] = s2
        except Exception:
            pass
        if ci:
            return 1 if s1.lower() == s2.lower() else 0
        return 1 if s1 == s2 else 0

    def _rtl_prefix_unicode_string(self, emu_arg, argv, ctx={}):
        # BOOLEAN RtlPrefixUnicodeString(s1, s2, ci) — does s1 prefix s2?
        if len(argv) < 2:
            return 0
        b1 = _read_ustr_bytes(emu_arg, argv[0])
        b2 = _read_ustr_bytes(emu_arg, argv[1])
        ci = bool(argv[2]) if len(argv) > 2 else False
        try:
            s1 = b1.decode('utf-16-le', errors='replace')
            s2 = b2.decode('utf-16-le', errors='replace')
        except Exception:
            return 0
        try:
            argv[0] = s1
            argv[1] = s2
        except Exception:
            pass
        if ci:
            return 1 if s2.lower().startswith(s1.lower()) else 0
        return 1 if s2.startswith(s1) else 0

    for _nm, _impl in (
            ('RtlCompareUnicodeString', _rtl_compare_unicode_string),
            ('RtlEqualUnicodeString',   _rtl_equal_unicode_string),
            ('RtlPrefixUnicodeString',  _rtl_prefix_unicode_string)):
        # Overwrite even if Speakeasy registered a stub already — the
        # whole reason this code exists is that LIKELY_STUBS returns 0.
        def _make_tramp(impl, nm):
            def _t(self, emu_arg, argv, ctx={}):
                return impl(self, emu_arg, argv, ctx)
            _t.__name__ = nm
            return apihook(nm, argc=3, conv=_rtl_conv)(_t)
        setattr(ntos_mod.Ntoskrnl, _nm, _make_tramp(_impl, _nm))

