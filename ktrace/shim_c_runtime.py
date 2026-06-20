"""Basic C-runtime stubs (strstr, strncmp, strcmp, strlen, wcscmp,
memcpy_s, _vsnwprintf) that Speakeasy doesn't ship. With --force-strstr-match
EMU_OPTS toggle, strstr returns the input pointer for the second arg if it
isn't found — bypasses machine-binding anti-emu checks."""
from speakeasy.winenv.api import api as api_module
from speakeasy.winenv import arch as _arch
from shim_state import EMU_OPTS
apihook = api_module.ApiHandler.apihook


# Module-level so other extracted sections (shim_ctype, callers in shim.py)
# can import these helpers without going through a closure.
def _read_cstr(emu_arg, addr, max_len=0x400):
    if not addr:
        return b''
    try:
        data = bytes((getattr(emu_arg, 'mem_read', None) or
                      emu_arg.emu.mem_read)(addr, max_len))
    except Exception:
        return b''
    nul = data.find(b'\x00')
    return data if nul < 0 else data[:nul]


def _read_wcstr(emu_arg, addr, max_chars=0x400):
    if not addr:
        return b''
    try:
        data = bytes((getattr(emu_arg, 'mem_read', None) or
                      emu_arg.emu.mem_read)(addr, max_chars * 2))
    except Exception:
        return b''
    for i in range(0, len(data) - 1, 2):
        if data[i] == 0 and data[i + 1] == 0:
            return data[:i]
    return data


def install_c_runtime(arch_bits, ntos_mod, conv, log_func):
    # ---- Basic C runtime that Speakeasy doesn't ship --------------
    # These zero-stubs are silently wrong but let drivers proceed
    # without halting on `unsupported_api`. strstr/strncmp/strlen are
    # most-called; proper implementations follow.

    def _strstr(self, emu_arg, argv, ctx={}):
        if len(argv) < 2 or not argv[0] or not argv[1]:
            return 0
        hay = _read_cstr(emu_arg, argv[0])
        needle = _read_cstr(emu_arg, argv[1])
        if not needle:
            return argv[0]
        idx = hay.find(needle)
        if idx >= 0:
            return argv[0] + idx
        # --force-strstr-match: bypass anti-emulation guards that
        # compare a runtime-generated fingerprint against the driver's
        # own install path. Returns the haystack base so the caller
        # sees a "match at offset 0".
        if EMU_OPTS.get('force_strstr_match'):
            if log_func:
                log_func(f"  [force-strstr-match] returning hay base "
                         f"(needle={needle!r:.60s} would have missed)")
            return argv[0]
        return 0

    def _strncmp(self, emu_arg, argv, ctx={}):
        if len(argv) < 3 or not argv[0] or not argv[1]:
            return 0
        n = argv[2]
        if n <= 0:
            return 0
        a = _read_cstr(emu_arg, argv[0], n)[:n]
        b = _read_cstr(emu_arg, argv[1], n)[:n]
        # pad with zeros to compare exactly n bytes
        a = a + b'\x00' * (n - len(a))
        b = b + b'\x00' * (n - len(b))
        for ca, cb in zip(a, b):
            if ca != cb:
                return -1 if ca < cb else 1
        return 0

    def _strcmp(self, emu_arg, argv, ctx={}):
        if len(argv) < 2:
            return 0
        a = _read_cstr(emu_arg, argv[0])
        b = _read_cstr(emu_arg, argv[1])
        if a == b:
            return 0
        return -1 if a < b else 1

    def _strlen(self, emu_arg, argv, ctx={}):
        if not argv or not argv[0]:
            return 0
        return len(_read_cstr(emu_arg, argv[0]))

    def _wcscmp(self, emu_arg, argv, ctx={}):
        if len(argv) < 2:
            return 0
        a = _read_wcstr(emu_arg, argv[0])
        b = _read_wcstr(emu_arg, argv[1])
        if a == b:
            return 0
        return -1 if a < b else 1

    def _memcpy_s(self, emu_arg, argv, ctx={}):
        # errno_t memcpy_s(dst, dst_size, src, count)
        if len(argv) < 4:
            return 0x16  # EINVAL
        dst, dst_sz, src, n = argv[0], argv[1], argv[2], argv[3]
        if not dst or not src or n > dst_sz:
            return 0x22  # ERANGE
        try:
            data = bytes((getattr(emu_arg, 'mem_read', None) or
                          emu_arg.emu.mem_read)(src, n))
            (getattr(emu_arg, 'mem_write', None) or
             emu_arg.emu.mem_write)(dst, data)
        except Exception:
            return 0x16
        return 0

    def _install(name, fn, argc, conv_=None):
        if hasattr(ntos_mod.Ntoskrnl, name):
            return
        setattr(ntos_mod.Ntoskrnl, name,
                apihook(name, argc=argc,
                        conv=conv_ or _arch.CALL_CONV_CDECL)(fn))

    _install('strstr',    _strstr,    2)
    _install('strncmp',   _strncmp,   3)
    _install('strcmp',    _strcmp,    2)
    _install('strlen',    _strlen,    1)
    _install('wcscmp',    _wcscmp,    2)
    _install('memcpy_s',  _memcpy_s,  4)
    _install_vsnwprintf(arch_bits, ntos_mod, log_func)


def _read_pwstr_safe(emu, addr, max_chars=0x400):
    """Read a NUL-terminated wide (UTF-16-LE) string. Tolerant of mem holes."""
    if not addr:
        return ''
    try:
        data = bytes((getattr(emu, 'mem_read', None) or
                      emu.emu.mem_read)(addr, max_chars * 2))
    except Exception:
        return ''
    for k in range(0, len(data) - 1, 2):
        if data[k] == 0 and data[k + 1] == 0:
            return data[:k].decode('utf-16-le', errors='replace')
    return data.decode('utf-16-le', errors='replace')


def _read_unicode_string(emu, addr, arch_bits):
    """Read a UNICODE_STRING { USHORT Length, USHORT Max, [pad,] PWSTR Buf }."""
    if not addr:
        return ''
    try:
        import struct as _s
        if arch_bits == 64:
            hdr = bytes((getattr(emu, 'mem_read', None) or
                         emu.emu.mem_read)(addr, 16))
            length = _s.unpack('<H', hdr[0:2])[0]
            buf = _s.unpack('<Q', hdr[8:16])[0]
        else:
            hdr = bytes((getattr(emu, 'mem_read', None) or
                         emu.emu.mem_read)(addr, 8))
            length = _s.unpack('<H', hdr[0:2])[0]
            buf = _s.unpack('<I', hdr[4:8])[0]
        if not buf or length == 0 or length > 0x800:
            return ''
        return bytes((getattr(emu, 'mem_read', None) or
                      emu.emu.mem_read)(buf, length)
                     ).decode('utf-16-le', errors='replace')
    except Exception:
        return ''


def _read_ansi_string(emu, addr, arch_bits):
    """Read an ANSI_STRING { USHORT Length, USHORT Max, PSTR Buf }."""
    if not addr:
        return ''
    try:
        import struct as _s
        if arch_bits == 64:
            hdr = bytes((getattr(emu, 'mem_read', None) or
                         emu.emu.mem_read)(addr, 16))
            length = _s.unpack('<H', hdr[0:2])[0]
            buf = _s.unpack('<Q', hdr[8:16])[0]
        else:
            hdr = bytes((getattr(emu, 'mem_read', None) or
                         emu.emu.mem_read)(addr, 8))
            length = _s.unpack('<H', hdr[0:2])[0]
            buf = _s.unpack('<I', hdr[4:8])[0]
        if not buf or length == 0 or length > 0x800:
            return ''
        return bytes((getattr(emu, 'mem_read', None) or
                      emu.emu.mem_read)(buf, length)
                     ).decode('latin-1', errors='replace')
    except Exception:
        return ''


def _format_ansi_kernel(emu, arch_bits, fmt_str, va_list_addr,
                        max_args=32):
    """ANSI sibling of _format_wide_kernel.

    Reads variadic args from the va_list (pointer-sized slots). MS CRT
    rules for the ANSI family: `%s`/`%hs` = narrow string,
    `%S`/`%ws`/`%ls` = wide string, `%wZ` = PUNICODE_STRING, `%Z` =
    PANSI_STRING. Numeric conversions standard. Supports `%I64u` /
    `%I64d` / `%I32u` MSVC length modifiers used heavily by kernel-mode
    event logs (d14's 15-field reporter).

    Returns the rendered Python str (always latin-1-safe)."""
    import struct as _s
    ptr_size = 8 if arch_bits == 64 else 4
    pfmt = '<Q' if arch_bits == 64 else '<I'
    out = []
    i = 0
    arg_i = 0

    def _fetch(idx):
        if va_list_addr == 0 or idx >= max_args:
            return 0
        try:
            raw = bytes((getattr(emu, 'mem_read', None) or
                         emu.emu.mem_read)(
                va_list_addr + idx * ptr_size, ptr_size))
            return _s.unpack(pfmt, raw)[0]
        except Exception:
            return 0

    while i < len(fmt_str):
        ch = fmt_str[i]
        if ch != '%' or i + 1 >= len(fmt_str):
            out.append(ch)
            i += 1
            continue
        j = i + 1
        flags_start = j
        while j < len(fmt_str) and fmt_str[j] in '0123456789.-+# *':
            j += 1
        flags_part = fmt_str[flags_start:j]
        peek2 = fmt_str[j:j+2]
        # Windows-kernel specifiers (rare in ANSI family but legal).
        if peek2 == 'wZ':
            addr = _fetch(arg_i); arg_i += 1
            out.append(_read_unicode_string(emu, addr, arch_bits))
            i = j + 2
            continue
        if peek2 == 'ws':
            addr = _fetch(arg_i); arg_i += 1
            out.append(_read_pwstr_safe(emu, addr))
            i = j + 2
            continue
        if fmt_str[j:j+1] == 'Z':
            addr = _fetch(arg_i); arg_i += 1
            out.append(_read_ansi_string(emu, addr, arch_bits))
            i = j + 1
            continue
        # Length prefix: l/ll/h/hh/I/I32/I64/z (excluding 'w')
        length = ''
        while j < len(fmt_str) and fmt_str[j] in 'lhzI':
            if fmt_str[j] == 'I' and j + 2 < len(fmt_str) \
                    and fmt_str[j+1:j+3] in ('32', '64'):
                length += fmt_str[j:j+3]
                j += 3
            else:
                length += fmt_str[j]
                j += 1
        if j >= len(fmt_str):
            out.append(fmt_str[i:j])
            break
        conv = fmt_str[j]
        # %ls / %S = wide string in ANSI-family
        if conv == 'S' or (conv == 's' and ('l' in length or 'w' in length)):
            addr = _fetch(arg_i); arg_i += 1
            out.append(_read_pwstr_safe(emu, addr))
            i = j + 1
            continue
        # %s in ANSI family = narrow string
        if conv == 's':
            addr = _fetch(arg_i); arg_i += 1
            try:
                raw = bytes((getattr(emu, 'mem_read', None) or
                             emu.emu.mem_read)(addr, 0x400))
                nul = raw.find(b'\x00')
                s = raw[:nul if nul >= 0 else len(raw)]
                out.append(s.decode('latin-1', errors='replace'))
            except Exception:
                pass
            i = j + 1
            continue
        if conv == 'c':
            v = _fetch(arg_i); arg_i += 1
            try:
                out.append(chr(v & 0xFF))
            except Exception:
                pass
            i = j + 1
            continue
        if conv in ('d', 'i', 'u', 'o', 'x', 'X', 'p'):
            v = _fetch(arg_i); arg_i += 1
            if conv in ('d', 'i'):
                bits = 64 if ('ll' in length or 'I64' in length) else 32
                if 'h' in length and 'hh' not in length:
                    bits = 16
                if 'hh' in length:
                    bits = 8
                v &= (1 << bits) - 1
                if v & (1 << (bits - 1)):
                    v -= (1 << bits)
                spec = '{:' + flags_part + 'd}'
            elif conv == 'u':
                # Mask out sign for unsigned
                if 'I64' in length or 'll' in length:
                    v &= 0xFFFFFFFFFFFFFFFF
                elif 'I32' in length or 'l' in length:
                    v &= 0xFFFFFFFF
                spec = '{:' + flags_part + 'd}'
            elif conv == 'o':
                spec = '{:' + flags_part + 'o}'
            elif conv == 'x':
                spec = '{:' + flags_part + 'x}'
            elif conv == 'X':
                spec = '{:' + flags_part + 'X}'
            else:  # p
                spec = '0x{:x}'
            try:
                out.append(spec.format(v))
            except Exception:
                out.append(str(v))
            i = j + 1
            continue
        # Unrecognised — emit verbatim.
        out.append(fmt_str[i:j+1])
        i = j + 1
    return ''.join(out)


def _format_wide_kernel(emu, arch_bits, fmt_wstr, va_list_addr,
                        max_args=16):
    """Render a wide format string with Windows-kernel %wZ/%Z/%ws/%hs/%s
    handling. Reads variadic args from the va_list address (each slot is
    pointer-sized). Returns the rendered Python string.

    On x64 _vsnwprintf, va_list is a pointer to the first arg slot in the
    caller's stack home/spill space; each slot is 8 bytes."""
    import struct as _s
    ptr_size = 8 if arch_bits == 64 else 4
    pfmt = '<Q' if arch_bits == 64 else '<I'
    out = []
    i = 0
    arg_i = 0

    def _fetch(idx):
        if va_list_addr == 0 or idx >= max_args:
            return 0
        try:
            raw = bytes((getattr(emu, 'mem_read', None) or
                         emu.emu.mem_read)(
                va_list_addr + idx * ptr_size, ptr_size))
            return _s.unpack(pfmt, raw)[0]
        except Exception:
            return 0

    while i < len(fmt_wstr):
        ch = fmt_wstr[i]
        if ch != '%' or i + 1 >= len(fmt_wstr):
            out.append(ch)
            i += 1
            continue
        # Parse flags/width/precision (we mostly discard these).
        j = i + 1
        flags_start = j
        while j < len(fmt_wstr) and fmt_wstr[j] in '0123456789.-+# *':
            j += 1
        flags_part = fmt_wstr[flags_start:j]
        # %wZ / %ws / %wc must be detected BEFORE the length-prefix loop
        # eats the 'w'. Likewise %Z is a Windows-kernel ANSI_STRING.
        peek2 = fmt_wstr[j:j+2]
        if peek2 == 'wZ':
            addr = _fetch(arg_i); arg_i += 1
            out.append(_read_unicode_string(emu, addr, arch_bits))
            i = j + 2
            continue
        if peek2 == 'ws':
            addr = _fetch(arg_i); arg_i += 1
            out.append(_read_pwstr_safe(emu, addr))
            i = j + 2
            continue
        if peek2 == 'wc':
            v = _fetch(arg_i); arg_i += 1
            try:
                out.append(chr(v & 0xFFFF))
            except Exception:
                pass
            i = j + 2
            continue
        if fmt_wstr[j:j+1] == 'Z':
            addr = _fetch(arg_i); arg_i += 1
            out.append(_read_ansi_string(emu, addr, arch_bits))
            i = j + 1
            continue
        # Length prefix: l/ll/h/hh/I/I32/I64/z. Do NOT eat 'w' here —
        # the %wZ / %ws / %wc lookahead above already handled it.
        length = ''
        while j < len(fmt_wstr) and fmt_wstr[j] in 'lhzI':
            if fmt_wstr[j] == 'I' and j + 2 < len(fmt_wstr) \
                    and fmt_wstr[j+1:j+3] in ('32', '64'):
                length += fmt_wstr[j:j+3]
                j += 3
            else:
                length += fmt_wstr[j]
                j += 1
        if j >= len(fmt_wstr):
            out.append(fmt_wstr[i:j])
            break
        conv = fmt_wstr[j]
        # %lc / %ls: wide char / wide string
        if conv == 's' and 'l' in length:
            addr = _fetch(arg_i); arg_i += 1
            out.append(_read_pwstr_safe(emu, addr))
            i = j + 1
            continue
        # %hs / %S: narrow string (in a wide-format function, %S is narrow)
        if conv in ('S',) or (conv == 's' and 'h' in length):
            addr = _fetch(arg_i); arg_i += 1
            try:
                raw = bytes((getattr(emu, 'mem_read', None) or
                             emu.emu.mem_read)(addr, 0x400))
                nul = raw.find(b'\x00')
                s = raw[:nul if nul >= 0 else len(raw)]
                out.append(s.decode('latin-1', errors='replace'))
            except Exception:
                pass
            i = j + 1
            continue
        # %s in wide-format = wide string (MS CRT rule)
        if conv == 's':
            addr = _fetch(arg_i); arg_i += 1
            out.append(_read_pwstr_safe(emu, addr))
            i = j + 1
            continue
        # %c in wide-format = wide char
        if conv == 'c':
            v = _fetch(arg_i); arg_i += 1
            try:
                out.append(chr(v & 0xFFFF))
            except Exception:
                pass
            i = j + 1
            continue
        # Numeric conversions.
        if conv in ('d', 'i', 'u', 'o', 'x', 'X', 'p'):
            v = _fetch(arg_i); arg_i += 1
            if conv in ('d', 'i'):
                # Treat as signed of appropriate width.
                bits = 64 if ('ll' in length or 'I64' in length
                              or arch_bits == 64 and conv == 'p') else 32
                if 'h' in length and 'hh' not in length:
                    bits = 16
                if 'hh' in length:
                    bits = 8
                v &= (1 << bits) - 1
                if v & (1 << (bits - 1)):
                    v -= (1 << bits)
                spec = '{:' + flags_part + 'd}'
            elif conv == 'u':
                spec = '{:' + flags_part + 'd}'
            elif conv == 'o':
                spec = '{:' + flags_part + 'o}'
            elif conv == 'x':
                spec = '{:' + flags_part + 'x}'
            elif conv == 'X':
                spec = '{:' + flags_part + 'X}'
            else:  # p
                spec = '0x{:x}'
            try:
                out.append(spec.format(v))
            except Exception:
                out.append(str(v))
            i = j + 1
            continue
        # Unrecognised — emit verbatim and skip.
        out.append(fmt_wstr[i:j+1])
        i = j + 1
    return ''.join(out)


def _install_vsnwprintf(arch_bits, ntos_mod, log_func):
    """Real _vsnwprintf / _snwprintf implementation. Reads the wide format
    string + va_list, formats with %wZ/%Z/%ws/%s/%d/etc., writes UTF-16-LE
    result to the output buffer, and (if log_func is set) logs the
    rendered string. Critical for malware that builds registry paths or
    DbgPrint output strings via this routine — otherwise the buffer
    contents stay zero and downstream RtlCreateRegistryKey /
    RtlWriteRegistryValue / etc. show opaque pointers."""

    def _vsnwprintf_impl(self, emu_arg, argv, ctx={}, _va_offset=3):
        # argv: [buf, count, fmt, va_list]
        if len(argv) < 4:
            return 0
        buf, count, fmt_addr, va_list = argv[0], argv[1], argv[2], argv[3]
        fmt = _read_pwstr_safe(emu_arg, fmt_addr)
        if not fmt:
            return 0
        try:
            text = _format_wide_kernel(emu_arg, arch_bits, fmt, va_list)
        except Exception as e:
            text = f'<vsnwprintf-err:{e}>'
        # Honour the caller's buffer size (count in wchars, includes NUL).
        if count > 0:
            text = text[:max(0, count - 1)]
        # Write UTF-16-LE to buffer.
        if buf:
            try:
                payload = text.encode('utf-16-le') + b'\x00\x00'
                (getattr(emu_arg, 'mem_write', None) or
                 emu_arg.emu.mem_write)(buf, payload)
            except Exception:
                pass
        # Substitute the rendered string in the report's arg slot
        # so format_call's per-API line shows it inline too.
        try:
            argv[2] = text
        except Exception:
            pass
        return len(text)

    # Same impl for _snwprintf — caller provides args directly, so va_list
    # equivalent is whatever sits at argv[3]+ in the spill region. Speakeasy
    # passes us the first N args; cdecl spill order makes argv[3] the first
    # variadic. We treat that as the va_list base — for a single-arg
    # registry-path build this is accurate. For richer cases the apihook
    # VAR_ARGS lookup returns address-of next-arg via Speakeasy itself.
    def _snwprintf_impl(self, emu_arg, argv, ctx={}):
        # Rebuild a va_list shape by reading from the spill area.
        # argv length depends on VAR_ARGS detection; we re-fetch via
        # get_func_argv so we can pull a va_list-equivalent pointer.
        try:
            _av = emu_arg.get_func_argv(_arch.CALL_CONV_CDECL, 4)
            buf, count, fmt_addr = _av[0], _av[1], _av[2]
        except Exception:
            return 0
        fmt = _read_pwstr_safe(emu_arg, fmt_addr)
        if not fmt:
            return 0
        # Read variadic args directly via Speakeasy.
        n_specs = fmt.count('%')
        try:
            full = emu_arg.get_func_argv(
                _arch.CALL_CONV_CDECL, 3 + max(n_specs, 1))[3:]
        except Exception:
            full = []
        # Stash them into a synthetic va_list region for _format_wide_kernel.
        ptr_size = 8 if arch_bits == 64 else 4
        pfmt = '<Q' if arch_bits == 64 else '<I'
        import struct as _s
        blob = b''.join(_s.pack(pfmt, a & ((1 << (ptr_size * 8)) - 1))
                        for a in full)
        from speakeasy.common import PERM_MEM_RWX
        try:
            mm = (getattr(emu_arg, 'mem_map', None) or
                  emu_arg.emu.mem_map)
            mw = (getattr(emu_arg, 'mem_write', None) or
                  emu_arg.emu.mem_write)
            va = mm(0x100, base=None, tag='ktrace.va_snwprintf',
                    perms=PERM_MEM_RWX)
            mw(va, blob)
        except Exception:
            va = 0
        try:
            text = _format_wide_kernel(emu_arg, arch_bits, fmt, va)
        except Exception as e:
            text = f'<snwprintf-err:{e}>'
        if count > 0:
            text = text[:max(0, count - 1)]
        if buf:
            try:
                (getattr(emu_arg, 'mem_write', None) or
                 emu_arg.emu.mem_write)(
                    buf, text.encode('utf-16-le') + b'\x00\x00')
            except Exception:
                pass
        try:
            argv[2] = text
        except Exception:
            pass
        return len(text)

    # apihook() mutates __apihook__ in place — give each name its own
    # trampoline so all four register independently.
    def _make_trampoline(target):
        def _t(self, emu, argv, ctx={}):
            return target(self, emu, argv, ctx)
        return _t

    # `_vsnwprintf` (4 args, has count) vs `_snwprintf`/`swprintf` (varargs).
    # `vswprintf` and `vswprintf_s` are va_list-form variants that show
    # up in C++-wrapped drivers — same impl shape as _vsnwprintf, just
    # with/without the count arg.
    def _vswprintf_impl(self, emu_arg, argv, ctx={}):
        # int vswprintf(wchar_t *buf, const wchar_t *fmt, va_list ap);
        if len(argv) < 3:
            return 0
        buf, fmt_addr, va_list = argv[0], argv[1], argv[2]
        fmt = _read_pwstr_safe(emu_arg, fmt_addr)
        if not fmt:
            return 0
        try:
            text = _format_wide_kernel(emu_arg, arch_bits, fmt, va_list)
        except Exception as e:
            text = f'<vswprintf-err:{e}>'
        if buf:
            try:
                (getattr(emu_arg, 'mem_write', None) or
                 emu_arg.emu.mem_write)(
                    buf, text.encode('utf-16-le') + b'\x00\x00')
            except Exception:
                pass
        try:
            argv[1] = text
        except Exception:
            pass
        return len(text)

    def _vswprintf_s_impl(self, emu_arg, argv, ctx={}):
        # int vswprintf_s(wchar_t *buf, size_t sz, fmt, va_list ap);
        if len(argv) < 4:
            return 0
        buf, sz, fmt_addr, va_list = argv[:4]
        fmt = _read_pwstr_safe(emu_arg, fmt_addr)
        if not fmt:
            return 0
        try:
            text = _format_wide_kernel(emu_arg, arch_bits, fmt, va_list)
        except Exception as e:
            text = f'<vswprintf_s-err:{e}>'
        if sz > 0:
            text = text[:max(0, sz - 1)]
        if buf:
            try:
                (getattr(emu_arg, 'mem_write', None) or
                 emu_arg.emu.mem_write)(
                    buf, text.encode('utf-16-le') + b'\x00\x00')
            except Exception:
                pass
        try:
            argv[2] = text
        except Exception:
            pass
        return len(text)

    for _nm, _impl, _argc in (
            ('_vsnwprintf', _vsnwprintf_impl, 4),
            ('vsnwprintf', _vsnwprintf_impl, 4),
            ('_snwprintf', _snwprintf_impl, _arch.VAR_ARGS),
            ('swprintf', _snwprintf_impl, _arch.VAR_ARGS),
            ('swprintf_s', _snwprintf_impl, _arch.VAR_ARGS),
            ('vswprintf', _vswprintf_impl, 3),
            ('vswprintf_s', _vswprintf_s_impl, 4)):
        # apihook() mutates __apihook__ in place; give each name its
        # own trampoline. Don't skip when Speakeasy ships an impl —
        # we replace it because the upstream parser is brittle.
        setattr(ntos_mod.Ntoskrnl, _nm,
                apihook(_nm, argc=_argc,
                        conv=_arch.CALL_CONV_CDECL)(
                    _make_trampoline(_impl)))

    # ---- ANSI variants: _vsnprintf_s, _snprintf_s, sprintf_s.
    # Same shape as the wide-char family but format string and output
    # are 8-bit (default latin-1 / utf-8). Drivers' event-log formatters
    # (see d14's "%d^%d^%d^%p^%p^%d^%I64u^%s^%s^..." reporter) generate
    # huge ANSI lines and our previous zero-stub buried them. Now we
    # walk the va_list, format, write back to dst, and log the
    # rendered string.
    #
    # _vsnprintf_s signature (MSVC secure CRT):
    #   int _vsnprintf_s(char *buffer, size_t sizeOfBuffer, size_t count,
    #                    const char *format, va_list arglist);
    # `count == _TRUNCATE (== SIZE_MAX)` means "truncate at sizeOfBuffer".
    def _vsnprintf_s_impl(self, emu_arg, argv, ctx={}):
        if len(argv) < 5:
            return 0
        buf, sz_of_buf, count, fmt_addr, va_list = argv[:5]
        fmt = _read_cstr(emu_arg, fmt_addr, 0x800).decode(
            'latin-1', errors='replace')
        if not fmt:
            return 0
        try:
            text = _format_ansi_kernel(emu_arg, arch_bits, fmt, va_list)
        except Exception as e:
            text = f'<vsnprintf_s-err:{e}>'
        # Honour the smaller of sizeOfBuffer / (count if not _TRUNCATE).
        TRUNCATE = (1 << (8 * (8 if arch_bits == 64 else 4))) - 1
        if count != TRUNCATE and count > 0:
            text = text[:max(0, min(count, sz_of_buf - 1))]
        elif sz_of_buf > 0:
            text = text[:max(0, sz_of_buf - 1)]
        if buf:
            try:
                (getattr(emu_arg, 'mem_write', None) or
                 emu_arg.emu.mem_write)(buf, text.encode('latin-1',
                                                         errors='replace')
                                        + b'\x00')
            except Exception:
                pass
        # Surface the rendered string in the arg slot so format_call's
        # per-API line shows it inline.
        try:
            argv[3] = text
        except Exception:
            pass
        return len(text)

    def _snprintf_s_impl(self, emu_arg, argv, ctx={}):
        # int _snprintf_s(buf, sz, count, fmt, ...);
        try:
            _av = emu_arg.get_func_argv(_arch.CALL_CONV_CDECL, 4)
            buf, sz_of_buf, count, fmt_addr = _av[0], _av[1], _av[2], _av[3]
        except Exception:
            return 0
        fmt = _read_cstr(emu_arg, fmt_addr, 0x800).decode(
            'latin-1', errors='replace')
        if not fmt:
            return 0
        # Rebuild a va_list from spill area.
        n_specs = max(fmt.count('%'), 1)
        try:
            full = emu_arg.get_func_argv(
                _arch.CALL_CONV_CDECL, 4 + n_specs)[4:]
        except Exception:
            full = []
        ptr_size = 8 if arch_bits == 64 else 4
        pfmt = '<Q' if arch_bits == 64 else '<I'
        import struct as _s
        blob = b''.join(_s.pack(pfmt, a & ((1 << (ptr_size * 8)) - 1))
                        for a in full)
        from speakeasy.common import PERM_MEM_RWX
        try:
            mm = (getattr(emu_arg, 'mem_map', None) or
                  emu_arg.emu.mem_map)
            mw = (getattr(emu_arg, 'mem_write', None) or
                  emu_arg.emu.mem_write)
            va = mm(0x100, base=None, tag='ktrace.va_snprintf_s',
                    perms=PERM_MEM_RWX)
            mw(va, blob)
        except Exception:
            va = 0
        try:
            text = _format_ansi_kernel(emu_arg, arch_bits, fmt, va)
        except Exception as e:
            text = f'<snprintf_s-err:{e}>'
        TRUNCATE = (1 << (8 * (8 if arch_bits == 64 else 4))) - 1
        if count != TRUNCATE and count > 0:
            text = text[:max(0, min(count, sz_of_buf - 1))]
        elif sz_of_buf > 0:
            text = text[:max(0, sz_of_buf - 1)]
        if buf:
            try:
                (getattr(emu_arg, 'mem_write', None) or
                 emu_arg.emu.mem_write)(buf, text.encode('latin-1',
                                                         errors='replace')
                                        + b'\x00')
            except Exception:
                pass
        try:
            argv[3] = text
        except Exception:
            pass
        return len(text)

    # ---- _vsnprintf / _snprintf / sprintf / printf (non-_s variants).
    # Speakeasy ships its own impls but its format-string parser is
    # "very brittle" per upstream comments — chokes on `%04d-%02d-…`
    # patterns (d3 FileProtection's timestamp logger) with
    # "not enough arguments for format string". Override with our
    # robust _format_ansi_kernel which handles MSVC width/precision/
    # length-modifier syntax (%I64u / %ll / %hs / %hZ / %Z etc.).
    def _vsnprintf_impl(self, emu_arg, argv, ctx={}):
        # int _vsnprintf(char *buffer, size_t count, const char *fmt,
        #                va_list argptr);
        if len(argv) < 4:
            return 0
        buf, count, fmt_addr, va_list = argv[:4]
        fmt = _read_cstr(emu_arg, fmt_addr, 0x800).decode(
            'latin-1', errors='replace')
        if not fmt:
            return 0
        try:
            text = _format_ansi_kernel(emu_arg, arch_bits, fmt, va_list)
        except Exception as e:
            text = f'<vsnprintf-err:{e}>'
        if count > 0:
            text = text[:max(0, count - 1)]
        if buf:
            try:
                (getattr(emu_arg, 'mem_write', None) or
                 emu_arg.emu.mem_write)(buf, text.encode('latin-1',
                                                         errors='replace')
                                        + b'\x00')
            except Exception:
                pass
        try:
            argv[2] = text
        except Exception:
            pass
        return len(text)

    def _snprintf_impl(self, emu_arg, argv, ctx={}):
        # int _snprintf(char *buf, size_t count, const char *fmt, ...);
        # ANSI sibling of _snwprintf — same approach: pull all args
        # off the call site via get_func_argv, rebuild a synthetic
        # va_list region, hand it to _format_ansi_kernel.
        try:
            _av = emu_arg.get_func_argv(_arch.CALL_CONV_CDECL, 3)
            buf, count, fmt_addr = _av[0], _av[1], _av[2]
        except Exception:
            return 0
        fmt = _read_cstr(emu_arg, fmt_addr, 0x800).decode(
            'latin-1', errors='replace')
        if not fmt:
            return 0
        n_specs = max(fmt.count('%'), 1)
        try:
            full = emu_arg.get_func_argv(
                _arch.CALL_CONV_CDECL, 3 + n_specs)[3:]
        except Exception:
            full = []
        ptr_size = 8 if arch_bits == 64 else 4
        pfmt = '<Q' if arch_bits == 64 else '<I'
        import struct as _s
        blob = b''.join(_s.pack(pfmt, a & ((1 << (ptr_size * 8)) - 1))
                        for a in full)
        from speakeasy.common import PERM_MEM_RWX
        try:
            mm = (getattr(emu_arg, 'mem_map', None) or
                  emu_arg.emu.mem_map)
            mw = (getattr(emu_arg, 'mem_write', None) or
                  emu_arg.emu.mem_write)
            va = mm(0x100, base=None, tag='ktrace.va_snprintf',
                    perms=PERM_MEM_RWX)
            mw(va, blob)
        except Exception:
            va = 0
        try:
            text = _format_ansi_kernel(emu_arg, arch_bits, fmt, va)
        except Exception as e:
            text = f'<snprintf-err:{e}>'
        if count > 0:
            text = text[:max(0, count - 1)]
        if buf:
            try:
                (getattr(emu_arg, 'mem_write', None) or
                 emu_arg.emu.mem_write)(buf, text.encode('latin-1',
                                                         errors='replace')
                                        + b'\x00')
            except Exception:
                pass
        try:
            argv[2] = text
        except Exception:
            pass
        return len(text)

    def _sprintf_impl(self, emu_arg, argv, ctx={}):
        # int sprintf(char *buf, const char *fmt, ...); no count arg.
        try:
            _av = emu_arg.get_func_argv(_arch.CALL_CONV_CDECL, 2)
            buf, fmt_addr = _av[0], _av[1]
        except Exception:
            return 0
        fmt = _read_cstr(emu_arg, fmt_addr, 0x800).decode(
            'latin-1', errors='replace')
        if not fmt:
            return 0
        n_specs = max(fmt.count('%'), 1)
        try:
            full = emu_arg.get_func_argv(
                _arch.CALL_CONV_CDECL, 2 + n_specs)[2:]
        except Exception:
            full = []
        ptr_size = 8 if arch_bits == 64 else 4
        pfmt = '<Q' if arch_bits == 64 else '<I'
        import struct as _s
        blob = b''.join(_s.pack(pfmt, a & ((1 << (ptr_size * 8)) - 1))
                        for a in full)
        from speakeasy.common import PERM_MEM_RWX
        try:
            mm = (getattr(emu_arg, 'mem_map', None) or
                  emu_arg.emu.mem_map)
            mw = (getattr(emu_arg, 'mem_write', None) or
                  emu_arg.emu.mem_write)
            va = mm(0x100, base=None, tag='ktrace.va_sprintf',
                    perms=PERM_MEM_RWX)
            mw(va, blob)
        except Exception:
            va = 0
        try:
            text = _format_ansi_kernel(emu_arg, arch_bits, fmt, va)
        except Exception as e:
            text = f'<sprintf-err:{e}>'
        if buf:
            try:
                (getattr(emu_arg, 'mem_write', None) or
                 emu_arg.emu.mem_write)(buf, text.encode('latin-1',
                                                         errors='replace')
                                        + b'\x00')
            except Exception:
                pass
        try:
            argv[1] = text
        except Exception:
            pass
        return len(text)

    # ---- strcat_s / wcscat_s: actually concatenate. The default 0-return
    # stub in LIKELY_STUBS leaves the destination unchanged, which then
    # causes downstream DbgPrint(buf) calls to log empty strings because
    # the malware's logger function builds its message via memset → strcat_s
    # → strcat_s → DbgPrint(buf). Without a real strcat_s the buf stays
    # zero-filled and the entire message stream is silenced.
    #
    # errno_t strcat_s(char *strDest, size_t numberOfElements,
    #                  const char *strSource);
    # Appends `strSource` to the end of the (NUL-terminated) `strDest`
    # provided the total fits in `numberOfElements` (including the
    # trailing NUL). Returns 0 on success.
    def _strcat_s_impl(self, emu_arg, argv, ctx={}):
        if len(argv) < 3:
            return 0x16  # EINVAL
        dst, n_elems, src = argv[:3]
        if not dst or not src or n_elems == 0:
            return 0x16
        try:
            cur = _read_cstr(emu_arg, dst, min(0x800, n_elems))
        except Exception:
            cur = b''
        try:
            add = _read_cstr(emu_arg, src, min(0x800, n_elems))
        except Exception:
            add = b''
        cur_len = len(cur)
        if cur_len + len(add) + 1 > n_elems:
            return 0x22  # ERANGE — dst too small
        try:
            (getattr(emu_arg, 'mem_write', None) or
             emu_arg.emu.mem_write)(dst + cur_len, add + b'\x00')
        except Exception:
            return 0x22
        # Surface the appended source so the trace shows what landed.
        try:
            argv[2] = add.decode('latin-1', errors='replace')
        except Exception:
            pass
        return 0

    # wcscat_s: same as strcat_s but UTF-16-LE wide chars. numberOfElements
    # counts wide characters, not bytes.
    def _wcscat_s_impl(self, emu_arg, argv, ctx={}):
        if len(argv) < 3:
            return 0x16
        dst, n_elems, src = argv[:3]
        if not dst or not src or n_elems == 0:
            return 0x16
        try:
            cur_b = bytes((getattr(emu_arg, 'mem_read', None) or
                           emu_arg.emu.mem_read)(dst, min(0x1000,
                                                          n_elems * 2)))
        except Exception:
            cur_b = b''
        # Find the wchar NUL terminator (two consecutive zero bytes on
        # an even offset).
        cur_wlen = 0
        for k in range(0, len(cur_b) - 1, 2):
            if cur_b[k] == 0 and cur_b[k+1] == 0:
                cur_wlen = k
                break
        else:
            cur_wlen = len(cur_b) & ~1
        try:
            add_b = bytes((getattr(emu_arg, 'mem_read', None) or
                           emu_arg.emu.mem_read)(src, min(0x1000,
                                                          n_elems * 2)))
        except Exception:
            add_b = b''
        add_wlen = 0
        for k in range(0, len(add_b) - 1, 2):
            if add_b[k] == 0 and add_b[k+1] == 0:
                add_wlen = k
                break
        else:
            add_wlen = len(add_b) & ~1
        if (cur_wlen + add_wlen) // 2 + 1 > n_elems:
            return 0x22
        try:
            (getattr(emu_arg, 'mem_write', None) or
             emu_arg.emu.mem_write)(dst + cur_wlen,
                                    add_b[:add_wlen] + b'\x00\x00')
        except Exception:
            return 0x22
        try:
            argv[2] = add_b[:add_wlen].decode('utf-16-le',
                                              errors='replace')
        except Exception:
            pass
        return 0

    # ---- strncpy_s: read src, write to dst, log the copied string.
    # errno_t strncpy_s(char *strDest, size_t numberOfElements,
    #                   const char *strSource, size_t count);
    # count == _TRUNCATE → copy up to numberOfElements-1
    def _strncpy_s_impl(self, emu_arg, argv, ctx={}):
        if len(argv) < 4:
            return 0x16  # EINVAL
        dst, n_elems, src, count = argv[:4]
        if not dst or not src or n_elems == 0:
            return 0x16
        TRUNCATE = (1 << (8 * (8 if arch_bits == 64 else 4))) - 1
        s = _read_cstr(emu_arg, src, min(0x800, n_elems))
        if count == TRUNCATE:
            limit = n_elems - 1
        else:
            limit = min(count, n_elems - 1)
        s = s[:max(0, limit)]
        try:
            (getattr(emu_arg, 'mem_write', None) or
             emu_arg.emu.mem_write)(dst, s + b'\x00')
        except Exception:
            return 0x22  # ERANGE
        # Surface the source string so format_call shows it inline.
        try:
            argv[2] = s.decode('latin-1', errors='replace')
        except Exception:
            pass
        return 0  # success

    # vsprintf — int vsprintf(buf, fmt, va_list). No count arg.
    def _vsprintf_impl(self, emu_arg, argv, ctx={}):
        if len(argv) < 3:
            return 0
        buf, fmt_addr, va_list = argv[:3]
        fmt = _read_cstr(emu_arg, fmt_addr, 0x800).decode(
            'latin-1', errors='replace')
        if not fmt:
            return 0
        try:
            text = _format_ansi_kernel(emu_arg, arch_bits, fmt, va_list)
        except Exception as e:
            text = f'<vsprintf-err:{e}>'
        if buf:
            try:
                (getattr(emu_arg, 'mem_write', None) or
                 emu_arg.emu.mem_write)(buf, text.encode('latin-1',
                                                         errors='replace')
                                        + b'\x00')
            except Exception:
                pass
        try:
            argv[1] = text
        except Exception:
            pass
        return len(text)

    # vsprintf_s — secure variant, int vsprintf_s(buf, sz, fmt, va).
    def _vsprintf_s_impl(self, emu_arg, argv, ctx={}):
        if len(argv) < 4:
            return 0
        buf, sz_of_buf, fmt_addr, va_list = argv[:4]
        fmt = _read_cstr(emu_arg, fmt_addr, 0x800).decode(
            'latin-1', errors='replace')
        if not fmt:
            return 0
        try:
            text = _format_ansi_kernel(emu_arg, arch_bits, fmt, va_list)
        except Exception as e:
            text = f'<vsprintf_s-err:{e}>'
        if sz_of_buf > 0:
            text = text[:max(0, sz_of_buf - 1)]
        if buf:
            try:
                (getattr(emu_arg, 'mem_write', None) or
                 emu_arg.emu.mem_write)(buf, text.encode('latin-1',
                                                         errors='replace')
                                        + b'\x00')
            except Exception:
                pass
        try:
            argv[2] = text
        except Exception:
            pass
        return len(text)

    # _vscprintf / _vscwprintf — return required buffer size without
    # writing. Same arg shape as _vsnprintf but no buffer.
    def _vscprintf_impl(self, emu_arg, argv, ctx={}):
        if len(argv) < 2:
            return 0
        fmt_addr, va_list = argv[:2]
        fmt = _read_cstr(emu_arg, fmt_addr, 0x800).decode(
            'latin-1', errors='replace')
        if not fmt:
            return 0
        try:
            text = _format_ansi_kernel(emu_arg, arch_bits, fmt, va_list)
        except Exception:
            return 0
        try:
            argv[0] = text
        except Exception:
            pass
        return len(text)

    for _nm, _impl, _argc in (
            ('_vsnprintf_s', _vsnprintf_s_impl, 5),
            ('vsnprintf_s', _vsnprintf_s_impl, 5),
            ('_snprintf_s', _snprintf_s_impl, _arch.VAR_ARGS),
            ('sprintf_s', _snprintf_s_impl, _arch.VAR_ARGS),
            ('strncpy_s', _strncpy_s_impl, 4),
            ('strcat_s', _strcat_s_impl, 3),
            ('wcscat_s', _wcscat_s_impl, 3),
            # Non-_s ANSI vararg printers — override Speakeasy's
            # brittle parser (fails on %04d-%02d-... patterns).
            ('_vsnprintf', _vsnprintf_impl, 4),
            ('vsnprintf', _vsnprintf_impl, 4),
            ('_snprintf', _snprintf_impl, _arch.VAR_ARGS),
            ('snprintf', _snprintf_impl, _arch.VAR_ARGS),
            ('sprintf', _sprintf_impl, _arch.VAR_ARGS),
            # va_list variants (no varargs at the call site, just a
            # pre-built va_list pointer).
            ('vsprintf', _vsprintf_impl, 3),
            ('vsprintf_s', _vsprintf_s_impl, 4),
            ('_vscprintf', _vscprintf_impl, 2)):
        # apihook() mutates __apihook__ on the function object — give
        # each name its own trampoline so all register independently.
        setattr(ntos_mod.Ntoskrnl, _nm,
                apihook(_nm, argc=_argc,
                        conv=_arch.CALL_CONV_CDECL)(
                    _make_trampoline(_impl)))

