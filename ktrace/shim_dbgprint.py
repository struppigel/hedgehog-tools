"""DbgPrint / DbgPrintEx logging with smart string decoding (UTF-8 → GBK →
Latin-1) and %wZ / %Z / %ws inline-substitution. Wired up only when
install_shim was given a log_func; otherwise we leave Speakeasy's
default DbgPrint stub alone."""
import struct as _struct
from speakeasy.winenv.api import api as api_module
from speakeasy.winenv import arch as _arch
from shim_fake_io import FAKE_IO, _install_fake_io_hooks
apihook = api_module.ApiHandler.apihook


def install_dbgprint_logging(arch_bits, ntos_mod, conv, state, log_func):
    # ---- Fake I/O overrides (Level 1 + Level 2) ----
    if FAKE_IO['mode'] != 'off':
        _install_fake_io_hooks(arch_bits, conv)

    def _smart_decode(b: bytes) -> str:
        """Auto-detect byte-string encoding: UTF-8 → GBK → Latin-1.

        UTF-8 first because it's the modern default and easy to detect
        (will raise UnicodeDecodeError on invalid sequences). GBK next
        because Chinese-market kernel malware is common in our corpus.
        Latin-1 always succeeds, so it's the no-loss fallback that
        preserves raw bytes for the analyst.
        """
        if not isinstance(b, (bytes, bytearray)):
            return str(b)
        if not b:
            return ''
        # Fast path: pure ASCII.
        if all(c < 0x80 for c in b):
            return b.decode('ascii', errors='replace')
        for enc in ('utf-8', 'gbk'):
            try:
                return b.decode(enc)
            except UnicodeDecodeError:
                continue
        return b.decode('latin-1', errors='replace')

    if log_func:
        def _read_cstr_smart(emu, addr, max_len=0x400):
            try:
                data = bytes((getattr(emu, 'mem_read', None) or
                              emu.emu.mem_read)(addr, max_len))
            except Exception:
                return ''
            nul = data.find(b'\x00')
            return _smart_decode(data[:nul if nul >= 0 else len(data)])

        def _resolve_wZ(emu, fmt_str, vargs):
            """Pre-process Windows-kernel DbgPrint format specifiers
            %wZ, %Z, %ws by reading the UNICODE_STRING / ANSI_STRING /
            PWSTR they point at and *inlining* the actual string
            content in the format string itself (since Speakeasy's
            do_str_format treats %s args as pointers and chokes on
            Python str values). Args corresponding to inlined
            specifiers are dropped from the new vargs list."""
            out = []
            new_args = []
            i = 0
            arg_i = 0

            def _read_ansi_str(addr):
                try:
                    if arch_bits == 64:
                        hdr = bytes((getattr(emu, 'mem_read', None) or
                                     emu.emu.mem_read)(addr, 16))
                        length = _struct.unpack('<H', hdr[0:2])[0]
                        buf = _struct.unpack('<Q', hdr[8:16])[0]
                    else:
                        hdr = bytes((getattr(emu, 'mem_read', None) or
                                     emu.emu.mem_read)(addr, 8))
                        length = _struct.unpack('<H', hdr[0:2])[0]
                        buf = _struct.unpack('<I', hdr[4:8])[0]
                    return _smart_decode(bytes(
                        (getattr(emu, 'mem_read', None) or
                         emu.emu.mem_read)(buf, length)))
                except Exception:
                    return ''

            def _read_pwstr(addr):
                try:
                    data = bytes((getattr(emu, 'mem_read', None) or
                                  emu.emu.mem_read)(addr, 1024))
                    for k in range(0, len(data) - 1, 2):
                        if data[k] == 0 and data[k+1] == 0:
                            return data[:k].decode('utf-16-le',
                                                   errors='replace')
                    return data.decode('utf-16-le', errors='replace')
                except Exception:
                    return ''

            while i < len(fmt_str):
                ch = fmt_str[i]
                if ch != '%' or i + 1 >= len(fmt_str):
                    out.append(ch)
                    i += 1
                    continue
                j = i + 1
                while j < len(fmt_str) and fmt_str[j] in '0123456789.-+# ':
                    j += 1
                spec2 = fmt_str[j:j+2].lower()
                spec1 = fmt_str[j:j+1].lower()
                if spec2 == 'wz':
                    addr = vargs[arg_i] if arg_i < len(vargs) else 0
                    arg_i += 1
                    # Read UNICODE_STRING { USHORT Length, USHORT Max,
                    #                       [pad,] PWSTR Buffer }.
                    try:
                        from shim_c_runtime import _read_unicode_string
                        out.append(_read_unicode_string(emu, addr,
                                                       arch_bits) or '')
                    except Exception:
                        out.append('')
                    i = j + 2
                    continue
                if spec1 == 'z':
                    addr = vargs[arg_i] if arg_i < len(vargs) else 0
                    arg_i += 1
                    out.append(_read_ansi_str(addr))
                    i = j + 1
                    continue
                if spec2 == 'ws':
                    addr = vargs[arg_i] if arg_i < len(vargs) else 0
                    arg_i += 1
                    out.append(_read_pwstr(addr))
                    i = j + 2
                    continue
                # Pass through unchanged; arg goes to Speakeasy.
                out.append(fmt_str[i:j+1])
                if arg_i < len(vargs):
                    new_args.append(vargs[arg_i])
                arg_i += 1
                i = j + 1
            return ''.join(out), new_args

        # _do_format: build a synthetic va_list region from a list of
        # ints and run our robust _format_ansi_kernel parser. Replaces
        # the Speakeasy `do_str_format` call that misparses common
        # MSVC width/precision specifiers like `%04d-%02d`.
        def _do_format(emu, fmt_str, vargs):
            from speakeasy.common import PERM_MEM_RWX
            import struct as _s
            from shim_c_runtime import _format_ansi_kernel
            ptr_size = 8 if arch_bits == 64 else 4
            pfmt = '<Q' if arch_bits == 64 else '<I'
            blob = b''.join(_s.pack(pfmt,
                                    (a & ((1 << (ptr_size * 8)) - 1))
                                    if isinstance(a, int) else 0)
                            for a in vargs)
            try:
                va = emu.mem_map(0x200, base=None,
                                 tag='ktrace.va_dbgprint',
                                 perms=PERM_MEM_RWX)
                emu.mem_write(va, blob)
            except Exception:
                va = 0
            try:
                return _format_ansi_kernel(emu, arch_bits, fmt_str, va)
            except Exception as e:
                return f'<fmt err: {e}>'

        @apihook('DbgPrint', argc=_arch.VAR_ARGS, conv=_arch.CALL_CONV_CDECL)
        def DbgPrint_logged(self, emu, argv, ctx={}):
            state['hits'] += 1
            try:
                fmt = emu.get_func_argv(_arch.CALL_CONV_CDECL, 1)[0]
                # Read raw bytes and auto-detect encoding (UTF-8 → GBK
                # → Latin-1) — Chinese-market malware embeds GBK strings
                # which Speakeasy's read_string mangles via latin-1.
                fmt_str = _read_cstr_smart(emu, fmt)
                # Count % signs (rough upper bound) and pull that many
                # call-site args. _format_ansi_kernel skips the ones
                # consumed by %wZ / %Z / %ws and walks the rest.
                raw_argc = max(self.get_va_arg_count(fmt_str),
                               fmt_str.count('%'))
                _argv = emu.get_func_argv(
                    _arch.CALL_CONV_CDECL, 1 + raw_argc)[1:]
                fin = _do_format(emu, fmt_str, _argv)
            except Exception as e:
                fin = f'<dbg err: {e}>'
            log_func(f'  DbgPrint #{state["hits"]}: {fin!r}')
            argv.clear(); argv.append(fin)
            return len(fin)
        ntos_mod.Ntoskrnl.DbgPrint = DbgPrint_logged
        # DbgPrintEx alias — same format-string handling.
        @apihook('DbgPrintEx', argc=_arch.VAR_ARGS, conv=_arch.CALL_CONV_CDECL)
        def DbgPrintEx_logged(self, emu, argv, ctx={}):
            state['hits'] += 1
            try:
                # DbgPrintEx(ComponentId, Level, Format, ...)
                _av = emu.get_func_argv(_arch.CALL_CONV_CDECL, 3)
                fmt = _av[2]
                fmt_str = _read_cstr_smart(emu, fmt)
                raw_argc = max(self.get_va_arg_count(fmt_str),
                               fmt_str.count('%'))
                _argv = emu.get_func_argv(
                    _arch.CALL_CONV_CDECL, 3 + raw_argc)[3:]
                fin = _do_format(emu, fmt_str, _argv)
            except Exception as e:
                fin = f'<dbg err: {e}>'
            log_func(f'  DbgPrintEx #{state["hits"]}: {fin!r}')
            argv.clear(); argv.append(fin)
            return len(fin)
        ntos_mod.Ntoskrnl.DbgPrintEx = DbgPrintEx_logged
