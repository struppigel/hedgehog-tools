"""Internal function tracing — log calls to addresses inside the sample
itself (string decryptors, config parsers, IPC marshallers, etc.), not
just imported APIs.

Wire by passing `--trace-fn ADDR[:NAME][:SPEC]` to ktrace. The hook
installs a fire-everywhere code hook with a per-PC filter (same pattern
as `shim_fake_driver`'s stub hook — narrow-range begin/end is not
reliable on every Speakeasy + unicorn pairing).

SPEC: comma-separated key=value pairs (all optional) — describes how to
render each arg in the log line, and which args need a post-return
snapshot.

  in=N         arg N is a pointer to an input buffer; log the first
               `len` bytes (or 0x40 if no len= specified) as hex
  len=N        arg N is a length value (rendered as decimal)
  out=N        arg N is a pointer to an output buffer; capture its
               contents AFTER the function returns and log as a string
               (auto-decoded UTF-8 / GBK / latin-1)
  str=N        arg N is an in-memory C-string pointer; log as `str`
  wstr=N       arg N is an in-memory UTF-16-LE pointer; log as `str`
  hex=N        arg N is rendered as plain hex (for non-pointer scalars
               that don't fit `len=`)
  argc=N       force the displayed arg count if you don't want all 4

If no SPEC is provided, the hook logs the first 4 args as raw register
values — useful when you don't yet know the function's signature.

Args 0..3 map to RCX / RDX / R8 / R9 on x64 (Microsoft x64 ABI), and
to [esp+4] / [esp+8] / [esp+0xC] / [esp+0x10] on x86 (__stdcall /
__cdecl).

Output line format mimics ktrace's API-tracer format so the lines
interleave naturally in the .log:

  [caller_fn+0xNN]  internal.<name>(arg0=<…>, arg1=<…>) -> <ret if seen>

Example for PoisonX's xor_decrypt_string(src, len, dst):

  --trace-fn 0x1400013f8:xor_decrypt_string:in=0,len=1,out=2

Yields (after each call):

  [DriverEntry+0xc6] internal.xor_decrypt_string(
      in=4a23bd5e8c…(85 B),
      len=0x55,
      out='\\Device\\{F8284233-48F4-…}'
  ) -> 0x0
"""
from __future__ import annotations
import struct
import json


# Module-level state, populated by ktrace.main before run_module.
_TRACE_FN_STATE = {
    'specs': [],          # list of dict {addr, name, spec, return_hits}
    'log_func': None,     # ktrace's log() bound at install time
    'jsonl_fh': None,
    'arch_bits': 64,
    'resolve_addr': lambda a: f"0x{a:x}",
    # Per-PC pending-return-snapshot list. Keyed by return address
    # (= the PC of the caller's next instruction after our CALL).
    # value = {spec, captured_args, captured_out_addrs}
    'pending_returns': {},
}


def _decode_smart(b):
    """Try UTF-8 → GBK → latin-1 for log readability."""
    if not b:
        return ''
    if isinstance(b, bytearray):
        b = bytes(b)
    # Strip trailing NULs for display.
    nul = b.find(b'\x00')
    if nul >= 0:
        b = b[:nul]
    for enc in ('utf-8', 'gbk'):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            continue
    return b.decode('latin-1', errors='replace')


def _decode_smart_w(b):
    """Decode UTF-16-LE wide string up to first wchar NUL."""
    if not b:
        return ''
    if isinstance(b, bytearray):
        b = bytes(b)
    for k in range(0, len(b) - 1, 2):
        if b[k] == 0 and b[k+1] == 0:
            b = b[:k]
            break
    try:
        return b.decode('utf-16-le', errors='replace')
    except Exception:
        return ''


def _parse_spec(s: str) -> dict:
    """Parse `in=0,len=1,out=2` style key=value pairs."""
    out = {}
    if not s:
        return out
    for kv in s.split(','):
        if '=' not in kv:
            continue
        k, v = kv.split('=', 1)
        k = k.strip().lower()
        v = v.strip()
        try:
            n = int(v, 0)
        except ValueError:
            continue
        out[k] = n
    return out


def parse_trace_fn_arg(raw: str) -> dict:
    """Parse a single --trace-fn ARG into a dict.

    Forms accepted:
      ADDR
      ADDR:NAME
      ADDR:NAME:SPEC
    """
    parts = raw.split(':', 2)
    addr = int(parts[0], 0)
    name = parts[1] if len(parts) > 1 and parts[1] else f'fn_0x{addr:x}'
    spec = _parse_spec(parts[2]) if len(parts) > 2 else {}
    return {'addr': addr, 'name': name, 'spec': spec,
            'entry_hits': 0, 'return_hits': 0}


def _read_regs_args(emu_obj, arch_bits: int):
    """Return list of first-4 argv values from registers (x64) or stack (x86)."""
    if arch_bits == 64:
        return [emu_obj.reg_read(r) for r in ('rcx', 'rdx', 'r8', 'r9')]
    esp = emu_obj.reg_read('esp')
    args = []
    for i in range(4):
        try:
            args.append(struct.unpack(
                '<I', bytes(emu_obj.mem_read(esp + 4 + i * 4, 4)))[0])
        except Exception:
            args.append(0)
    return args


def _read_return_addr(emu_obj, arch_bits: int) -> int:
    """Read the call return address (= top-of-stack at function entry)."""
    if arch_bits == 64:
        rsp = emu_obj.reg_read('rsp')
        ptr_size = 8
    else:
        rsp = emu_obj.reg_read('esp')
        ptr_size = 4
    try:
        if arch_bits == 64:
            return struct.unpack('<Q',
                                 bytes(emu_obj.mem_read(rsp, 8)))[0]
        return struct.unpack('<I', bytes(emu_obj.mem_read(rsp, 4)))[0]
    except Exception:
        return 0


def _format_arg(emu_obj, idx: int, val: int, spec: dict, args: list,
                arch_bits: int) -> str:
    """Render one arg per the spec."""
    # in= → buffer (hex preview, length from len= or default 0x40)
    if spec.get('in') == idx:
        n = args[spec['len']] if 'len' in spec and spec['len'] < len(args) \
            else 0x40
        n = max(0, min(int(n) & 0xFFFFFFFF, 0x400))
        try:
            buf = bytes(emu_obj.mem_read(val, n))
            return f'in={buf.hex()}({n}B)'
        except Exception:
            return f'in=0x{val:x}(unread)'
    if spec.get('len') == idx:
        v = val & 0xFFFFFFFF
        return f'len=0x{v:x}'
    if spec.get('out') == idx:
        # Snapshot deferred to return; show the pointer for now.
        return f'out=0x{val:x}(pending)'
    if spec.get('wout') == idx:
        # Same as out= but the buffer holds UTF-16-LE wide chars.
        return f'wout=0x{val:x}(pending)'
    if spec.get('str') == idx:
        try:
            buf = bytes(emu_obj.mem_read(val, 0x400))
            return f'str={_decode_smart(buf)!r}'
        except Exception:
            return f'str=0x{val:x}'
    if spec.get('wstr') == idx:
        try:
            buf = bytes(emu_obj.mem_read(val, 0x800))
            return f'wstr={_decode_smart_w(buf)!r}'
        except Exception:
            return f'wstr=0x{val:x}'
    if spec.get('hex') == idx:
        return f'hex=0x{val:x}'
    # No semantic spec — render as plain hex.
    return f'arg{idx}=0x{val:x}'


def _install_one(emu, sp: dict, arch_bits: int, log_func, jsonl_fh,
                 resolve_addr):
    """Register the entry hook for one --trace-fn spec.

    Each entry hook is a fire-everywhere code hook that filters to its
    own ADDR via in-cb comparison (the same idiom shim_fake_driver
    uses for its stub-call detection)."""
    spec = sp['spec']
    addr = sp['addr']
    name = sp['name']
    argc_show = spec.get('argc', 4)

    def _emit_log(caller_pc: int, fields: list, ret_val=None):
        body = ', '.join(fields)
        ret_str = (f' -> 0x{ret_val & 0xFFFFFFFFFFFFFFFF:x}'
                   if ret_val is not None else '')
        call_site = resolve_addr(caller_pc)
        log_func(f'  [{call_site}]  internal.{name}({body}){ret_str}')
        if jsonl_fh is not None:
            try:
                jsonl_fh.write(json.dumps({
                    'phase': 'internal_fn',
                    'api': name,
                    'pc_name': call_site,
                    'pc': caller_pc,        # caller's CALL-site PC
                    'fn_addr': addr,        # callee entry (--trace-fn ADDR)
                    'fields': fields,
                    'ret': (f'0x{ret_val:x}' if ret_val is not None
                            else None),
                }) + '\n')
            except Exception:
                pass

    def _on_entry(emu_obj, pc, size, cb_ctx):
        if pc != addr:
            return
        try:
            sp['entry_hits'] += 1
            args = _read_regs_args(emu_obj, arch_bits)
            ret_addr = _read_return_addr(emu_obj, arch_bits)
            # Render the args we know NOW.
            shown = []
            for i in range(min(argc_show, len(args))):
                shown.append(_format_arg(emu_obj, i, args[i], spec,
                                         args, arch_bits))
            # If out=/wout= is in the spec, snapshot the buffer at return.
            # Capture the OUT pointer + length now; rendered later.
            out_idx = spec.get('out')
            wout_idx = spec.get('wout')
            chosen = out_idx if out_idx is not None else wout_idx
            wide = wout_idx is not None
            len_val = args[spec['len']] if 'len' in spec \
                and spec['len'] < len(args) else 0
            if chosen is not None and chosen < len(args):
                # Wide buffers are 2× the byte count of len= (which is
                # almost always the wchar count for wide encryptors).
                # Wide decryptors that interpret len as a byte count
                # should pass len through explicitly; we handle both
                # by reading the larger possible size.
                _TRACE_FN_STATE['pending_returns'][ret_addr] = {
                    'sp': sp,
                    'caller_pc': ret_addr - 5,  # est. CALL site
                    'shown': shown,
                    'out_addr': args[chosen],
                    'len': len_val & 0xFFFFFFFF,
                    'out_idx': chosen,
                    'wide': wide,
                }
            else:
                _emit_log(ret_addr - 5, shown)
        except Exception as e:
            try:
                log_func(f'  [trace-fn {name}] entry hook err: {e}')
            except Exception:
                pass

    def _on_return(emu_obj, pc, size, cb_ctx):
        pending = _TRACE_FN_STATE['pending_returns'].pop(pc, None)
        if pending is None:
            return
        try:
            out_addr = pending['out_addr']
            ln = max(1, min(pending['len'], 0x800))
            # For wide buffers `len` is usually wchar count; bump the
            # byte read accordingly. Keep capped at 0x1000 so we don't
            # read garbage past the allocation if the caller mis-stated.
            byte_count = ln * 2 if pending['wide'] else ln
            byte_count = min(byte_count, 0x1000)
            buf = bytes(emu_obj.mem_read(out_addr, byte_count)) \
                if out_addr else b''
            if pending['wide']:
                rendered = _decode_smart_w(buf)
            else:
                rendered = _decode_smart(buf)
            # Fallback: if the smart-decode collapsed to a tiny string
            # (e.g. the buffer has interleaved NULs from a doubled-up
            # encoding, or the first byte happens to be the only valid
            # one), also append a hex preview so the analyst can see
            # what really landed in the buffer.
            if len(rendered) < 4 and ln > 4:
                rendered = (f"{rendered!r} (raw hex {ln}B: "
                            f"{buf[:min(ln, 64)].hex()}"
                            f"{'…' if ln > 64 else ''})")
            shown = pending['shown']
            # Replace the pending placeholder with the rendered value.
            placeholder_prefix = ('wout=0x' if pending['wide']
                                  else 'out=0x')
            label = 'wout' if pending['wide'] else 'out'
            for i, f in enumerate(shown):
                if f.startswith(placeholder_prefix) and '(pending)' in f:
                    shown[i] = f"{label}={rendered!r}"
                    break
            ret_val = emu_obj.reg_read(
                'rax' if _TRACE_FN_STATE['arch_bits'] == 64 else 'eax')
            _emit_log(pending['caller_pc'], shown, ret_val)
        except Exception as e:
            try:
                log_func(f'  [trace-fn {sp["name"]}] return hook err: {e}')
            except Exception:
                pass

    # Both hooks are fire-everywhere — narrow ranges aren't reliable.
    # The PC comparison is cheap.
    emu.add_code_hook(_on_entry, begin=1, end=0)
    emu.add_code_hook(_on_return, begin=1, end=0)


def install_trace_fns(emu, arch_bits: int, specs: list, log_func,
                      jsonl_fh, resolve_addr):
    """Called by ktrace.main BEFORE run_module / first emu.call. Each
    spec is a dict produced by parse_trace_fn_arg()."""
    _TRACE_FN_STATE['specs'] = list(specs)
    _TRACE_FN_STATE['log_func'] = log_func
    _TRACE_FN_STATE['jsonl_fh'] = jsonl_fh
    _TRACE_FN_STATE['arch_bits'] = arch_bits
    _TRACE_FN_STATE['resolve_addr'] = resolve_addr
    _TRACE_FN_STATE['pending_returns'].clear()
    if not specs:
        return
    inner = getattr(emu, 'emu', None) or emu
    for sp in specs:
        try:
            _install_one(inner, sp, arch_bits, log_func, jsonl_fh,
                         resolve_addr)
        except Exception as e:
            try:
                log_func(f"# --trace-fn install for "
                         f"0x{sp['addr']:x} failed: {e}")
            except Exception:
                pass
    log_func(f"# --trace-fn: {len(specs)} internal "
             f"function hook(s) armed")
