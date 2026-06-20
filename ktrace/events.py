"""Trace-event emission for ktrace.

`Phaser` infers the current phase from API call patterns and prints
phase headers on transition.

`Tracer` consumes Speakeasy's API report incrementally, formats each
call through `decode.format_call`, applies run-length collapsing for
consecutive same-(PC, API, return) calls, and writes both a human-
readable log and a JSONL trace.
"""
from __future__ import annotations
import json

import decode


# All phases the Phaser can put us into. The order in the list defines
# the display order in the meta `phases_seen` field.
PHASES = [
    ('driver_init',          'Driver initialisation'),
    ('module_enumeration',   'Kernel module enumeration (NtQuerySystemInformation class 11)'),
    ('mdl_alias_setup',      'MDL alias setup (kernel R/W or page mapping)'),
    ('mdl_alias_teardown',   'MDL alias teardown'),
    ('object_allocation',    'Pool allocations'),
    ('device_name_build',    'Device-name string synthesis'),
    ('device_registration',  'Device + symbolic-link registration'),
    ('reinit_registration',  'Driver-reinitialisation registration'),
    ('file_io',              'File I/O via Zw* / Nt*'),
    ('registry_access',      'Registry access via Zw* / Nt*'),
    ('process_callbacks',    'Process/thread/image notify callbacks'),
    ('reinit_invocation',    'Driver-reinitialisation callback invocation'),
    ('irp_dispatch',         'Synthetic IRP dispatch'),
]
PHASE_DESC = dict(PHASES)


class Phaser:
    def __init__(self, log_fn):
        self.cur = None
        self._log = log_fn

    def classify(self, api_short, raw_args):
        a = raw_args if raw_args else []
        if api_short in ('NtQuerySystemInformation', 'ZwQuerySystemInformation'):
            c = decode.as_int(a[0]) if a else None
            if c == 0x0B:
                return 'module_enumeration'
        if api_short in ('IoAllocateMdl', 'MmProbeAndLockPages',
                         'MmMapLockedPagesSpecifyCache'):
            return 'mdl_alias_setup'
        if api_short in ('MmUnlockPages', 'IoFreeMdl'):
            return 'mdl_alias_teardown'
        if api_short in ('ExAllocatePoolWithTag', 'ExAllocatePool',
                         'ExAllocatePool2'):
            return 'object_allocation'
        if api_short in ('KeQuerySystemTime', '_alldvrm',
                         'ExSystemTimeToLocalTime'):
            return 'device_name_build'
        if api_short in ('IoCreateDevice', 'IoCreateSymbolicLink'):
            return 'device_registration'
        if api_short in ('IoRegisterDriverReinitialization',
                         'IoRegisterBootDriverReinitialization'):
            return 'reinit_registration'
        if api_short in ('ZwOpenFile', 'NtOpenFile', 'ZwCreateFile',
                         'NtCreateFile', 'ZwReadFile', 'NtReadFile',
                         'ZwWriteFile', 'NtWriteFile'):
            return 'file_io'
        if api_short in ('ZwOpenKey', 'NtOpenKey', 'ZwQueryValueKey',
                         'NtQueryValueKey', 'ZwSetValueKey', 'NtSetValueKey',
                         'ZwEnumerateKey', 'ZwEnumerateValueKey'):
            return 'registry_access'
        if api_short in ('PsSetCreateProcessNotifyRoutine',
                         'PsSetCreateProcessNotifyRoutineEx',
                         'PsSetCreateThreadNotifyRoutine',
                         'PsSetLoadImageNotifyRoutine'):
            return 'process_callbacks'
        return None

    def maybe_emit(self, api_short, raw_args):
        # Update the per-event phase classification (still surfaced in
        # .jsonl `phase` field and in meta `phases_seen`) but do NOT
        # interleave header lines in the human log — that re-orders
        # nothing semantically but makes execution order harder to read.
        new = self.classify(api_short, raw_args)
        if new is None or self.cur == new:
            return
        self.cur = new

    def force(self, name):
        self.cur = name


class Tracer:
    """One Tracer per ktrace run. Holds the run-length state, the
    cursor into Speakeasy's API report, and the per-driver summary
    counters.

    Use `replay_new(section=...)` to emit any APIs Speakeasy recorded
    since the last replay. Errors are deduplicated by entry-point so
    the same fault doesn't print under every IRP subsection.
    """
    def __init__(self, log_fn, jsonl_fh, summary, resolve_addr,
                 emu, arch_bits, iat_map=None):
        self._log = log_fn
        self._jsonl = jsonl_fh
        self.summary = summary
        self._resolve = resolve_addr
        self._emu = emu
        self._arch_bits = arch_bits
        # `{func_name_lower: dll_short}` from the driver's PE IAT.
        # When set, log lines show the import DLL the driver actually
        # depends on rather than whichever class Speakeasy routed the
        # call through. Speakeasy puts everything we apihook under
        # `ntoskrnl` regardless of where Windows actually exports it.
        self._iat_map = dict(iat_map or {})
        self.phaser = Phaser(log_fn)
        self._consumed = {}
        self._errors_reported = set()
        self._pending = {
            'sig': None, 'count': 0,
            'pc_int': 0, 'short': '', 'pc_name': '',
            'api_full': '', 'first_args': None, 'last_args': None,
            'ret_val': None, 'phase': None,
        }

    # ---- run-length collapse + emit ----
    def flush(self):
        p = self._pending
        if p['count'] == 0:
            return
        first_line = decode.format_call(
            p['api_full'], p['first_args'], p['ret_val'],
            resolve=self._resolve,
            emu=self._emu, arch_bits=self._arch_bits)
        if p['count'] > 1:
            last_line = decode.format_call(
                p['api_full'], p['last_args'], p['ret_val'],
                resolve=self._resolve,
                emu=self._emu, arch_bits=self._arch_bits)
            if last_line == first_line:
                self._log(f"  [{p['pc_name']}] {first_line}  × {p['count']}")
            else:
                self._log(f"  [{p['pc_name']}] {first_line}  × {p['count']}")
                self._log(f"    …last: {last_line}")
        else:
            self._log(f"  [{p['pc_name']}] {first_line}")
        self._jsonl.write(json.dumps({
            'phase': p['phase'], 'pc': p['pc_int'],
            'pc_name': p['pc_name'], 'api': p['short'],
            'args': [str(x) for x in (p['first_args'] or [])],
            'last_args': ([str(x) for x in (p['last_args'] or [])]
                          if p['count'] > 1 else None),
            'ret': str(p['ret_val']), 'decoded': first_line,
            'count': p['count'],
        }) + '\n')
        self._jsonl.flush()
        p['sig'] = None
        p['count'] = 0

    def emit(self, pc, api_full, raw_args, ret_val):
        short = api_full.split('.')[-1] if api_full else '?'
        # Rewrite the library prefix from the driver's actual IAT.
        # If the driver imports this function from, say, FLTMGR.SYS,
        # show `FLTMGR.FltRegisterFilter` even when Speakeasy routed
        # the apihook through its ntoskrnl class. Functions absent
        # from the IAT (e.g. MmGetSystemRoutineAddress lookups,
        # `_alldvrm` MSVC intrinsics) keep their Speakeasy prefix.
        if self._iat_map and short:
            dll = self._iat_map.get(short.lower())
            if dll:
                api_full = f"{dll}.{short}"
        pc_int = decode.as_int(pc) or 0
        sig = (pc_int, short, str(ret_val))
        new_phase = self.phaser.classify(short, raw_args)
        phase_change = (new_phase is not None and new_phase != self.phaser.cur)
        if phase_change or sig != self._pending['sig']:
            self.flush()
        self.phaser.maybe_emit(short, raw_args)
        if self.phaser.cur:
            self.summary['phases_seen'].add(self.phaser.cur)

        p = self._pending
        if p['sig'] == sig:
            p['count'] += 1
            p['last_args'] = raw_args
        else:
            p['sig'] = sig
            p['count'] = 1
            p['pc_int'] = pc_int
            p['short'] = short
            p['api_full'] = api_full
            p['first_args'] = raw_args
            p['last_args'] = raw_args
            p['ret_val'] = ret_val
            p['phase'] = self.phaser.cur
            p['pc_name'] = self._resolve(pc_int)

        self.summary['apis_total'] += 1
        self.summary['apis_by_name'][short] = (
            self.summary['apis_by_name'].get(short, 0) + 1)
        if short == 'ExAllocatePoolWithTag' and raw_args and len(raw_args) >= 3:
            tag = raw_args[2]
            if not isinstance(tag, str):
                tag = decode.fmt_pool_tag(tag).strip("'")
            sz = decode.as_int(raw_args[1]) or 0
            self.summary['pool_tags'][tag] = (
                self.summary['pool_tags'].get(tag, 0) + 1)
            self.summary['pool_tags_sizes'][tag] = (
                self.summary['pool_tags_sizes'].get(tag, 0) + sz)

        # Handle-to-name correlation: when an open succeeds, read the
        # OUT handle and the name (UNICODE_STRING inside OBJECT_ATTRIBUTES)
        # so subsequent calls referencing that handle can show the name.
        try:
            self._record_handle(short, raw_args, ret_val)
        except Exception:
            pass

    def _record_handle(self, short, raw_args, ret_val):
        """Stash {handle -> name} for opens that succeeded."""
        if not raw_args:
            return
        rn = decode.as_int(ret_val)
        if rn is not None and rn != 0:
            return  # only record successful opens
        opens_by_attr2 = {
            'ZwOpenKey', 'NtOpenKey', 'ZwCreateKey', 'NtCreateKey',
            'ZwOpenFile', 'NtOpenFile', 'ZwOpenSymbolicLinkObject',
            'NtOpenSymbolicLinkObject', 'ZwOpenDirectoryObject',
            'NtOpenDirectoryObject', 'ZwOpenSection', 'NtOpenSection',
        }
        opens_by_attr3 = {'ZwCreateFile', 'NtCreateFile'}
        attr_idx = None
        if short in opens_by_attr2:
            attr_idx = 2
        elif short in opens_by_attr3:
            attr_idx = 2  # OBJECT_ATTRIBUTES is also arg2 in NtCreateFile
        if attr_idx is None or len(raw_args) <= attr_idx:
            return

        # Handle pointer is arg 0. Read the qword/dword at that address
        # to recover the handle that was written out.
        try:
            ptr_size = 8 if self._arch_bits == 64 else 4
            buf = bytes(self._emu.mem_read(
                decode.as_int(raw_args[0]) or 0, ptr_size))
            import struct as _s
            h = _s.unpack('<Q' if ptr_size == 8 else '<I', buf)[0]
        except Exception:
            return
        if not h:
            return

        # Name was already decoded by format_call into raw_args[attr_idx]
        # if it's a string; otherwise dereference OBJECT_ATTRIBUTES.
        name_arg = raw_args[attr_idx]
        if isinstance(name_arg, str) and name_arg and not name_arg.startswith('0x'):
            decode.remember_handle(h, name_arg)
            return
        try:
            name = decode.read_object_attributes_name(
                self._emu, decode.as_int(name_arg) or 0,
                self._arch_bits)
            if name:
                decode.remember_handle(h, name)
        except Exception:
            pass

    # ---- consume Speakeasy's incrementally-growing report ----
    def replay_new(self, section=None):
        if section:
            self.flush()
            self._log('')
            self._log(f"--- {section}")
        report = self._emu.get_report()
        new_n = 0
        for ei, ent in enumerate(report.get('entry_points', [])):
            already = self._consumed.get(ei, 0)
            apis = ent.get('apis', [])
            for a in apis[already:]:
                self.emit(a.get('pc'), a.get('api_name', '?'),
                          a.get('args', []), a.get('ret_val', None))
                new_n += 1
            self._consumed[ei] = len(apis)
            err = ent.get('error', {})
            if err and ei not in self._errors_reported:
                self.flush()
                self._errors_reported.add(ei)
                api = err.get('api_name')
                desc = (f"pc={err.get('pc')}: {err.get('type')} "
                        f"on {err.get('instr', '?')}"
                        + (f" api={api}" if api else ''))
                self._log(f"  [emulator] {desc}")
                self.summary['errors'].append(desc)
                # Surface the Python-side traceback if Speakeasy captured
                # one. Most useful for "'NoneType' object has no attribute
                # 'to_bytes'"-class crashes inside our hook code where the
                # PC alone tells us nothing.
                tb = err.get('traceback') or ''
                if tb and ('to_bytes' in (err.get('type') or '')
                           or 'AttributeError' in tb
                           or 'TypeError' in tb):
                    for ln in tb.rstrip().splitlines():
                        self._log(f"  [emulator]   {ln}")
        self.flush()
        return new_n
