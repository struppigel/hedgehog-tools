"""Post-DriverEntry invocation helpers for ktrace.

These walk Speakeasy's API report to find what the driver *registered*
during DriverEntry — reinitialisation callbacks, process/thread/image
notify routines, ExRegisterCallback handlers, ObRegisterCallbacks pre/
post-op routines — and then synthesise calls to them so we observe
their behaviour too.

Also exposes `synth_irp_sequence` which fires CREATE / DEVICE_CONTROL
(with optional multi-input fuzz) / extra majors (PNP/POWER/SHUTDOWN/
QUERY_INFORMATION/SET_INFORMATION/CLEANUP) / CLOSE against the
captured `MajorFunction[]` handlers.
"""
from __future__ import annotations
import json
import struct

import decode
import irp


# Constants used when synthesising callback args. The fake-object page
# is mapped at 0x6f6b0000 ("foeb" / "fake") by shim.install_shim.
FAKE_OBJ = 0x6f6b0000
FAKE_PID = 0x1000
FAKE_TID = 0x2000


def _fake_proc_targets():
    """Return shim.EMU_OPTS['fake_processes'] as a list of (pid, name)."""
    try:
        import shim
        return list(shim.EMU_OPTS.get('fake_processes') or [])
    except Exception:
        return []


def _fake_create_info(emu, arch_bits, targets):
    """For each (pid, name) target, allocate:
      - a fake EPROCESS pointer (reusing shim's _state_fp.eproc_by_pid map
        which is populated lazily; we trigger that here)
      - a PS_CREATE_NOTIFY_INFO blob with:
          +Size, +Flags
          +ParentProcessId (HANDLE)
          +CreatingThreadId (CLIENT_ID)
          +FileObject (PVOID)
          +ImageFileName (PCUNICODE_STRING — we set this so the driver's
                          hit-list check sees the AV name)
          +CommandLine
          +IsSubsystemProcess
          +CreationStatus  (driver writes STATUS_ACCESS_DENIED here to deny)
    Yields (pid, name, eproc, info_blob_addr).
    """
    import shim
    from speakeasy.common import PERM_MEM_RWX
    ptr_size = 8 if arch_bits == 64 else 4
    fmt = '<Q' if arch_bits == 64 else '<I'
    # Trigger the lazy table by calling shim's PsLookupProcessByProcessId
    # path. Easier: directly populate from shim state.
    fp_state = shim.install_shim.__globals__.get(  # type: ignore
        'state', None)
    # Use shim.EMU_OPTS['fake_processes'] order to assign eprocs the same
    # way shim does (0x6f6d0000 + 0x100*(idx+1)).
    fakes = shim.EMU_OPTS.get('fake_processes') or []
    eproc_by_pid = {pid: 0x6f6d0000 + 0x100 * (idx + 1)
                    for idx, (pid, _) in enumerate(fakes)}

    out = []
    for pid, name in targets:
        eproc = eproc_by_pid.get(pid, FAKE_OBJ)
        # Backing wide string for the image name (UNICODE_STRING content).
        wname = f'\\Device\\HarddiskVolume1\\Windows\\System32\\{name}'.encode(
            'utf-16-le')
        ustr_size = 16 if arch_bits == 64 else 8
        info_size = 0x80
        # Single allocation: UNICODE_STRING header + string buffer + INFO.
        total = ustr_size + len(wname) + 2 + info_size
        try:
            base = emu.emu.mem_map(total, base=None,
                                   tag='ktrace.psnotify_info',
                                   perms=PERM_MEM_RWX)
        except Exception:
            continue
        ustr_addr = base
        str_addr = base + ustr_size
        info_addr = base + ustr_size + len(wname) + 2
        import struct as _s
        # UNICODE_STRING { Length, Max, [pad,] Buffer }
        emu.mem_write(ustr_addr,
                      _s.pack('<H', len(wname)) +
                      _s.pack('<H', len(wname) + 2) +
                      (b'\x00\x00\x00\x00' if arch_bits == 64 else b'') +
                      _s.pack(fmt, str_addr))
        emu.mem_write(str_addr, wname + b'\x00\x00')
        # PS_CREATE_NOTIFY_INFO layout (x64, simplified):
        #   +0x00 SIZE_T Size
        #   +0x08 ULONG Flags
        #   +0x10 HANDLE ParentProcessId
        #   +0x18 CLIENT_ID CreatingThreadId
        #   +0x28 PFILE_OBJECT FileObject
        #   +0x30 PCUNICODE_STRING ImageFileName   <-- driver reads this
        #   +0x38 PCUNICODE_STRING CommandLine
        #   +0x40 NTSTATUS CreationStatus          <-- driver WRITES this
        info = bytearray(info_size)
        if arch_bits == 64:
            _s.pack_into('<Q', info, 0x00, info_size)
            _s.pack_into('<Q', info, 0x10, max(pid - 1, 0))  # parent pid
            _s.pack_into('<Q', info, 0x30, ustr_addr)        # ImageFileName
        else:
            _s.pack_into('<I', info, 0x00, info_size)
            _s.pack_into('<I', info, 0x0c, max(pid - 1, 0))
            _s.pack_into('<I', info, 0x18, ustr_addr)
        emu.mem_write(info_addr, bytes(info))
        out.append((pid, name, eproc, info_addr))
    return out


def _fake_unicode_string(emu, arch_bits, s, perm_rwx):
    """Allocate a UNICODE_STRING + backing buffer; return the UNICODE_STRING
    address. Caller passes Speakeasy's `PERM_MEM_RWX` constant."""
    try:
        wstr = s.encode('utf-16-le')
        base = emu.emu.mem_map(0x200, base=None,
                               tag='ktrace.fake_ustr', perms=perm_rwx)
        emu.mem_write(base, b'\x00' * 0x200)
        buf_addr = base + 0x20
        emu.mem_write(buf_addr, wstr)
        if arch_bits == 64:
            emu.mem_write(base, struct.pack(
                '<HHIQ', len(wstr), len(wstr) + 2, 0, buf_addr))
        else:
            emu.mem_write(base, struct.pack(
                '<HHI', len(wstr), len(wstr) + 2, buf_addr))
        return base
    except Exception:
        return 0


def discover_reinit_calls(emu):
    """Return list of (fn_addr, ctx) tuples from IoRegisterDriver*Reinit*."""
    out = []
    for ent in emu.get_report().get('entry_points', []):
        for a in ent.get('apis', []):
            if a.get('api_name', '').endswith('DriverReinitialization'):
                argv = a.get('args', [])
                try:
                    fn = decode.as_int(argv[1])
                    ctx = decode.as_int(argv[2])
                    if fn:
                        out.append((fn, ctx or 0))
                except Exception:
                    pass
    return out


def discover_callbacks(emu, arch_bits):
    """Return list of (kind, fn, [args]) tuples for all callbacks the
    driver registered during DriverEntry. The arg shapes match each
    callback's documented signature so the invoked code gets sensible
    inputs."""
    out = []

    # UNICODE_STRING for "fake.sys" — allocated lazily because we need
    # PERM_MEM_RWX from Speakeasy.
    from speakeasy.common import PERM_MEM_RWX
    fake_ustr = None
    def ustr_lazy():
        nonlocal fake_ustr
        if fake_ustr is None:
            fake_ustr = _fake_unicode_string(
                emu, arch_bits, '\\Driver\\fake.sys', PERM_MEM_RWX)
        return fake_ustr or FAKE_OBJ

    for ent in emu.get_report().get('entry_points', []):
        for a in ent.get('apis', []):
            nm = (a.get('api_name') or '').split('.')[-1]
            argv = a.get('args', []) or []
            try:
                if nm == 'PsSetCreateProcessNotifyRoutine':
                    fn = decode.as_int(argv[0])
                    if fn:
                        # Fire once per fake AV process when set, else
                        # one synthetic placeholder call.
                        targets = _fake_proc_targets() or [(FAKE_PID, 'fake')]
                        for pid, name in targets:
                            out.append((f'ProcessNotify({name})', fn,
                                        [pid - 1, pid, 1]))
                elif nm == 'PsSetCreateProcessNotifyRoutineEx':
                    fn = decode.as_int(argv[0])
                    if fn:
                        targets = _fake_proc_targets()
                        if targets:
                            # For each fake AV process, build a
                            # PS_CREATE_NOTIFY_INFO blob with the
                            # ImageFileName set so the driver's hit-list
                            # check succeeds and the trace shows the
                            # CreationStatus deny (= AV blocked).
                            for pid, name, eproc, info_blob in _fake_create_info(
                                    emu, arch_bits, targets):
                                out.append((f'ProcessNotifyEx({name})', fn,
                                            [eproc, pid, info_blob]))
                        else:
                            out.append(('ProcessNotifyEx', fn,
                                        [FAKE_OBJ, FAKE_PID, FAKE_OBJ]))
                elif nm == 'PsSetCreateProcessNotifyRoutineEx2':
                    fn = decode.as_int(argv[1])
                    if fn:
                        targets = _fake_proc_targets()
                        if targets:
                            for pid, name, eproc, info_blob in _fake_create_info(
                                    emu, arch_bits, targets):
                                out.append((f'ProcessNotifyEx2({name})', fn,
                                            [eproc, pid, info_blob]))
                        else:
                            out.append(('ProcessNotifyEx2', fn,
                                        [FAKE_OBJ, FAKE_PID, FAKE_OBJ]))
                elif nm == 'PsSetCreateThreadNotifyRoutine':
                    fn = decode.as_int(argv[0])
                    if fn:
                        out.append(('ThreadNotify', fn,
                                    [FAKE_PID, FAKE_TID, 1]))
                elif nm == 'PsSetCreateThreadNotifyRoutineEx':
                    fn = decode.as_int(argv[1])
                    if fn:
                        out.append(('ThreadNotifyEx', fn,
                                    [FAKE_PID, FAKE_TID, 1]))
                elif nm in ('FwpsCalloutRegister0',
                            'FwpsCalloutRegister1',
                            'FwpsCalloutRegister2'):
                    # NTSTATUS FwpsCalloutRegister[012](
                    #   PDEVICE_OBJECT deviceObject,   ; argv[0]
                    #   const FWPS_CALLOUT* callout,   ; argv[1]
                    #   UINT32* calloutId)             ; argv[2]
                    #
                    # FWPS_CALLOUT0 layout (x64):
                    #   +0x00 GUID  calloutKey            (16 bytes)
                    #   +0x10 UINT32 flags
                    #   +0x18 PFN classifyFn  ← the packet processor
                    #   +0x20 PFN notifyFn    ← filter add/remove notifications
                    #   +0x28 PFN flowDeleteFn
                    # The 1/2 variants add fields after but keep the same
                    # initial three callback offsets, so the read works
                    # for all three.
                    callout_ptr = decode.as_int(argv[1]) if len(argv) > 1 \
                        else 0
                    if not callout_ptr:
                        continue
                    try:
                        ptr_size = 8 if arch_bits == 64 else 4
                        fmt = '<Q' if ptr_size == 8 else '<I'
                        import struct as _s
                        blob = bytes(emu.mem_read(callout_ptr + 0x18,
                                                  3 * ptr_size))
                        classify_fn = _s.unpack(fmt, blob[0:ptr_size])[0]
                        notify_fn   = _s.unpack(
                            fmt, blob[ptr_size:2*ptr_size])[0]
                    except Exception:
                        continue
                    # Classify callback — the actual per-packet hook. We
                    # invoke at FWPS_LAYER_INBOUND_TRANSPORT_V4 (the
                    # common redirect / firewall layer). All args point
                    # at FAKE_OBJ pages which are RWX-mapped, so the
                    # callback's reads + writes to classifyOut succeed.
                    #
                    # VOID classifyFn(
                    #   const FWPS_INCOMING_VALUES0*  inFixedValues,  ; argv[0]
                    #   const FWPS_INCOMING_METADATA* inMetaValues,   ; argv[1]
                    #   VOID*                         layerData,      ; argv[2]
                    #   const FWPS_FILTER0*           filter,         ; argv[3]
                    #   UINT64                        flowContext,    ; argv[4]
                    #   FWPS_CLASSIFY_OUT0*           classifyOut)    ; argv[5]
                    if classify_fn:
                        out.append(
                            (f'FwpsCallout-classify', classify_fn,
                             [FAKE_OBJ, FAKE_OBJ, FAKE_OBJ,
                              FAKE_OBJ, 0, FAKE_OBJ]))
                    # Notify callback — fired by WFP on filter add/remove.
                    # NTSTATUS notifyFn(
                    #   FWPS_CALLOUT_NOTIFY_TYPE notifyType,  ; argv[0]
                    #   const GUID*               filterKey,  ; argv[1]
                    #   const FWPS_FILTER0*       filter)     ; argv[2]
                    # notifyType=1 is FWPS_CALLOUT_NOTIFY_ADD_FILTER —
                    # the "you just got attached" event the driver uses
                    # to finalise its per-filter state.
                    if notify_fn:
                        out.append(
                            (f'FwpsCallout-notify(add)', notify_fn,
                             [1, FAKE_OBJ, FAKE_OBJ]))
                elif nm == 'KeRegisterBugCheckCallback':
                    # NTSTATUS KeRegisterBugCheckCallback(
                    #   PKBUGCHECK_CALLBACK_RECORD CallbackRecord,
                    #   PKBUGCHECK_CALLBACK_ROUTINE CallbackRoutine,  ; argv[1]
                    #   PVOID Buffer,                                   ; argv[2]
                    #   ULONG Length,                                   ; argv[3]
                    #   PUCHAR Component)                               ; argv[4]
                    # The routine signature is:
                    #   VOID (*)(PVOID Buffer, ULONG Length)
                    fn = decode.as_int(argv[1]) if len(argv) > 1 else 0
                    if fn:
                        buf = decode.as_int(argv[2]) if len(argv) > 2 \
                            else FAKE_OBJ
                        length = decode.as_int(argv[3]) if len(argv) > 3 \
                            else 0
                        out.append(('BugCheckCallback', fn,
                                    [buf or FAKE_OBJ, length or 0x100]))
                elif nm == 'KeRegisterBugCheckReasonCallback':
                    # NTSTATUS KeRegisterBugCheckReasonCallback(
                    #   PKBUGCHECK_REASON_CALLBACK_RECORD Record,
                    #   PKBUGCHECK_REASON_CALLBACK_ROUTINE CallbackRoutine, ; argv[1]
                    #   KBUGCHECK_CALLBACK_REASON Reason,                   ; argv[2]
                    #   PUCHAR Component)                                   ; argv[3]
                    # Routine signature:
                    #   VOID (*)(KBUGCHECK_CALLBACK_REASON Reason,
                    #            PKBUGCHECK_REASON_CALLBACK_RECORD Record,
                    #            PVOID ReasonSpecificData,
                    #            ULONG ReasonSpecificDataLength)
                    # We invoke with each known reason code so per-reason
                    # branches in the body (anti-forensic scrubbers /
                    # core-dump filters that EDR products commonly park
                    # here) execute.
                    fn = decode.as_int(argv[1]) if len(argv) > 1 else 0
                    if fn:
                        # Reason codes from wdm.h:
                        #   KbCallbackInvalid           = 0
                        #   KbCallbackReserved1         = 1
                        #   KbCallbackSecondaryDumpData = 2
                        #   KbCallbackDumpIo            = 3
                        #   KbCallbackAddPages          = 4
                        for reason in (2, 3, 4):
                            out.append(
                                (f'BugCheckReason(reason={reason})', fn,
                                 [reason, FAKE_OBJ, FAKE_OBJ, 0x100]))
                elif nm == 'PsSetLoadImageNotifyRoutine':
                    fn = decode.as_int(argv[0])
                    if fn:
                        out.append(('LoadImageNotify', fn,
                                    [ustr_lazy(), FAKE_PID, FAKE_OBJ]))
                elif nm == 'PsSetLoadImageNotifyRoutineEx':
                    # WDK signature: PsSetLoadImageNotifyRoutineEx(
                    #     PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine,
                    #     ULONG_PTR Flags )
                    # Function pointer is arg 0, Flags is arg 1 — earlier
                    # code read argv[1] which is the Flags value, so the
                    # callback was either NULL-dispatched (Flags=0) or
                    # called at a bogus low address (Flags=1, the
                    # CONFLICTING_ARCHITECTURE bit). The real notify
                    # routine never ran.
                    fn = decode.as_int(argv[0])
                    if fn:
                        out.append(('LoadImageNotifyEx', fn,
                                    [ustr_lazy(), FAKE_PID, FAKE_OBJ]))
                elif nm in ('CmRegisterCallback', 'CmRegisterCallbackEx'):
                    # NTSTATUS CmRegisterCallback[Ex](
                    #   PEX_CALLBACK_FUNCTION Function,  ; arg 0
                    #   ... )                            ; arg 0 in both flavours
                    fn = decode.as_int(argv[0])
                    if not fn:
                        continue
                    # For each REG_NOTIFY_CLASS value the driver might
                    # handle, fire the callback with synthesised pre/post
                    # information structures so the per-class handlers
                    # (FUN_1400208b0 / FUN_140020a90 / ... in d14, and
                    # equivalents in every other registry-filter driver)
                    # actually execute and surface in the trace.
                    #
                    # CmRegisterCallback signature:
                    #   NTSTATUS (*)(PVOID CallbackContext,
                    #                PVOID NotifyClass,         // ULONG_PTR
                    #                PVOID Argument2);          // class-dependent struct
                    # We pass our fake-obj page for the third arg —
                    # the driver may read a couple of fields off of
                    # it but the page is mapped RWX so reads succeed
                    # and write-backs are absorbed.
                    for cls in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
                                10, 11, 0x1A, 0x1B):
                        out.append(
                            (f'CmCallback(class=0x{cls:x})', fn,
                             [FAKE_OBJ, cls, FAKE_OBJ]))
                elif nm == 'PsCreateSystemThread':
                    # NTSTATUS PsCreateSystemThread(
                    #   PHANDLE ThreadHandle,           ; argv[0]
                    #   ULONG DesiredAccess,            ; argv[1]
                    #   POBJECT_ATTRIBUTES ObjAttrs,    ; argv[2]
                    #   HANDLE ProcessHandle,           ; argv[3]
                    #   PCLIENT_ID ClientId,            ; argv[4]
                    #   PKSTART_ROUTINE StartRoutine,   ; argv[5]
                    #   PVOID StartContext);            ; argv[6]
                    fn = decode.as_int(argv[5]) if len(argv) > 5 else 0
                    if not fn:
                        continue
                    ctx_arg = decode.as_int(argv[6]) if len(argv) > 6 else 0
                    # Many drivers defer "real work" to a system thread so
                    # DriverEntry can return quickly. Invoking the thread
                    # start routine surfaces that work AND often toggles
                    # internal "ready" / "running" state flags that gate
                    # the other callbacks (e.g. d14's WFP-arming worker
                    # sets a global cRam_…3f2f flag without which the
                    # registry-filter callback body short-circuits).
                    out.append(
                        ('SystemThread', fn,
                         [ctx_arg if ctx_arg else FAKE_OBJ]))
                elif nm == 'ObRegisterCallbacks':
                    reg = decode.as_int(argv[0])
                    if not reg:
                        continue
                    if arch_bits == 64:
                        hdr = bytes(emu.mem_read(reg, 0x28))
                        op_count = struct.unpack('<H', hdr[2:4])[0]
                        op_arr = struct.unpack('<Q', hdr[0x20:0x28])[0]
                        op_size = 0x28
                    else:
                        hdr = bytes(emu.mem_read(reg, 0x1c))
                        op_count = struct.unpack('<H', hdr[2:4])[0]
                        op_arr = struct.unpack('<I', hdr[0x18:0x1c])[0]
                        op_size = 0x14
                    if op_count == 0 or op_count > 16 or not op_arr:
                        continue
                    for i in range(min(op_count, 8)):
                        op = bytes(emu.mem_read(op_arr + i * op_size, op_size))
                        if arch_bits == 64:
                            pre = struct.unpack('<Q', op[0x10:0x18])[0]
                            post = struct.unpack('<Q', op[0x18:0x20])[0]
                        else:
                            pre = struct.unpack('<I', op[0x0c:0x10])[0]
                            post = struct.unpack('<I', op[0x10:0x14])[0]
                        if pre:
                            out.append(
                                ('ObPreOp', pre, [FAKE_OBJ, FAKE_OBJ]))
                        if post:
                            out.append(
                                ('ObPostOp', post, [FAKE_OBJ, FAKE_OBJ]))
            except Exception:
                pass
    # Reorder so SystemThread invocations run first — many drivers defer
    # state-flag setup to the worker, and those flags gate downstream
    # callback bodies. Stable sort preserves relative order otherwise.
    out.sort(key=lambda x: 0 if x[0] == 'SystemThread' else 1)
    return out


def invoke_reinit(emu, tracer, drvobj_ptr, log_fn, resolve_addr):
    """Invoke each registered IoRegisterDriverReinitialization callback."""
    if not drvobj_ptr:
        return 0
    calls = discover_reinit_calls(emu)
    if not calls:
        return 0
    import shim
    tracer.phaser.force('reinit_invocation')
    for fn, ctx in calls:
        if getattr(shim, '_watchdog_expired', lambda: False)():
            log_fn("  (skipping remaining reinit calls — watchdog expired)")
            break
        if not getattr(shim, '_rearm_watchdog', lambda: True)():
            break
        log_fn(f"  Invoking reinit 0x{fn:x} ({resolve_addr(fn)})")
        try:
            emu.call(fn, [drvobj_ptr, ctx, 1])
        except Exception as e:
            log_fn(f"    reinit error: {e}")
        tracer.replay_new(section=f"APIs called inside reinit 0x{fn:x}:")
    return len(calls)


def invoke_callbacks(emu, tracer, drvobj_ptr, arch_bits, log_fn, resolve_addr,
                     max_invocations=20):
    """Invoke all registered Ps*NotifyRoutine + ExRegisterCallback +
    CmRegisterCallback + ObRegisterCallbacks handlers found in the API
    report."""
    if not drvobj_ptr:
        return 0
    cbs = discover_callbacks(emu, arch_bits)
    if not cbs:
        return 0
    tracer.phaser.force('reinit_invocation')  # reuse the phase label
    log_fn('')
    log_fn(f"# Invoking {len(cbs)} registered callbacks:")
    import shim
    for kind, fn, call_args in cbs[:max_invocations]:
        if getattr(shim, '_watchdog_expired', lambda: False)():
            # SystemThread is special: drivers commonly defer payload
            # unpacking / "init-complete" flag-set to a worker, then poll
            # for it inside DriverEntry. If the poll loop burned the
            # initial wall budget, we still want the unpacker thread to
            # run — its side effects show up in the memdump and surface
            # the real behaviour. Grant a one-shot extension; per-cb
            # 5s Timer below still caps a runaway thread.
            if (kind == 'SystemThread' and
                    getattr(shim, '_extend_watchdog', lambda _x: False)(8)):
                log_fn(f"  watchdog expired; extending +8s for "
                       f"deferred SystemThread (unpacker / init-flag)")
            else:
                log_fn(f"  (skipping remaining {len(cbs) - cbs.index((kind, fn, call_args))} "
                       f"callbacks — watchdog expired)")
                break
        # Re-arm SIGALRM to the remaining wall budget so an infinite
        # loop inside this callback gets stopped (threading.Timer
        # below doesn't share the GIL with unicorn and is ineffective).
        if not getattr(shim, '_rearm_watchdog', lambda: True)():
            break
        log_fn(f"  -> {kind} 0x{fn:x} ({resolve_addr(fn)}) "
               f"args={[hex(a) for a in call_args]}")
        # For ProcessNotify-family callbacks, the driver typically
        # calls PsGetCurrentProcessId() to identify the requestor.
        # We override that to return the synthesised process's PID so
        # the driver's hit-list match sees the right name.
        pid_override = None
        if kind.startswith('ProcessNotify'):
            if len(call_args) >= 2:
                pid_override = call_args[1]
        # Per-callback watchdog (threading.Timer — doesn't share the
        # SIGALRM channel with ktrace.py's global watchdog). Kernel
        # workers very commonly loop forever (`do { Wait; } while
        # (true)` — d15 JKDriver, d14 SafeCenter both do this); a
        # single infinite-loop callback would burn the entire wall
        # budget otherwise. SystemThread invocations get 5s; other
        # callbacks 2s. Legitimate bodies run well under 100ms.
        import threading as _thr

        def _per_cb_watchdog_stop():
            try:
                emu.emu.emu_eng.stop()
            except Exception:
                pass
        cap_sec = 5 if kind == 'SystemThread' else 2
        _wd_timer = _thr.Timer(cap_sec, _per_cb_watchdog_stop)
        _wd_timer.daemon = True

        try:
            shim.set_current_pid_override(pid_override)
            # Callbacks were registered to fire on user-mode triggered
            # events. Reporting PreviousMode=UserMode lets bodies past
            # their "skip kernel-mode" gate.
            shim.set_previous_mode_override(1)  # UserMode
            _wd_timer.start()
            try:
                # Speakeasy quirk: emu.call(addr, params) only triggers
                # start() when run_queue is empty. After a watchdog-
                # interrupted DriverEntry the queue still has the threads
                # PsCreateSystemThread queued via create_thread, so our
                # new run lands BEHIND them and never executes. discover_
                # callbacks() already harvests those same start routines
                # as 'SystemThread' cbs, so drop the queued duplicates
                # before scheduling our own — keeps the per-cb Timer cap
                # in force for everything we actually run.
                try:
                    emu.emu.run_queue.clear()
                except Exception:
                    pass
                emu.call(fn, call_args)
            finally:
                _wd_timer.cancel()
        except Exception as e:
            log_fn(f"     callback error: {e}")
        finally:
            shim.set_current_pid_override(None)
            shim.set_previous_mode_override(None)
        tracer.replay_new(section=f"APIs inside {kind} callback 0x{fn:x}:")

        # If this was a ProcessNotifyEx/Ex2 invocation with a
        # PS_CREATE_NOTIFY_INFO blob, peek at CreationStatus
        # (+0x40 x64 / +0x24 x86) to detect "spawn denied" decisions.
        if (kind.startswith('ProcessNotifyEx')
                and len(call_args) >= 3 and call_args[2]):
            try:
                cs_off = 0x40 if arch_bits == 64 else 0x24
                cs_bytes = bytes(emu.mem_read(call_args[2] + cs_off, 4))
                cs = int.from_bytes(cs_bytes, 'little')
                if cs:
                    sym = decode.fmt_status(cs)
                    log_fn(f"  !! {kind} wrote CreationStatus=0x{cs:08x} "
                           f"({sym}) — AV process spawn BLOCKED")
            except Exception:
                pass
    return len(cbs)


def synth_irp_sequence(emu, tracer, jsonl_fh, log_fn, resolve_addr,
                       arch_bits, mf_table, devobj,
                       ioctls, ioctl_input,
                       ioctl_fuzz=True, more_irps=True, no_irp=False,
                       device_label=''):
    """Fire the IRP repertoire (CREATE → IOCTLs → extras → CLOSE) and
    replay the dispatcher's internal API calls between each."""
    dispatcher_devctl = mf_table.get(0x0E)
    dispatcher_create = mf_table.get(0x00)
    dispatcher_close = mf_table.get(0x02)
    dispatcher_intern = mf_table.get(0x0F)
    if no_irp:
        log_fn("# IRP synthesis disabled.")
        return
    if not dispatcher_devctl:
        log_fn('')
        log_fn("# No IRP_MJ_DEVICE_CONTROL dispatcher captured.")
        return
    import shim as _shim
    if getattr(_shim, '_watchdog_expired', lambda: False)():
        log_fn("# IRP synthesis skipped — watchdog expired")
        return
    if not getattr(_shim, '_rearm_watchdog', lambda: True)():
        return
    tracer.phaser.force('irp_dispatch')
    tag_prefix = f"[{device_label}] " if device_label else ''
    log_fn('')
    log_fn(f"--- {tag_prefix}DeviceObject = 0x{devobj:x}")

    if dispatcher_create:
        log_fn(f"  Firing IRP_MJ_CREATE on 0x{dispatcher_create:x} "
               f"({resolve_addr(dispatcher_create)}) ...")
        s, info, _ = irp.synth_irp(emu, dispatcher_create, arch_bits,
                                   0x00, devobj, file_obj=0)
        if s is not None:
            log_fn(f"    -> status={decode.fmt_status(s)} Information={info}")
        tracer.replay_new(section="APIs inside IRP_MJ_CREATE handler:")

    log_fn(f"  DEVICE_CONTROL dispatcher = 0x{dispatcher_devctl:x} "
           f"({resolve_addr(dispatcher_devctl)})")
    log_fn(f"  DeviceObject = 0x{devobj:x}")

    if ioctl_input:
        fuzz_inputs = [ioctl_input]
        is_fuzz = False
        mode_label = f'user-supplied ({len(ioctl_input)}B)'
        per_call_tag = 'user-buf'
    elif ioctl_fuzz:
        # Sizes are roughly powers of 2 from "empty" to "rule-sized".
        # 0x2000 (8 KB) covers length-gated IOCTLs whose handlers
        # require ≥ a full per-rule struct (d3 / d11 FileProtection
        # demand 0x1400; many AV-style filter drivers want similar
        # 4-8 KB inputs). Without this bucket their dispatchers bail
        # with STATUS_BUFFER_TOO_SMALL on every probe.
        fuzz_inputs = [b'', b'\x00' * 4, b'\x00' * 16, b'\x00' * 64,
                       b'\x00' * 256, b'\x00' * 0x2000]
        is_fuzz = True
        mode_label = 'zero-filled fuzz'
        per_call_tag = 'fuzz'
    else:
        # --no-ioctl-fuzz: single empty-buffer probe per IOCTL. Not
        # fuzzing — just exercising each dispatcher entrypoint once.
        fuzz_inputs = [b'']
        is_fuzz = False
        mode_label = 'single empty-buffer probe'
        per_call_tag = 'probe'

    if not ioctls:
        log_fn(
            "  # IOCTL discovery returned 0 codes. Dispatcher exists at "
            f"0x{dispatcher_devctl:x} but no `cmp <reg>, IMM` patterns "
            "were found in linear-sweep disasm — codes may live in "
            "virtualized/encrypted code (custom .vmpN/.borat/etc. sections), "
            "or be loaded from .data at runtime. Supply --ioctl <CODE> "
            "to probe a specific value; without it, the dispatcher only "
            "sees IRP_MJ_DEVICE_CONTROL with an unknown IOCTL.")
    elif is_fuzz:
        sizes = '/'.join(str(len(b)) for b in fuzz_inputs) + ' bytes'
        log_fn(f"  # IOCTL fuzz: {len(ioctls)} code(s) × "
               f"{len(fuzz_inputs)} input size(s) "
               f"({mode_label}, sizes {sizes}). "
               f"Each `STATUS_BUFFER_TOO_SMALL` below is the driver "
               f"rejecting our probe size, not a ktrace error — "
               f"supply --ioctl-input HEX to control the buffer.")
    else:
        log_fn(f"  # IOCTL probe ({mode_label}): "
               f"{len(ioctls)} code(s), 1 buffer each.")
    for code in ioctls:
        verb = 'Fuzzing' if is_fuzz else 'Firing'
        log_fn(f"  [{per_call_tag}] {verb} {decode.fmt_ioctl(code)} "
               f"(0x{code:08X}) "
               f"with {len(fuzz_inputs)} synthetic buffer(s) ...")
        for buf in fuzz_inputs:
            tag = f"{per_call_tag} in={len(buf)}B"
            s, info, out = irp.synth_irp(
                emu, dispatcher_devctl, arch_bits, 0x0E, devobj,
                ioctl_code=code, output_len=4, input_buf=buf)
            if s is None:
                log_fn(f"    [{tag}]  (no result)")
                continue
            hexdump = out[:max(info, 4)].hex()
            le32 = (struct.unpack('<I', out[:4])[0]
                    if len(out) >= 4 else None)
            log_fn(f"    [{tag}]  status={decode.fmt_status(s)}, "
                   f"Information={info}, "
                   f"SystemBuffer[:{max(info,4)}]={hexdump}"
                   + (f" (LE u32 = 0x{le32:x})" if le32 is not None else ''))
            jsonl_fh.write(json.dumps({
                'phase': 'irp_dispatch',
                'ioctl': code, 'ioctl_decoded': decode.fmt_ioctl(code),
                'input_len': len(buf), 'mode': mode_label,
                'status': decode.fmt_status(s),
                'information': info, 'output_hex': hexdump,
            }) + '\n')
            sect_verb = 'fuzz IOCTL' if is_fuzz else 'IOCTL'
            tracer.replay_new(
                section=f"APIs inside {sect_verb} 0x{code:08X} ({tag}):")
        if more_irps and dispatcher_intern and dispatcher_intern != dispatcher_devctl:
            log_fn(f"    [INTERNAL] firing same IOCTL via "
                   f"IRP_MJ_INTERNAL_DEVICE_CONTROL @ 0x{dispatcher_intern:x}")
            s, info, _ = irp.synth_irp(
                emu, dispatcher_intern, arch_bits, 0x0F, devobj,
                ioctl_code=code, output_len=4, input_buf=b'')
            if s is not None:
                log_fn(f"      -> status={decode.fmt_status(s)} "
                       f"Information={info}")
            tracer.replay_new(
                section=f"APIs inside INTERNAL_IOCTL 0x{code:08X}:")

    if more_irps:
        for mj, label in ((0x1B, 'PNP'),
                          (0x16, 'POWER'),
                          (0x10, 'SHUTDOWN'),
                          (0x05, 'QUERY_INFORMATION'),
                          (0x06, 'SET_INFORMATION'),
                          (0x12, 'CLEANUP')):
            disp = mf_table.get(mj)
            if not disp:
                continue
            log_fn(f"  Firing IRP_MJ_{label} on 0x{disp:x} "
                   f"({resolve_addr(disp)}) ...")
            s, info, _ = irp.synth_irp(emu, disp, arch_bits, mj, devobj,
                                       file_obj=0)
            if s is not None:
                log_fn(f"    -> status={decode.fmt_status(s)} "
                       f"Information={info}")
            tracer.replay_new(
                section=f"APIs inside IRP_MJ_{label} handler:")

    if dispatcher_close:
        log_fn(f"  Firing IRP_MJ_CLOSE on 0x{dispatcher_close:x} "
               f"({resolve_addr(dispatcher_close)}) ...")
        s, info, _ = irp.synth_irp(emu, dispatcher_close, arch_bits,
                                   0x02, devobj, file_obj=0)
        if s is not None:
            log_fn(f"    -> status={decode.fmt_status(s)} Information={info}")
        tracer.replay_new(section="APIs inside IRP_MJ_CLOSE handler:")


def invoke_flt_callbacks(emu, tracer, arch_bits, log_fn, resolve_addr,
                         max_invocations=16):
    """Walk FLT_REGISTRATION pointers captured by shim.FltRegisterFilter
    and synthetically invoke each FLT_OPERATION_REGISTRATION's
    PreOperation callback.

    FLT_REGISTRATION layout (x64):
      +0x00  USHORT Size
      +0x02  USHORT Version
      +0x04  ULONG Flags
      +0x08  CONST FLT_CONTEXT_REGISTRATION *ContextRegistration
      +0x10  CONST FLT_OPERATION_REGISTRATION *OperationRegistration
      ...

    FLT_OPERATION_REGISTRATION entry (x64, 32 bytes):
      +0x00  UCHAR MajorFunction
      +0x04  FLT_OPERATION_REGISTRATION_FLAGS Flags
      +0x08  PFLT_PRE_OPERATION_CALLBACK PreOperation
      +0x10  PFLT_POST_OPERATION_CALLBACK PostOperation
      +0x18  PVOID Reserved1

    Terminator: MajorFunction == 0x80 (IRP_MJ_OPERATION_END).

    Pre-op signature:
      FLT_PREOP_CALLBACK_STATUS (*)(PFLT_CALLBACK_DATA Data,
                                    PCFLT_RELATED_OBJECTS FltObjects,
                                    PVOID *CompletionContext);
    """
    import shim
    if not shim.FLT_REGISTRATION_PTRS:
        return 0
    from speakeasy.common import PERM_MEM_RWX
    is64 = (arch_bits == 64)
    ptr_size = 8 if is64 else 4
    fmt = '<Q' if is64 else '<I'
    # FLT_OPERATION_REGISTRATION: Major(1+pad to 4) Flags(4) Pre(ptr)
    # Post(ptr) Reserved(ptr). x64=0x20, x86=0x14.
    op_stride = 0x20 if is64 else 0x14
    op_pre_off = 0x08
    # FLT_REGISTRATION.OperationRegistration: offset 0x10 (x64), 0x08 (x86).
    flt_reg_op_off = 0x10 if is64 else 0x08

    # Allocate scratch FLT structures. Layouts (x64):
    #   FLT_CALLBACK_DATA:
    #     +0x00 Flags (4)
    #     +0x08 Thread (PETHREAD)
    #     +0x10 Iopb (PFLT_IO_PARAMETER_BLOCK)
    #     +0x18 IoStatus (IO_STATUS_BLOCK, 16)
    #     +0x50 FileObject (PFILE_OBJECT)
    #     +0x58 RequestorMode
    #   FLT_IO_PARAMETER_BLOCK:
    #     +0x00 IrpFlags (4)
    #     +0x04 MajorFunction (1)
    #     +0x05 MinorFunction (1)
    #     +0x06 OperationFlags (1)
    #     +0x08 TargetFileObject (PFILE_OBJECT)
    #     +0x10 TargetInstance (PFLT_INSTANCE)
    #     +0x18 Parameters (FLT_PARAMETERS union, ~0x80 bytes)
    #   FLT_RELATED_OBJECTS:
    #     +0x00 Size (2)
    #     +0x08 Filter
    #     +0x10 Volume
    #     +0x18 Instance
    #     +0x20 FileObject
    #     +0x28 Transaction
    # Sizes generous so handlers reading nested fields don't trap.
    cb_data    = emu.emu.mem_map(0x100, base=None, tag='ktrace.flt_cb',
                                  perms=PERM_MEM_RWX)
    iopb       = emu.emu.mem_map(0x100, base=None, tag='ktrace.flt_iopb',
                                  perms=PERM_MEM_RWX)
    related    = emu.emu.mem_map(0x80, base=None, tag='ktrace.flt_rel',
                                  perms=PERM_MEM_RWX)
    compl_ctx  = emu.emu.mem_map(0x10, base=None, tag='ktrace.flt_ctx',
                                  perms=PERM_MEM_RWX)
    fake_file  = emu.emu.mem_map(0x80, base=None, tag='ktrace.flt_file',
                                  perms=PERM_MEM_RWX)
    fake_inst  = emu.emu.mem_map(0x40, base=None, tag='ktrace.flt_inst',
                                  perms=PERM_MEM_RWX)
    fake_volu  = emu.emu.mem_map(0x40, base=None, tag='ktrace.flt_vol',
                                  perms=PERM_MEM_RWX)
    fake_filtr = 0x6f6b1000  # the handle shim.FltRegisterFilter wrote out
    # Fake ETHREAD page (just a non-NULL, readable blob).
    fake_thread = emu.emu.mem_map(0x40, base=None, tag='ktrace.flt_thr',
                                   perms=PERM_MEM_RWX)
    for p, sz in ((cb_data, 0x100), (iopb, 0x100), (related, 0x80),
                  (compl_ctx, 0x10), (fake_file, 0x80),
                  (fake_inst, 0x40), (fake_volu, 0x40),
                  (fake_thread, 0x40)):
        emu.mem_write(p, b'\x00' * sz)

    # FILE_OBJECT: Type=5, Size=0x80, DeviceObject points to NULL but
    # the FsContext slot is non-NULL so dispatchers that switch on it
    # take a deterministic branch.
    fo_buf = bytearray(0x80)
    struct.pack_into('<H', fo_buf, 0, 5)
    struct.pack_into('<H', fo_buf, 2, 0x80)
    if is64:
        struct.pack_into('<Q', fo_buf, 0x18, 1)  # FsContext
    else:
        struct.pack_into('<I', fo_buf, 0x0c, 1)
    emu.mem_write(fake_file, bytes(fo_buf))

    n = 0
    tracer.phaser.force('reinit_invocation')
    for drvobj, flt_reg in shim.FLT_REGISTRATION_PTRS:
        if not flt_reg:
            continue
        try:
            op_table_ptr = struct.unpack(
                fmt, emu.mem_read(flt_reg + flt_reg_op_off, ptr_size))[0]
        except Exception:
            continue
        if not op_table_ptr:
            continue
        log_fn(f"\n# Invoking FLT pre-op callbacks "
               f"(FLT_REGISTRATION @ 0x{flt_reg:x}, OperationRegistration "
               f"@ 0x{op_table_ptr:x})")
        for i in range(64):  # bounded
            ent_addr = op_table_ptr + i * op_stride
            try:
                ent = bytes(emu.mem_read(ent_addr, op_stride))
            except Exception:
                break
            major = ent[0]
            if major == 0x80:  # IRP_MJ_OPERATION_END
                break
            pre = struct.unpack(fmt, ent[op_pre_off:op_pre_off + ptr_size])[0]
            post_off = op_pre_off + ptr_size
            post = struct.unpack(fmt, ent[post_off:post_off + ptr_size])[0]
            if not pre:
                continue
            mj_name = (decode.IRP_MJ[major] if major < len(decode.IRP_MJ)
                       else f"IRP_MJ_0x{major:x}")

            # Populate Iopb for this call.
            ip_buf = bytearray(0x100)
            ip_buf[4] = major
            if is64:
                struct.pack_into('<Q', ip_buf, 0x08, fake_file)  # TargetFO
                struct.pack_into('<Q', ip_buf, 0x10, fake_inst)  # TargetInstance
            else:
                struct.pack_into('<I', ip_buf, 0x04, fake_file)
                struct.pack_into('<I', ip_buf, 0x08, fake_inst)
            emu.mem_write(iopb, bytes(ip_buf))

            # Populate FLT_CALLBACK_DATA.
            cb_buf = bytearray(0x100)
            if is64:
                struct.pack_into('<Q', cb_buf, 0x08, fake_thread)  # Thread
                struct.pack_into('<Q', cb_buf, 0x10, iopb)         # Iopb
                struct.pack_into('<Q', cb_buf, 0x50, fake_file)    # FileObject
                cb_buf[0x58] = 0  # KernelMode
            else:
                struct.pack_into('<I', cb_buf, 0x04, fake_thread)
                struct.pack_into('<I', cb_buf, 0x08, iopb)
                struct.pack_into('<I', cb_buf, 0x28, fake_file)
                cb_buf[0x2c] = 0
            emu.mem_write(cb_data, bytes(cb_buf))

            # Populate FLT_RELATED_OBJECTS.
            ro_buf = bytearray(0x80)
            struct.pack_into('<H', ro_buf, 0, 0x80)  # Size
            if is64:
                struct.pack_into('<Q', ro_buf, 0x08, fake_filtr)
                struct.pack_into('<Q', ro_buf, 0x10, fake_volu)
                struct.pack_into('<Q', ro_buf, 0x18, fake_inst)
                struct.pack_into('<Q', ro_buf, 0x20, fake_file)
            else:
                struct.pack_into('<I', ro_buf, 0x04, fake_filtr)
                struct.pack_into('<I', ro_buf, 0x08, fake_volu)
                struct.pack_into('<I', ro_buf, 0x0c, fake_inst)
                struct.pack_into('<I', ro_buf, 0x10, fake_file)
            emu.mem_write(related, bytes(ro_buf))

            # Reset CompletionContext slot.
            emu.mem_write(compl_ctx, b'\x00' * 0x10)

            import shim as _shim
            if getattr(_shim, '_watchdog_expired', lambda: False)():
                log_fn("  (skipping remaining FLT pre-ops — "
                       "watchdog expired)")
                return n
            if not getattr(_shim, '_rearm_watchdog', lambda: True)():
                return n
            log_fn(f"  -> FLT pre-op for {mj_name} @ 0x{pre:x} "
                   f"({resolve_addr(pre)})")
            try:
                emu.call(pre, [cb_data, related, compl_ctx])
            except Exception as e:
                log_fn(f"     pre-op error: {e}")
            tracer.replay_new(
                section=f"APIs inside FLT pre-op {mj_name} @ 0x{pre:x}:")
            n += 1
            if n >= max_invocations:
                break
        if n >= max_invocations:
            break
    return n


def invoke_unload(emu, tracer, drvobj_ptr, unload_fn, log_fn, resolve_addr):
    """Call DriverObject->DriverUnload, if registered. Surfaces cleanup
    APIs (IoDeleteSymbolicLink, IoDetachDevice, KeCancelTimer,
    PsRemoveLoad*NotifyRoutine, IoUnregisterShutdownNotification, ...)
    that don't appear during DriverEntry or dispatch.

    Most drivers register a real Unload (otherwise they can't be
    unloaded by the SCM). For drivers that don't register one we
    silently skip.
    """
    if not unload_fn or not drvobj_ptr:
        return 0
    import shim as _shim
    if getattr(_shim, '_watchdog_expired', lambda: False)():
        log_fn("# DriverUnload skipped — watchdog expired")
        return 0
    if not getattr(_shim, '_rearm_watchdog', lambda: True)():
        return 0
    log_fn('')
    log_fn(f"# Invoking DriverUnload @ 0x{unload_fn:x} "
           f"({resolve_addr(unload_fn)})")
    tracer.phaser.force('reinit_invocation')  # reuse the post-init phase
    try:
        emu.call(unload_fn, [drvobj_ptr])
    except Exception as e:
        log_fn(f"  DriverUnload error: {e}")
    tracer.replay_new(section="APIs inside DriverUnload:")
    return 1
