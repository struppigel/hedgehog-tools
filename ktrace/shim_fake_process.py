"""Fake-process responders. Installed when EMU_OPTS['fake_processes'] is
populated; surfaces a consistent view of synthetic AV/EDR processes
through PsLookupProcessByProcessId / ZwQueryInformationProcess(class=27) /
PsGetProcessImageFileName / ZwTerminateProcess / NtTerminateProcess so an
AV-killer driver finds its targets and its kill calls are captured."""
from speakeasy.winenv.api import api as api_module
from speakeasy.winenv import arch as _arch
from shim_state import EMU_OPTS
apihook = api_module.ApiHandler.apihook


def install_fake_process_responders(arch_bits, ntos_mod, state):
    _rtl_conv = (_arch.CALL_CONV_FASTCALL if arch_bits == 64
                 else _arch.CALL_CONV_STDCALL)
    # ---- Fake-process responders ---------------------------------
    # `fake_processes` is a [(pid, image-name), ...] list. We surface
    # the same view through:
    #   * PsLookupProcessByProcessId(pid)        → fake EPROCESS ptr
    #   * ZwQueryInformationProcess(...class=27) → image filename
    #   * PsGetProcessImageFileName(eproc)       → ANSI image basename
    # so an AV-killer driver enumerating PIDs + reading image names
    # finds its targets, and any ZwTerminateProcess that follows is
    # captured as proof of intent.
    #
    # Synthetic EPROCESS pointers: 0x6f6d0000 + 0x100*idx, paired with
    # the (pid, name) entry. Subsequent lookups by handle map back via
    # the cached _FAKE_PROC_BY_EPROC dict on the apihook instance.
    _state_fp = {'eproc_by_pid': {}, 'name_by_eproc': {},
                 'name_by_handle': {}, '_built_for': None}
    state['fake_proc'] = _state_fp

    def _build_fake_proc_table():
        """Rebuild table from current EMU_OPTS['fake_processes']."""
        fakes = EMU_OPTS.get('fake_processes') or ()
        if _state_fp['_built_for'] is fakes:
            return
        _state_fp['eproc_by_pid'].clear()
        _state_fp['name_by_eproc'].clear()
        for idx, (pid, name) in enumerate(fakes):
            eproc = 0x6f6d0000 + 0x100 * (idx + 1)
            _state_fp['eproc_by_pid'][pid] = (eproc, name)
            _state_fp['name_by_eproc'][eproc] = name
        _state_fp['_built_for'] = fakes

    # Capture the original Speakeasy handler so we can delegate to it
    # for tracked emulator processes (PID 4 / our driver / etc.) and
    # only handle fake PIDs in our hook.
    _orig_pslookup = ntos_mod.Ntoskrnl.__dict__.get(
        'PsLookupProcessByProcessId')

    _orig_psgetcurpid = ntos_mod.Ntoskrnl.__dict__.get(
        'PsGetCurrentProcessId')

    def _ps_get_current_pid(self, emu_arg, argv, ctx={}):
        ovr = EMU_OPTS.get('current_pid_override')
        if ovr is not None:
            return ovr
        if _orig_psgetcurpid is not None:
            return _orig_psgetcurpid(self, emu_arg, argv, ctx)
        # Return a synthetic non-zero, non-System PID so callers that
        # do "kill my own process" (or fold the current PID into other
        # decisions) don't accidentally target PID 0 (Idle) / PID 4
        # (System) and get mis-labelled as system-impacting in the
        # trace. 0xCAFE (=51966) is outside every preset PID range
        # (common: 0x100..0x800, av: 0x1000..0x10FF, raw default:
        # 0x2000+) and obvious-on-sight in hex dumps.
        return 0xCAFE

    setattr(ntos_mod.Ntoskrnl, 'PsGetCurrentProcessId',
            apihook('PsGetCurrentProcessId', argc=0,
                    conv=_rtl_conv)(_ps_get_current_pid))

    # ExGetPreviousMode override: many callback bodies (registry-filter,
    # process-notify, ob-callback) short-circuit when PreviousMode is
    # KernelMode. When invoke_callbacks simulates a user-mode-triggered
    # event, it sets previous_mode_override=1 so the body actually runs.
    def _ex_get_previous_mode(self, emu_arg, argv, ctx={}):
        ovr = EMU_OPTS.get('previous_mode_override')
        if ovr is not None:
            return ovr
        return 0  # KernelMode (default — matches Speakeasy's behavior)

    setattr(ntos_mod.Ntoskrnl, 'ExGetPreviousMode',
            apihook('ExGetPreviousMode', argc=0,
                    conv=_rtl_conv)(_ex_get_previous_mode))

    def _ps_lookup_by_pid(self, emu_arg, argv, ctx={}):
        if len(argv) < 2:
            return 0xC000000B  # STATUS_INVALID_CID
        pid = argv[0]
        fakes = EMU_OPTS.get('fake_processes') or ()
        if fakes:
            _build_fake_proc_table()
            info = _state_fp['eproc_by_pid'].get(pid)
            if info is not None:
                eproc, _name = info
                if argv[1]:
                    try:
                        ptr_size = emu_arg.get_ptr_size()
                        (getattr(emu_arg, 'mem_write', None) or
                         emu_arg.emu.mem_write)(
                            argv[1],
                            eproc.to_bytes(ptr_size, 'little'))
                    except Exception:
                        pass
                return 0
        # Fall back to Speakeasy's original handler for tracked
        # emulator-side processes (PID 4, our driver, etc.).
        # Upstream crashes with "'NoneType' has no attribute 'to_bytes'"
        # when proc.address is None — guard against that and synthesise a
        # fake EPROCESS instead so the trace continues.
        if _orig_pslookup is not None:
            try:
                return _orig_pslookup(self, emu_arg, argv, ctx)
            except AttributeError:
                pass
        # PID-ceiling cap for the unbounded "walk the entire PID space"
        # pattern. Without this cap, drivers like Chinese AV-killers
        # / PDF-DRM minifilters that loop
        #
        #   for (pid = 4; ; pid += 4) {
        #       if (PsLookupProcessByProcessId(pid, &p) != 0) break;
        #       ... open proc_NNN.exe, scan, dereference ...
        #   }
        #
        # run until the watchdog kills emulation — every PID succeeds
        # and the loop has no termination condition. Real Windows PIDs
        # are typically <8 K on a normal system; samples that care
        # about higher PIDs should register them via --fake-processes.
        #
        # Configurable via EMU_OPTS['pid_lookup_ceiling']; defaults to
        # 0x2000 (8192). Setting to 0 disables the cap (legacy "always
        # succeed" behavior).
        ceiling = EMU_OPTS.get('pid_lookup_ceiling', 0x2000)
        try:
            pid_int = int(pid) if not isinstance(pid, int) else pid
        except Exception:
            pid_int = 0
        if ceiling and pid_int > ceiling:
            return 0xC000000B  # STATUS_INVALID_CID — terminate the loop

        # Generic fallback: hand out a deterministic synthetic EPROCESS so
        # PsLookupProcessByProcessId always succeeds when the caller asks
        # about an in-range unknown PID.
        eproc = 0x6f6d8000 + ((pid_int & 0xFFFF) << 4)
        if argv[1]:
            try:
                ptr_size = emu_arg.get_ptr_size()
                (getattr(emu_arg, 'mem_write', None) or
                 emu_arg.emu.mem_write)(argv[1],
                                        eproc.to_bytes(ptr_size, 'little'))
            except Exception:
                pass
        return 0

    _orig_obopen = ntos_mod.Ntoskrnl.__dict__.get('ObOpenObjectByPointer')

    def _ob_open_object_by_pointer(self, emu_arg, argv, ctx={}):
        # NTSTATUS ObOpenObjectByPointer(PVOID Obj, ULONG attrs, ...,
        #   AccessMode, OUT HANDLE *out)
        # Caller passes the EPROCESS pointer (arg 0) and gets a handle.
        # Remember name_by_eproc → name_by_handle.
        if len(argv) < 7:
            return 0xC0000001
        fakes = EMU_OPTS.get('fake_processes') or ()
        if not fakes and _orig_obopen is not None:
            try:
                return _orig_obopen(self, emu_arg, argv, ctx)
            except AttributeError:
                # Upstream `obj.ref_cnt += 1` crashes when obj is None
                # (driver opens by a synthetic EPROCESS we minted). Fall
                # through and just hand out a fresh fake handle.
                pass
        eproc = argv[0]
        name = _state_fp['name_by_eproc'].get(eproc)
        # Hand out a unique handle.
        handle = 0x6f6e1000 + (len(_state_fp['name_by_handle']) << 4)
        if name:
            _state_fp['name_by_handle'][handle] = name
            # also stash in decode's handle-name map for nice display
            try:
                import decode
                decode.remember_handle(handle, name)
            except Exception:
                pass
        try:
            if argv[6]:
                ptr_size = emu_arg.get_ptr_size()
                (getattr(emu_arg, 'mem_write', None) or
                 emu_arg.emu.mem_write)(argv[6],
                                        handle.to_bytes(ptr_size, 'little'))
        except Exception:
            pass
        return 0

    _orig_zwqip = ntos_mod.Ntoskrnl.__dict__.get('ZwQueryInformationProcess')

    def _zw_query_information_process(self, emu_arg, argv, ctx={}):
        # NTSTATUS ZwQueryInformationProcess(HANDLE h, ULONG class,
        #   PVOID info, ULONG infolen, PULONG retlen)
        if len(argv) < 5:
            return 0xC0000001
        # Always run our impl. We now track every ZwOpenProcess handle
        # (with PID-resolved name) and the upstream Speakeasy impl
        # rejects synthetic handles with STATUS_OBJECT_TYPE_MISMATCH,
        # which the driver then treats as "couldn't ID the process"
        # and falls through to its "Unknown" log path.
        h, cls, info, infolen, retlen = argv
        name = _state_fp['name_by_handle'].get(h, '')
        # Class 27 (ProcessImageFileName): UNICODE_STRING + buffer
        if cls == 0x1B:
            if not name:
                # Default placeholder so drivers iterating known PIDs see
                # *some* name and progress.
                name = f'proc_{h & 0xFFFFFFFF:x}.exe'
            try:
                ps = emu_arg.get_ptr_size()
                fmt = '<Q' if ps == 8 else '<I'
                full = f'\\Device\\HarddiskVolume1\\Windows\\System32\\{name}'
                wb = full.encode('utf-16-le')
                needed = (8 if ps == 8 else 4) + (4 if ps == 8 else 0) + ps + len(wb) + 2
                if retlen:
                    (getattr(emu_arg, 'mem_write', None) or
                     emu_arg.emu.mem_write)(retlen,
                                            needed.to_bytes(4, 'little'))
                if not info or infolen < needed:
                    return 0xC0000004  # STATUS_INFO_LENGTH_MISMATCH
                # UNICODE_STRING + inline buffer
                import struct as _s
                hdr_size = 16 if ps == 8 else 8
                buf_addr = info + hdr_size
                ustr = (_s.pack('<H', len(wb)) + _s.pack('<H', len(wb) + 2) +
                        (b'\x00\x00\x00\x00' if ps == 8 else b'') +
                        _s.pack(fmt, buf_addr))
                (getattr(emu_arg, 'mem_write', None) or
                 emu_arg.emu.mem_write)(info, ustr + wb + b'\x00\x00')
            except Exception:
                return 0xC0000001
            return 0
        # Other classes: zero the buffer and return success.
        try:
            if info and infolen:
                (getattr(emu_arg, 'mem_write', None) or
                 emu_arg.emu.mem_write)(info, b'\x00' * min(infolen, 0x80))
            if retlen:
                (getattr(emu_arg, 'mem_write', None) or
                 emu_arg.emu.mem_write)(retlen,
                                        int(infolen).to_bytes(4, 'little'))
        except Exception:
            pass
        return 0

    def _ps_get_process_image_filename(self, emu_arg, argv, ctx={}):
        # PUCHAR PsGetProcessImageFileName(PEPROCESS) — returns pointer
        # to a 16-byte ANSI-truncated name field inside EPROCESS.
        if not argv:
            return 0
        eproc = argv[0]
        name = _state_fp['name_by_eproc'].get(eproc) or 'unknown.exe'
        # Allocate a small region with the name (16 bytes max, NUL-padded)
        from speakeasy.common import PERM_MEM_RWX
        mm = (getattr(emu_arg, 'mem_map', None) or
              emu_arg.emu.mem_map)
        if not mm:
            return 0
        try:
            buf = mm(16, base=None, tag='ktrace.proc_name',
                     perms=PERM_MEM_RWX)
            payload = name.encode('latin1', errors='replace')[:15] + b'\x00'
            (getattr(emu_arg, 'mem_write', None) or
             emu_arg.emu.mem_write)(buf, payload.ljust(16, b'\x00'))
        except Exception:
            return 0
        return buf

    def _zw_terminate_process(self, emu_arg, argv, ctx={}):
        # NTSTATUS ZwTerminateProcess(HANDLE Process, NTSTATUS ExitStatus)
        # Log which AV product just got killed (already shown via the
        # decode handle→name correlation if the handle came from
        # ObOpenObjectByPointer above).
        return 0

    # ZwOpenProcess / NtOpenProcess record the PID being opened so a
    # later ZwQueryInformationProcess(ProcessImageFileName) can return
    # something other than STATUS_OBJECT_TYPE_MISMATCH. Without this
    # the FLT pre-op flow in d3 etc. falls through to its "Unknown"
    # process-name branch even though the driver tried to identify
    # the requesting process.
    # NTSTATUS ZwOpenProcess(PHANDLE ProcessHandle,
    #                        ACCESS_MASK DesiredAccess,
    #                        POBJECT_ATTRIBUTES ObjectAttributes,
    #                        PCLIENT_ID ClientId);
    # CLIENT_ID = { HANDLE UniqueProcess; HANDLE UniqueThread; }
    # (8-byte pid + 8-byte tid on x64; 4+4 on x86).
    def _zw_open_process(self, emu_arg, argv, ctx={}):
        if len(argv) < 4:
            return 0xC0000001
        phandle, _access, _attrs, cid_addr = argv[:4]
        pid = 0
        try:
            ptr_size = emu_arg.get_ptr_size()
            cid = bytes((getattr(emu_arg, 'mem_read', None) or
                         emu_arg.emu.mem_read)(cid_addr, ptr_size * 2))
            import struct as _s
            pid = _s.unpack('<Q' if ptr_size == 8 else '<I',
                            cid[:ptr_size])[0]
        except Exception:
            pass
        # Resolve PID → name from --fake-processes if supplied; else
        # synthesise a deterministic placeholder so the driver still
        # gets a real-looking name back from ProcessImageFileName.
        _build_fake_proc_table()
        name = None
        info = _state_fp['eproc_by_pid'].get(pid)
        if info:
            _eproc, name = info
        if not name:
            if pid == 0:
                # PID 0 on real Windows is the Idle process, NOT System
                # (System is PID 4). Label it explicitly as "unset" so
                # the trace doesn't suggest a system-level kill when the
                # zero is just the malware's atoi() running on an empty
                # IOCTL input buffer or a zero return from some
                # uninitialised path.
                name = '[pid=0 unset/idle]'
            elif pid == 0xffffffff:
                name = '[pid=-1 self-handle]'
            elif pid == 4:
                name = 'System.exe'
            else:
                name = f'proc_{pid}.exe'
        # Mint a unique fake handle and remember the resolved name.
        handle = 0x6f6f1000 + (len(_state_fp['name_by_handle']) << 4)
        _state_fp['name_by_handle'][handle] = name
        try:
            import decode
            decode.remember_handle(handle, name)
        except Exception:
            pass
        try:
            if phandle:
                ptr_size = emu_arg.get_ptr_size()
                (getattr(emu_arg, 'mem_write', None) or
                 emu_arg.emu.mem_write)(phandle,
                                        handle.to_bytes(ptr_size, 'little'))
        except Exception:
            pass
        # Surface the resolved pid+name in argv so format_call can show
        # it: argv[3] (CLIENT_ID ptr) becomes "pid=N name='...'"
        try:
            argv[3] = f"pid={pid} name={name!r}"
        except Exception:
            pass
        return 0

    setattr(ntos_mod.Ntoskrnl, 'PsLookupProcessByProcessId',
            apihook('PsLookupProcessByProcessId', argc=2,
                    conv=_rtl_conv)(_ps_lookup_by_pid))
    setattr(ntos_mod.Ntoskrnl, 'ObOpenObjectByPointer',
            apihook('ObOpenObjectByPointer', argc=7,
                    conv=_rtl_conv)(_ob_open_object_by_pointer))
    setattr(ntos_mod.Ntoskrnl, 'ZwOpenProcess',
            apihook('ZwOpenProcess', argc=4,
                    conv=_rtl_conv)(_zw_open_process))
    setattr(ntos_mod.Ntoskrnl, 'NtOpenProcess',
            apihook('NtOpenProcess', argc=4,
                    conv=_rtl_conv)(_zw_open_process))
    setattr(ntos_mod.Ntoskrnl, 'ZwQueryInformationProcess',
            apihook('ZwQueryInformationProcess', argc=5,
                    conv=_rtl_conv)(_zw_query_information_process))
    setattr(ntos_mod.Ntoskrnl, 'NtQueryInformationProcess',
            apihook('NtQueryInformationProcess', argc=5,
                    conv=_rtl_conv)(_zw_query_information_process))
    setattr(ntos_mod.Ntoskrnl, 'PsGetProcessImageFileName',
            apihook('PsGetProcessImageFileName', argc=1,
                    conv=_rtl_conv)(_ps_get_process_image_filename))
    setattr(ntos_mod.Ntoskrnl, 'ZwTerminateProcess',
            apihook('ZwTerminateProcess', argc=2,
                    conv=_rtl_conv)(_zw_terminate_process))
    setattr(ntos_mod.Ntoskrnl, 'NtTerminateProcess',
            apihook('NtTerminateProcess', argc=2,
                    conv=_rtl_conv)(_zw_terminate_process))

