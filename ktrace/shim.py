"""Drop-in compat shim — matches super_tracer.py's setup verbatim."""
from speakeasy.winenv.api import api as api_module
from speakeasy.winenv.api.kernelmode import ntoskrnl as ntos_mod
from speakeasy.winenv.api.kernelmode import hal as hal_mod
from speakeasy.winenv.api import winapi as _winapi
from speakeasy.winenv import arch as _arch
from speakeasy.windows.kernel import WinKernelEmulator
apihook = api_module.ApiHandler.apihook


# API-module stubs (TDI, FltMgr, NetIo, CNG, KsecDD, Fwpkclnt) +
# their registration into _winapi.API_HANDLERS are kept in a
# separate file. The import side-effect performs registration.
from shim_api_modules import (  # noqa: F401
    FLT_REGISTRATION_PTRS,
    _reset_flt_state,
)
import shim_api_modules as _api_modules_eager  # noqa: F401



# State / presets / set_* helpers / map_stack_shadow live in shim_state.
from shim_state import (  # noqa: F401
    EMU_OPTS,
    FAKE_MODULE_PRESETS,
    FAKE_PROCESS_PRESETS,
    set_current_pid_override,
    set_previous_mode_override,
    set_fake_modules,
    set_fake_processes,
    set_force_strstr_match,
    map_stack_shadow,
)


# FAKE_IO state + fake-io hook installation live in shim_fake_io.
from shim_fake_io import (  # noqa: F401
    FAKE_IO,
    _reset_fake_io_state,
    _patch_pefile_decoymodule,
    _install_fake_io_hooks,
    _flush_dumped_files,
)


def install_shim(emu, arch_bits, log_func=None):
    _patch_pefile_decoymodule()
    state = {'hits': 0, 'fake_obj_addr': 0}
    import struct as _struct
    is64 = (arch_bits == 64)
    _rtl_conv = (_arch.CALL_CONV_FASTCALL if is64
                 else _arch.CALL_CONV_STDCALL)
    conv = _rtl_conv  # historical alias used later

    def _q(s,e,a,c={}): return 1
    def _s(s,e,a,c={}): return 0
    def _e(s,e,a,c={}): return 1
    ntos_mod.Ntoskrnl.KeQueryActiveProcessors = apihook('KeQueryActiveProcessors', argc=0)(_q)
    ntos_mod.Ntoskrnl.KeSetSystemAffinityThread = apihook('KeSetSystemAffinityThread', argc=1)(_s)
    ntos_mod.Ntoskrnl.KeRevertToUserAffinityThread = apihook('KeRevertToUserAffinityThread', argc=0)(_s)
    ntos_mod.Ntoskrnl._except_handler3 = apihook('_except_handler3', argc=4, conv=_arch.CALL_CONV_CDECL)(_e)
    # SEH unwind helpers — return 0 so the handler treats the unwind
    # as a normal-flow termination rather than an unhandled exception.
    # Each apihook needs its own function object — decorating a shared
    # function overwrites __apihook__ on every call.
    def _lu(s, e, a, c={}): return 0
    def _gu(s, e, a, c={}): return 0
    def _at(s, e, a, c={}): return 0
    if not hasattr(ntos_mod.Ntoskrnl, '_local_unwind'):
        ntos_mod.Ntoskrnl._local_unwind = apihook(
            '_local_unwind', argc=2, conv=_arch.CALL_CONV_CDECL)(_lu)
    if not hasattr(ntos_mod.Ntoskrnl, '_global_unwind2'):
        ntos_mod.Ntoskrnl._global_unwind2 = apihook(
            '_global_unwind2', argc=2, conv=_arch.CALL_CONV_CDECL)(_gu)
    if not hasattr(ntos_mod.Ntoskrnl, '_abnormal_termination'):
        ntos_mod.Ntoskrnl._abnormal_termination = apihook(
            '_abnormal_termination', argc=0, conv=_arch.CALL_CONV_CDECL)(_at)

    # ---- String conversion helpers — extracted to shim_string_helpers.py
    from shim_string_helpers import install_string_helpers
    install_string_helpers(arch_bits, ntos_mod)

    # ---- Basic C runtime — extracted to shim_c_runtime.py
    from shim_c_runtime import install_c_runtime, _read_cstr, _read_wcstr
    install_c_runtime(arch_bits, ntos_mod, conv, log_func)

    # ---- RtlRandom / RtlRandomEx — pseudo-random ULONG -------------
    # Both Speakeasy gaps. RtlRandom takes an in-out seed (ULONG*) and
    # returns a ULONG with bit 31 = 0. We use a deterministic LCG so
    # runs are reproducible.
    _rng_state = [0x12345678]

    def _rtl_random(self, emu_arg, argv, ctx={}):
        # Read seed if provided, advance our deterministic state.
        try:
            if argv and argv[0]:
                seed_bytes = bytes((getattr(emu_arg, 'mem_read', None) or
                                    emu_arg.emu.mem_read)(argv[0], 4))
                seed = _struct.unpack('<I', seed_bytes)[0]
            else:
                seed = _rng_state[0]
        except Exception:
            seed = _rng_state[0]
        # Numerical recipes LCG.
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
        _rng_state[0] = seed
        try:
            if argv and argv[0]:
                (getattr(emu_arg, 'mem_write', None) or
                 emu_arg.emu.mem_write)(argv[0],
                                        seed.to_bytes(4, 'little'))
        except Exception:
            pass
        return seed

    if not hasattr(ntos_mod.Ntoskrnl, 'RtlRandom'):
        ntos_mod.Ntoskrnl.RtlRandom = apihook(
            'RtlRandom', argc=1, conv=_rtl_conv)(_rtl_random)
    if not hasattr(ntos_mod.Ntoskrnl, 'RtlRandomEx'):
        def _rtl_random_ex(self, emu_arg, argv, ctx={}):
            return _rtl_random(self, emu_arg, argv, ctx)
        ntos_mod.Ntoskrnl.RtlRandomEx = apihook(
            'RtlRandomEx', argc=1, conv=_rtl_conv)(_rtl_random_ex)

    # ---- C runtime string / ctype Speakeasy doesn't ship ----------
    def _strnicmp_impl(self, emu_arg, argv, ctx={}):
        if len(argv) < 3:
            return 0
        n = argv[2]
        if n <= 0:
            return 0
        # _read_cstr returns bytes; keep everything bytes through the
        # comparison (mixing str+bytes raised TypeError).
        a = _read_cstr(emu_arg, argv[0], n)[:n].lower()
        b = _read_cstr(emu_arg, argv[1], n)[:n].lower()
        a = a + b'\x00' * (n - len(a))
        b = b + b'\x00' * (n - len(b))
        for ca, cb in zip(a, b):
            if ca != cb:
                return -1 if ca < cb else 1
        return 0

    def _atoi_impl(self, emu_arg, argv, ctx={}):
        if not argv:
            return 0
        # _read_cstr returns bytes; decode to str for parsing.
        try:
            s = _read_cstr(emu_arg, argv[0], 64).decode(
                'latin1', errors='replace').strip()
        except Exception:
            return 0
        sign = 1
        if s.startswith(('-', '+')):
            sign = -1 if s[0] == '-' else 1
            s = s[1:]
        digits = ''
        for c in s:
            if c.isdigit():
                digits += c
            else:
                break
        try:
            return sign * int(digits) if digits else 0
        except Exception:
            return 0

    # ctype: param is an int (the character). C ctype.h returns
    # non-zero for true / zero for false; the exact non-zero value
    # doesn't matter to callers using the result as a boolean.
    def _make_ctype(predicate):
        def fn(self, emu_arg, argv, ctx={}):
            if not argv:
                return 0
            c = argv[0] & 0xFF
            return 1 if predicate(c) else 0
        return fn

    _ctype = [
        ('isspace', lambda c: c in b' \t\n\r\x0b\x0c'),
        ('isdigit', lambda c: 0x30 <= c <= 0x39),
        ('isxdigit', lambda c: (0x30 <= c <= 0x39 or
                                0x41 <= c <= 0x46 or 0x61 <= c <= 0x66)),
        ('islower', lambda c: 0x61 <= c <= 0x7a),
        ('isupper', lambda c: 0x41 <= c <= 0x5a),
        ('isalpha', lambda c: (0x41 <= c <= 0x5a or 0x61 <= c <= 0x7a)),
        ('isalnum', lambda c: (0x30 <= c <= 0x39 or
                               0x41 <= c <= 0x5a or 0x61 <= c <= 0x7a)),
        ('isprint', lambda c: 0x20 <= c < 0x7f),
        ('iscntrl', lambda c: c < 0x20 or c == 0x7f),
    ]
    for name, pred in _ctype:
        if not hasattr(ntos_mod.Ntoskrnl, name):
            setattr(ntos_mod.Ntoskrnl, name,
                    apihook(name, argc=1,
                            conv=_arch.CALL_CONV_CDECL)(_make_ctype(pred)))

    def _tolower(self, emu_arg, argv, ctx={}):
        if not argv: return 0
        c = argv[0] & 0xFF
        return (c + 0x20) if 0x41 <= c <= 0x5a else c

    def _toupper(self, emu_arg, argv, ctx={}):
        if not argv: return 0
        c = argv[0] & 0xFF
        return (c - 0x20) if 0x61 <= c <= 0x7a else c

    def _strcpy_s(self, emu_arg, argv, ctx={}):
        # errno_t strcpy_s(dst, dst_sz, src). _read_cstr returns bytes
        # already (raw memory contents), so no .encode().
        if len(argv) < 3 or not argv[0] or not argv[2]:
            return 0x16  # EINVAL
        src = _read_cstr(emu_arg, argv[2])
        if len(src) + 1 > argv[1]:
            return 0x22  # ERANGE
        try:
            (getattr(emu_arg, 'mem_write', None) or
             emu_arg.emu.mem_write)(argv[0], src + b'\x00')
        except Exception:
            return 0x16
        return 0

    if not hasattr(ntos_mod.Ntoskrnl, '_strnicmp'):
        ntos_mod.Ntoskrnl._strnicmp = apihook(
            '_strnicmp', argc=3,
            conv=_arch.CALL_CONV_CDECL)(_strnicmp_impl)
    if not hasattr(ntos_mod.Ntoskrnl, 'atoi'):
        ntos_mod.Ntoskrnl.atoi = apihook(
            'atoi', argc=1, conv=_arch.CALL_CONV_CDECL)(_atoi_impl)
    if not hasattr(ntos_mod.Ntoskrnl, 'atol'):
        # atol is same as atoi for our purposes
        def _atol_impl(self, emu_arg, argv, ctx={}):
            return _atoi_impl(self, emu_arg, argv, ctx)
        ntos_mod.Ntoskrnl.atol = apihook(
            'atol', argc=1, conv=_arch.CALL_CONV_CDECL)(_atol_impl)
    if not hasattr(ntos_mod.Ntoskrnl, 'tolower'):
        ntos_mod.Ntoskrnl.tolower = apihook(
            'tolower', argc=1, conv=_arch.CALL_CONV_CDECL)(_tolower)
    if not hasattr(ntos_mod.Ntoskrnl, 'toupper'):
        ntos_mod.Ntoskrnl.toupper = apihook(
            'toupper', argc=1, conv=_arch.CALL_CONV_CDECL)(_toupper)
    if not hasattr(ntos_mod.Ntoskrnl, 'strcpy_s'):
        ntos_mod.Ntoskrnl.strcpy_s = apihook(
            'strcpy_s', argc=3, conv=_arch.CALL_CONV_CDECL)(_strcpy_s)
    if not hasattr(ntos_mod.Ntoskrnl, 'swprintf'):
        def _swprintf(self, emu_arg, argv, ctx={}):
            return 0
        ntos_mod.Ntoskrnl.swprintf = apihook(
            'swprintf', argc=_arch.VAR_ARGS,
            conv=_arch.CALL_CONV_CDECL)(_swprintf)

    # ---- Misc kernel constants Speakeasy doesn't ship -------------
    # KeQueryTimeIncrement returns the system clock tick interval in
    # 100-ns units. Typical value ~156250 (15.625ms HPET) or 100000.
    if not hasattr(ntos_mod.Ntoskrnl, 'KeQueryTimeIncrement'):
        def _ke_time_inc(self, emu_arg, argv, ctx={}):
            return 156250
        ntos_mod.Ntoskrnl.KeQueryTimeIncrement = apihook(
            'KeQueryTimeIncrement', argc=0)(_ke_time_inc)
    if not hasattr(ntos_mod.Ntoskrnl, 'KeQueryUnbiasedInterruptTime'):
        def _ke_uit(self, emu_arg, argv, ctx={}):
            return 0
        ntos_mod.Ntoskrnl.KeQueryUnbiasedInterruptTime = apihook(
            'KeQueryUnbiasedInterruptTime', argc=0)(_ke_uit)

    # ---- ExAllocatePool2 / 3 — real allocators -----------------
    # Speakeasy doesn't ship these (modern kernel allocator APIs).
    # Bulk stubs return 0 which presents as STATUS_INSUFFICIENT_RESOURCES
    # to the caller; many drivers bail. Allocate from emu memory.
    def _make_pool_alloc(name, size_arg_idx):
        def fn(self, emu_arg, argv, ctx={}):
            if len(argv) <= size_arg_idx:
                return 0
            size = argv[size_arg_idx]
            if not size or size > 0x10_000_000:
                return 0
            try:
                from speakeasy.common import PERM_MEM_RWX
                mm = (getattr(emu_arg, 'mem_map', None) or
                      emu_arg.emu.mem_map)
                return mm(int(size), base=None,
                          tag=f'ktrace.{name}', perms=PERM_MEM_RWX)
            except Exception:
                return 0
        return fn
    if not hasattr(ntos_mod.Ntoskrnl, 'ExAllocatePool2'):
        ntos_mod.Ntoskrnl.ExAllocatePool2 = apihook(
            'ExAllocatePool2', argc=3, conv=_rtl_conv)(
                _make_pool_alloc('expool2', 1))
    if not hasattr(ntos_mod.Ntoskrnl, 'ExAllocatePool3'):
        ntos_mod.Ntoskrnl.ExAllocatePool3 = apihook(
            'ExAllocatePool3', argc=5, conv=_rtl_conv)(
                _make_pool_alloc('expool3', 1))

    # ---- ExEnter/ReleaseCriticalRegionAndAcquire/ReleaseResource* --
    # These are wrappers around ExEnterCriticalRegion +
    # ExAcquire/ReleaseResource*Lite. Speakeasy has the inner APIs but
    # not the combo. The Acquire variants also auto-init the ERESOURCE
    # when called on an uninitialised one (all-zero head bytes) — many
    # KMDF drivers call ExInitializeResourceLite from a callback path
    # that our emulator never reaches, then proceed to acquire; without
    # the auto-init they crash on subsequent `mov reg, [eresource+off]`
    # reads of uninitialised owner-thread / SharedWaiters / etc. fields.
    #
    # ERESOURCE x64 layout (relevant fields):
    #   +0x00 LIST_ENTRY SystemResourcesList   (16 bytes)
    #   +0x10 POWNER_ENTRY OwnerTable
    #   +0x18 SHORT ActiveCount
    #   +0x1A USHORT Flag
    #   +0x20 PKSEMAPHORE SharedWaiters
    #   +0x28 PKEVENT     ExclusiveWaiters
    #   +0x30 OWNER_ENTRY OwnerThreads[2]      (16 bytes each = 32 total)
    #   +0x50 ULONG ContentionCount
    # Total ~0x68.
    import struct as _eresruct
    _ERESOURCE_FLAG_EXCL = 0x0008
    _ERES_SIZE_PROBE = 0x30   # how many bytes we read to detect uninit

    def _auto_init_eresource(emu_arg, addr):
        """If ERESOURCE at `addr` looks uninitialised (head bytes all
        zero), write a minimal valid state and return True. No-op + False
        otherwise (already initialised, or read failed)."""
        if not addr:
            return False
        mem_read = (getattr(emu_arg, 'mem_read', None) or
                    emu_arg.emu.mem_read)
        mem_write = (getattr(emu_arg, 'mem_write', None) or
                     emu_arg.emu.mem_write)
        try:
            head = bytes(mem_read(addr, _ERES_SIZE_PROBE))
        except Exception:
            return False
        if any(head):
            return False
        # Self-loop the SystemResourcesList. Any LIST_ENTRY walker
        # terminates immediately. Set ActiveCount=1 + Flag=exclusive
        # so the resource looks "owned by us". Leave waiter pointers
        # NULL — drivers that fail-fast on those crash anyway under
        # real Windows when no waiter exists.
        try:
            ptr_size = 8 if arch_bits == 64 else 4
            pack_p = '<Q' if ptr_size == 8 else '<I'
            blob = bytearray(0x68)
            # SystemResourcesList.Flink = self
            _eresruct.pack_into(pack_p, blob, 0x00, addr)
            # SystemResourcesList.Blink = self
            _eresruct.pack_into(pack_p, blob, 0x08, addr)
            # ActiveCount = 1, Flag = ResourceOwnedExclusive
            _eresruct.pack_into('<h', blob, 0x18, 1)
            _eresruct.pack_into('<H', blob, 0x1A, _ERESOURCE_FLAG_EXCL)
            mem_write(addr, bytes(blob))
            return True
        except Exception:
            return False

    def _make_acquire_resource(initial_argv=1):
        """Build an apihook that auto-inits the ERESOURCE pointed-to by
        argv[0] (the first arg of every ExAcquireResource*/ExEnterCritical*
        wrapper) and returns success."""
        def fn(self, emu_arg, argv, ctx={}):
            if argv and argv[0]:
                _auto_init_eresource(emu_arg, argv[0])
            return 0
        return fn

    for _crname, _crargc, _is_acquire in (
        ('ExEnterCriticalRegionAndAcquireResourceExclusive', 1, True),
        ('ExEnterCriticalRegionAndAcquireResourceShared',    1, True),
        ('ExEnterCriticalRegionAndAcquireResourceSharedLite', 1, True),
        ('ExReleaseResourceAndLeaveCriticalRegion',           1, False),
        ('ExReleaseResourceLiteAndLeaveCriticalRegion',       1, False),
        ('PsAcquireProcessExitSynchronization', 1, False),
        ('PsReleaseProcessExitSynchronization', 1, False),
        ('IoReleaseRemoveLockEx', 3, False),
        ('IoAcquireRemoveLockEx', 5, False),
    ):
        if hasattr(ntos_mod.Ntoskrnl, _crname):
            continue
        if _is_acquire:
            cloned = _make_acquire_resource()
        else:
            def _zero_fn(self, emu_arg, argv, ctx={}):
                return 0
            cloned = _clone_fn(_zero_fn) if '_clone_fn' in dir() else _zero_fn
        setattr(ntos_mod.Ntoskrnl, _crname,
                apihook(_crname, argc=_crargc, conv=_rtl_conv)(cloned))

    # Also wrap the standalone Acquire-Lite variants the same way (these
    # exist in shim_stub_lists as zero-stubs; replace with the auto-init
    # version). ExAcquireResourceExclusiveLite / ExAcquireResourceSharedLite
    # both take (PERESOURCE, BOOLEAN wait).
    for _acqname in ('ExAcquireResourceExclusiveLite',
                     'ExAcquireResourceSharedLite'):
        # Use our auto-init version regardless of whether Speakeasy or a
        # prior stub registered one — these are the canonical entry
        # points for KMDF resource use and our auto-init is strictly
        # additive (no-op when already initialised).
        setattr(ntos_mod.Ntoskrnl, _acqname,
                apihook(_acqname, argc=2, conv=_rtl_conv)(
                    _make_acquire_resource()))

    # ---- IoEnumerateDeviceObjectList: walk a driver's devices -----
    # NTSTATUS IoEnumerateDeviceObjectList(PDRIVER_OBJECT, PDEVICE_OBJECT*,
    #     ULONG bufSize, PULONG actual)
    # Drivers use this to find target devices (e.g. mouhid).
    # For emulation, we walk Speakeasy's `drv.devices` for the
    # passed driver and write the array. Return STATUS_BUFFER_TOO_SMALL
    # if buf is undersized; STATUS_SUCCESS otherwise.
    if not hasattr(ntos_mod.Ntoskrnl, 'IoEnumerateDeviceObjectList'):
        def _io_enum_devices(self, emu_arg, argv, ctx={}):
            if len(argv) < 4:
                return 0xC0000001
            drv_addr, list_buf, buf_sz, actual_p = argv[:4]
            try:
                drivers = getattr(emu_arg, 'drivers', None) or \
                          getattr(getattr(emu_arg, 'emu', None),
                                  'drivers', [])
                target = None
                for d in drivers:
                    if getattr(d, 'address', 0) == drv_addr:
                        target = d
                        break
                ptr_size = 8 if arch_bits == 64 else 4
                addrs = []
                if target:
                    addrs = [getattr(dv, 'address', 0)
                             for dv in getattr(target, 'devices', [])]
                if not target or not addrs:
                    # Fall back to ktrace's fake-driver list. Samples
                    # that hook a foreign driver via ObReferenceObjectByName
                    # (PoisonX-style → nsiproxy, ZenithQuantum-style →
                    # mouhid/mouclass) typically follow up with this
                    # enumerator to find a device to attach to. With our
                    # auto-fake-driver pipeline we know the DRIVER_OBJECT
                    # exists at `drv_addr` and we synthesised one
                    # DEVICE_OBJECT under it; return that single device
                    # so the sample's attach path proceeds.
                    try:
                        from shim_fake_driver import FAKE_DRV_STATE
                        for st in FAKE_DRV_STATE.values():
                            if st.get('addr') == drv_addr:
                                dev = st.get('devobj_addr', 0)
                                if dev:
                                    addrs = [dev]
                                break
                    except Exception:
                        pass
                if not addrs:
                    # No devices anywhere: signal "no entries" so drivers
                    # that don't have a "0 devices" fallback (which would
                    # NULL-deref walking the empty list) bail gracefully.
                    if actual_p:
                        (getattr(emu_arg, 'mem_write', None) or
                         emu_arg.emu.mem_write)(actual_p, b'\x00\x00\x00\x00')
                    return 0x8000001A  # STATUS_NO_MORE_ENTRIES
                needed = len(addrs) * ptr_size
                if actual_p:
                    (getattr(emu_arg, 'mem_write', None) or
                     emu_arg.emu.mem_write)(
                        actual_p, needed.to_bytes(4, 'little'))
                if buf_sz < needed or not list_buf:
                    return 0xC0000023  # STATUS_BUFFER_TOO_SMALL
                blob = b''.join(a.to_bytes(ptr_size, 'little')
                                for a in addrs)
                (getattr(emu_arg, 'mem_write', None) or
                 emu_arg.emu.mem_write)(list_buf, blob)
            except Exception:
                return 0xC0000001
            return 0
        ntos_mod.Ntoskrnl.IoEnumerateDeviceObjectList = apihook(
            'IoEnumerateDeviceObjectList', argc=4, conv=_rtl_conv)(
                _io_enum_devices)

    # ---- IoRegister/UnregisterShutdownNotification: validate args.
    # Real kernel rejects NULL DeviceObject with STATUS_INVALID_PARAMETER.
    # Speakeasy's stub returns STATUS_SUCCESS unconditionally, which
    # breaks drivers that use the NULL-call as a "kernel ready" probe
    # (poll-loops until they see the *expected* failure). Seen on
    # fk_undead_maindrv (4bf11bea8b0fd…): DriverEntry burns the whole
    # wall budget polling this with NULL because we never return the
    # error it's waiting for.
    def _io_register_shutdown(self, emu_arg, argv, ctx={}):
        dev = argv[0] if argv else 0
        if not dev:
            return 0xC000000D  # STATUS_INVALID_PARAMETER
        return 0
    def _io_unregister_shutdown(self, emu_arg, argv, ctx={}):
        dev = argv[0] if argv else 0
        if not dev:
            return 0xC000000D
        return 0
    ntos_mod.Ntoskrnl.IoRegisterShutdownNotification = apihook(
        'IoRegisterShutdownNotification', argc=1, conv=_rtl_conv)(
            _io_register_shutdown)
    ntos_mod.Ntoskrnl.IoUnregisterShutdownNotification = apihook(
        'IoUnregisterShutdownNotification', argc=1, conv=_rtl_conv)(
            _io_unregister_shutdown)

    # ---- MmFlushImageSection: return TRUE so self-deleting drivers
    # proceed to the ZwDeleteFile branch. Real kernel returns TRUE when
    # the image isn't currently mapped (the common case in our emulator
    # — no other process has it mapped) and FALSE when it is. Returning 0
    # via the default LIKELY_STUBS stub keeps self-delete code paths
    # dark. Seen on TpSafe.sys (0856a1da…) which does
    # `if (MmFlushImageSection(FO->SectionObjectPointer, MmFlushForDelete))
    #     ZwDeleteFile(own_path);` to wipe itself off disk after install.
    def _mm_flush_image_section(self, emu_arg, argv, ctx={}):
        return 1   # BOOLEAN TRUE
    ntos_mod.Ntoskrnl.MmFlushImageSection = apihook(
        'MmFlushImageSection', argc=2, conv=_rtl_conv)(
            _mm_flush_image_section)

    # ---- Mm process-memory copy: present success with zeroed data --
    # Real impl reads from foreign process; for emulation we return
    # STATUS_SUCCESS with the destination zero-filled so the caller
    # proceeds (and we see what *would* happen next).
    def _mm_copy_virtual_memory(self, emu_arg, argv, ctx={}):
        # NTSTATUS MmCopyVirtualMemory(PEPROCESS Src, PVOID SrcAddr,
        #   PEPROCESS Dst, PVOID DstAddr, SIZE_T Size,
        #   KPROCESSOR_MODE Mode, PSIZE_T Returned)
        if len(argv) < 7:
            return 0xC0000001
        try:
            sz = int(argv[4])
            if argv[3]:
                (getattr(emu_arg, 'mem_write', None) or
                 emu_arg.emu.mem_write)(argv[3], b'\x00' * min(sz, 0x1000))
            if argv[6]:
                (getattr(emu_arg, 'mem_write', None) or
                 emu_arg.emu.mem_write)(argv[6],
                                        sz.to_bytes(8 if arch_bits == 64
                                                    else 4, 'little'))
        except Exception:
            pass
        return 0

    def _mm_copy_memory(self, emu_arg, argv, ctx={}):
        # NTSTATUS MmCopyMemory(PVOID Dst, MM_COPY_ADDRESS Src,
        #   SIZE_T Size, ULONG Flags, PSIZE_T Returned)
        if len(argv) < 5:
            return 0xC0000001
        try:
            sz = int(argv[2])
            if argv[0]:
                (getattr(emu_arg, 'mem_write', None) or
                 emu_arg.emu.mem_write)(argv[0], b'\x00' * min(sz, 0x1000))
            if argv[4]:
                (getattr(emu_arg, 'mem_write', None) or
                 emu_arg.emu.mem_write)(argv[4],
                                        sz.to_bytes(8 if arch_bits == 64
                                                    else 4, 'little'))
        except Exception:
            pass
        return 0

    if not hasattr(ntos_mod.Ntoskrnl, 'MmCopyVirtualMemory'):
        ntos_mod.Ntoskrnl.MmCopyVirtualMemory = apihook(
            'MmCopyVirtualMemory', argc=7, conv=_rtl_conv)(
                _mm_copy_virtual_memory)
    if not hasattr(ntos_mod.Ntoskrnl, 'MmCopyMemory'):
        ntos_mod.Ntoskrnl.MmCopyMemory = apihook(
            'MmCopyMemory', argc=5, conv=_rtl_conv)(_mm_copy_memory)

    # ---- PsGetProcessSectionBaseAddress + RtlImageNtHeader --------
    if not hasattr(ntos_mod.Ntoskrnl, 'PsGetProcessSectionBaseAddress'):
        def _ps_sect_base(self, emu_arg, argv, ctx={}):
            return 0x140000000  # plausible image base
        ntos_mod.Ntoskrnl.PsGetProcessSectionBaseAddress = apihook(
            'PsGetProcessSectionBaseAddress', argc=1,
            conv=_rtl_conv)(_ps_sect_base)
    if not hasattr(ntos_mod.Ntoskrnl, 'RtlImageNtHeader'):
        def _rtl_img_nt(self, emu_arg, argv, ctx={}):
            # Return the passed base + offset to 0x100 (typical
            # IMAGE_DOS_HEADER e_lfanew); drivers usually read from
            # this. Returning the base itself works for the common
            # null-check path.
            return argv[0] if argv else 0
        ntos_mod.Ntoskrnl.RtlImageNtHeader = apihook(
            'RtlImageNtHeader', argc=1, conv=_rtl_conv)(_rtl_img_nt)
    if not hasattr(ntos_mod.Ntoskrnl, 'RtlPcToFileHeader'):
        def _rtl_pc_to_fh(self, emu_arg, argv, ctx={}):
            return argv[0] if argv else 0
        ntos_mod.Ntoskrnl.RtlPcToFileHeader = apihook(
            'RtlPcToFileHeader', argc=2, conv=_rtl_conv)(_rtl_pc_to_fh)
    if not hasattr(ntos_mod.Ntoskrnl, 'RtlFindExportedRoutineByName'):
        def _rtl_find_export(self, emu_arg, argv, ctx={}):
            return 0
        ntos_mod.Ntoskrnl.RtlFindExportedRoutineByName = apihook(
            'RtlFindExportedRoutineByName', argc=2,
            conv=_rtl_conv)(_rtl_find_export)
    # _wcsicmp: case-insensitive wide string compare.
    if not hasattr(ntos_mod.Ntoskrnl, '_wcsicmp'):
        def _wcsicmp_impl(self, emu_arg, argv, ctx={}):
            if len(argv) < 2:
                return 0
            a = _read_wcstr(emu_arg, argv[0])
            b = _read_wcstr(emu_arg, argv[1])
            try:
                aa = a.decode('utf-16-le', errors='replace').lower()
                bb = b.decode('utf-16-le', errors='replace').lower()
            except Exception:
                return 0
            if aa == bb:
                return 0
            return -1 if aa < bb else 1
        ntos_mod.Ntoskrnl._wcsicmp = apihook(
            '_wcsicmp', argc=2, conv=_arch.CALL_CONV_CDECL)(_wcsicmp_impl)
    if not hasattr(ntos_mod.Ntoskrnl, 'swprintf_s'):
        def _swprintf_s(self, emu_arg, argv, ctx={}):
            return 0
        ntos_mod.Ntoskrnl.swprintf_s = apihook(
            'swprintf_s', argc=_arch.VAR_ARGS,
            conv=_arch.CALL_CONV_CDECL)(_swprintf_s)
    # ---- Fake-process responders — extracted to shim_fake_process.py
    from shim_fake_process import install_fake_process_responders
    install_fake_process_responders(arch_bits, ntos_mod, state)

    # ---- NtQuerySystemInformation augmentation for fake AV modules ---
    # When EMU_OPTS['fake_modules'] is non-empty, wrap Speakeasy's
    # ZwQuerySystemInformation handler for class 0x0B (SystemModuleInformation)
    # to APPEND extra SYSTEM_MODULE entries with plausible Base / Size /
    # ImageName so anti-AV drivers that hunt for specific driver names
    # in the loaded-module list find their targets and proceed.
    try:
        from speakeasy.winenv.defs.nt import ntoskrnl as _nt_defs
        from speakeasy.winenv.defs.nt import ddk as _ddk
        _SystemModuleInformation_class = 0x0B
        _orig_zqsi = ntos_mod.Ntoskrnl.__dict__.get('ZwQuerySystemInformation')

        def _qsi_with_fakes(self, emu_arg, argv, ctx={}):
            sysclass, sysinfo, syslen, retlen = argv
            fakes = EMU_OPTS.get('fake_modules') or []
            if sysclass != _SystemModuleInformation_class or not fakes:
                # Fall back to Speakeasy's original.
                if _orig_zqsi is not None:
                    return _orig_zqsi(self, emu_arg, argv, ctx)
                return 0xC0000004  # STATUS_INFO_LENGTH_MISMATCH

            try:
                ps = emu_arg.get_ptr_size()
            except Exception:
                ps = 8 if arch_bits == 64 else 4
            sm_template = _nt_defs.SYSTEM_MODULE(ps)
            sm_size = sm_template.sizeof()

            # Combine Speakeasy's view of loaded modules + our fakes.
            try:
                real_mods = emu_arg.get_sys_modules() or []
            except Exception:
                real_mods = []
            total = len(real_mods) + len(fakes)
            needed = ps + total * sm_size

            mw = (getattr(emu_arg, 'mem_write', None) or
                  emu_arg.emu.mem_write)
            try:
                if retlen:
                    mw(retlen, needed.to_bytes(4, 'little'))
                if not sysinfo or syslen < needed:
                    return 0xC0000004
                # Write ModuleCount header.
                mw(sysinfo, total.to_bytes(ps, 'little'))
                buf_ptr = sysinfo + ps
                # Speakeasy's real modules first.
                for i, mod in enumerate(real_mods):
                    sm = _nt_defs.SYSTEM_MODULE(ps)
                    sm.Base = mod.get_base()
                    sm.Size = mod.get_image_size()
                    raw_name = b'\\??\\' + mod.get_emu_path().encode(
                        'utf-8', errors='replace')
                    sm.ImageName = raw_name[:256].ljust(256, b'\x00')
                    sm.LoadCount = 1
                    sm.Index = i
                    sm.ModuleNameOffset = (bytes(sm.ImageName).rfind(b'\\')
                                           + 1)
                    mw(buf_ptr, self.get_bytes(sm))
                    buf_ptr += sm_size
                # Now our fakes. Generate plausible Base addresses.
                fake_base = 0xfffff80012340000
                for j, path in enumerate(fakes):
                    sm = _nt_defs.SYSTEM_MODULE(ps)
                    sm.Base = (fake_base + j * 0x100000) & ((1 << (ps * 8)) - 1)
                    sm.Size = 0x80000  # plausible 512 KB
                    name_bytes = path.encode('utf-8', errors='replace')
                    sm.ImageName = name_bytes[:256].ljust(256, b'\x00')
                    sm.LoadCount = 1
                    sm.Index = len(real_mods) + j
                    sm.ModuleNameOffset = (bytes(sm.ImageName).rfind(b'\\')
                                           + 1)
                    mw(buf_ptr, self.get_bytes(sm))
                    buf_ptr += sm_size
            except Exception:
                return 0xC0000001
            return 0

        # Install on BOTH Nt/Zw aliases — Speakeasy registers Zw only,
        # but our shim has installed Nt elsewhere via the export-sort
        # patch; safest to cover both names.
        setattr(ntos_mod.Ntoskrnl, 'ZwQuerySystemInformation',
                apihook('ZwQuerySystemInformation', argc=4,
                        conv=_rtl_conv)(_qsi_with_fakes))
        setattr(ntos_mod.Ntoskrnl, 'NtQuerySystemInformation',
                apihook('NtQuerySystemInformation', argc=4,
                        conv=_rtl_conv)(_qsi_with_fakes))
    except Exception:
        pass

    # Per-slot zero-return factory (kept here so subsequent loops
    # share it; apihook __apihook__ tagging is per-function so each
    # call to _make_zero() must return a fresh function).
    def _make_zero():
        def _f(self, emu_arg, argv, ctx={}):
            return 0
        return _f

    # KeReleaseMutex / KeWaitForMutexObject etc. (Speakeasy ships
    # KeInitializeMutex / KeWaitForSingleObject but not the rest).
    for _kemtx, _kemtx_argc in (
        ('KeReleaseMutex', 2),
        ('KeReadStateMutex', 1),
        ('KeReleaseSemaphore', 4),
        ('KeReadStateSemaphore', 1),
        ('KeInitializeSemaphore', 3),
        ('KeResetEvent', 1),
        ('KeReadStateEvent', 1),
        ('KeClearEvent', 1),
        ('KePulseEvent', 3),
    ):
        if not hasattr(ntos_mod.Ntoskrnl, _kemtx):
            setattr(ntos_mod.Ntoskrnl, _kemtx,
                    apihook(_kemtx, argc=_kemtx_argc,
                            conv=_rtl_conv)(_make_zero()))

    # Queued spinlock variants — each gets its own function object so
    # apihook __apihook__ tagging stays unique per slot.
    def _qsl_zero(self, emu_arg, argv, ctx={}): return 0
    def _make_unique_zero():
        def _f(self, emu_arg, argv, ctx={}):
            return 0
        return _f
    for _qsl, _qsl_argc in (
        ('KeAcquireQueuedSpinLock', 1),
        ('KeReleaseQueuedSpinLock', 2),
        ('KeAcquireInStackQueuedSpinLock', 2),
        ('KeReleaseInStackQueuedSpinLock', 1),
    ):
        if not hasattr(ntos_mod.Ntoskrnl, _qsl):
            setattr(ntos_mod.Ntoskrnl, _qsl,
                    apihook(_qsl, argc=_qsl_argc, conv=_rtl_conv)(
                        _make_unique_zero()))
    # SList ops: when the list is empty, real Pop returns NULL — but
    # many drivers don't have a fallback and just deref the result.
    # Instead of returning NULL, allocate a fresh pool block and
    # return that, mimicking the "ExAllocateFromNPagedLookasideList"
    # auto-fill behaviour. Push is a no-op (we don't track the list).
    state['slist_entry_pool_base'] = 0x6f6f0000

    def _slist_pop(self, emu_arg, argv, ctx={}):
        # PSLIST_ENTRY ExpInterlockedPopEntrySList(PSLIST_HEADER)
        # We don't track real entries; hand out a fresh writable block
        # so callers using it as `node = pop(); node->field = ...;`
        # don't NULL-deref.
        try:
            from speakeasy.common import PERM_MEM_RWX
            fn = (getattr(emu_arg, 'mem_map', None) or
                  getattr(getattr(emu_arg, 'emu', None), 'mem_map', None))
            if fn:
                return fn(0x1000, base=None,
                          tag='ktrace.slist_entry', perms=PERM_MEM_RWX)
        except Exception:
            pass
        return 0

    def _slist_push(self, emu_arg, argv, ctx={}):
        return 0

    def _slist_depth(self, emu_arg, argv, ctx={}):
        return 0

    # Apihook decorator stamps __apihook__ on the function object —
    # re-using the same function across registrations overwrites it,
    # so only the last install would survive. Clone per slot.
    def _clone_fn(fn):
        def _w(self, emu_arg, argv, ctx={}):
            return fn(self, emu_arg, argv, ctx)
        return _w

    for _slist_name, _slist_argc, _slist_fn in (
        ('ExQueryDepthSList',           1, _slist_depth),
        ('ExpInterlockedPopEntrySList', 1, _slist_pop),
        ('ExpInterlockedPushEntrySList', 2, _slist_push),
        ('ExInterlockedPopEntrySList',  2, _slist_pop),
        ('ExInterlockedPushEntrySList', 3, _slist_push),
        ('InterlockedPopEntrySList',    1, _slist_pop),
        ('InterlockedPushEntrySList',   2, _slist_push),
    ):
        if not hasattr(ntos_mod.Ntoskrnl, _slist_name):
            setattr(ntos_mod.Ntoskrnl, _slist_name,
                    apihook(_slist_name, argc=_slist_argc, conv=_rtl_conv)(
                        _clone_fn(_slist_fn)))

    # #3: MmGetSystemRoutineAddress resolves a name to a real apihook
    # trigger so dynamically resolved imports actually work.
    import struct as _s_mga
    def _mm_get_routine(self, emu, argv, ctx={}):
        if not argv:
            return 0
        name_ptr = argv[0]
        try:
            if arch_bits == 64:
                hdr = bytes(emu.mem_read(name_ptr, 16))
                length = _s_mga.unpack('<H', hdr[0:2])[0]
                buf = _s_mga.unpack('<Q', hdr[8:16])[0]
            else:
                hdr = bytes(emu.mem_read(name_ptr, 8))
                length = _s_mga.unpack('<H', hdr[0:2])[0]
                buf = _s_mga.unpack('<I', hdr[4:8])[0]
            if not buf or not length or length > 0x200:
                return 0
            name = bytes(emu.mem_read(buf, length)).decode(
                'utf-16-le', errors='replace').rstrip('\x00')
        except Exception:
            return 0
        for mod in ('ntoskrnl', 'hal'):
            try:
                return emu.emu.get_proc(mod, name)
            except Exception:
                continue
        return 0
    _conv_mga = (_arch.CALL_CONV_FASTCALL if arch_bits == 64
                 else _arch.CALL_CONV_STDCALL)
    # Only install if Speakeasy hasn't already implemented this — its
    # default returns a valid apihook trigger; our override would shadow it
    # with an arguably-equivalent but slightly different one, which has
    # been observed to throw drivers off.
    if not hasattr(ntos_mod.Ntoskrnl, 'MmGetSystemRoutineAddress'):
        ntos_mod.Ntoskrnl.MmGetSystemRoutineAddress = apihook(
            'MmGetSystemRoutineAddress', argc=1, conv=_conv_mga)(_mm_get_routine)

    def _make_64bit(args_signed=(True, True), op='div'):
        def fn(self, emu, argv, ctx={}):
            a_lo, a_hi, b_lo, b_hi = argv[:4]
            a = (a_hi << 32) | a_lo; b = (b_hi << 32) | b_lo
            if args_signed[0] and a & (1<<63): a -= 1<<64
            if args_signed[1] and b & (1<<63): b -= 1<<64
            r = (a//b) if op=='div' and b else ((a%b) if op=='mod' and b else (a*b if op=='mul' else 0))
            r &= 0xFFFFFFFFFFFFFFFF
            emu.reg_write('eax', r&0xFFFFFFFF); emu.reg_write('edx', (r>>32)&0xFFFFFFFF)
            return r&0xFFFFFFFF
        return fn
    if arch_bits == 32:
        for n, op, sg in [('_alldiv','div',(True,True)),('_aulldiv','div',(False,False)),
                          ('_allmul','mul',(True,True)),('_allrem','mod',(True,True)),
                          ('_aullrem','mod',(False,False))]:
            setattr(ntos_mod.Ntoskrnl, n, apihook(n, argc=4, conv=_arch.CALL_CONV_STDCALL)(_make_64bit(sg, op)))

        def _shift(d='shr', signed=False):
            def fn(s,e,a,c={}):
                eax=e.reg_read('eax'); edx=e.reg_read('edx')
                cnt = (a[0] if a else e.reg_read('ecx')) & 0x3F
                v = (edx<<32)|eax
                if signed and v&(1<<63): v -= 1<<64
                v = (v >> cnt) if d=='shr' else (v << cnt) & 0xFFFFFFFFFFFFFFFF
                v &= 0xFFFFFFFFFFFFFFFF
                e.reg_write('eax', v&0xFFFFFFFF); e.reg_write('edx', (v>>32)&0xFFFFFFFF)
                return v&0xFFFFFFFF
            return fn
        ntos_mod.Ntoskrnl._allshr = apihook('_allshr', argc=1, conv=_arch.CALL_CONV_STDCALL)(_shift('shr', True))
        ntos_mod.Ntoskrnl._aullshr = apihook('_aullshr', argc=1, conv=_arch.CALL_CONV_STDCALL)(_shift('shr', False))

        def _divmod_x(signed=True):
            def fn(self, emu, argv, ctx={}):
                a_lo, a_hi, b_lo, b_hi = argv[:4]
                a = (a_hi<<32)|a_lo; b = (b_hi<<32)|b_lo
                if signed and a&(1<<63): a -= 1<<64
                if signed and b&(1<<63): b -= 1<<64
                if b == 0: q = r = 0
                else: q, r = divmod(a, b)
                q &= 0xFFFFFFFFFFFFFFFF; r &= 0xFFFFFFFFFFFFFFFF
                emu.reg_write('eax', q&0xFFFFFFFF); emu.reg_write('edx', (q>>32)&0xFFFFFFFF)
                emu.reg_write('ecx', r&0xFFFFFFFF); emu.reg_write('ebx', (r>>32)&0xFFFFFFFF)
                return q&0xFFFFFFFF
            return fn
        ntos_mod.Ntoskrnl._alldvrm = apihook('_alldvrm', argc=4, conv=_arch.CALL_CONV_STDCALL)(_divmod_x(True))
        ntos_mod.Ntoskrnl._aulldvrm = apihook('_aulldvrm', argc=4, conv=_arch.CALL_CONV_STDCALL)(_divmod_x(False))

        def _chkstk_fn(self, emu, argv, ctx={}):
            # x86 __chkstk on MSVC: stack-probe only. EAX = bytes to probe.
            # Function preserves EAX; caller does `sub esp, eax` (or
            # `sub esp, <const>` matching eax) after the return. We model
            # the probe as a no-op and just preserve EAX through the
            # return-value path.
            return emu.reg_read('eax')
        ntos_mod.Ntoskrnl._chkstk = apihook('_chkstk', argc=0, conv=_arch.CALL_CONV_STDCALL)(_chkstk_fn)
        ntos_mod.Ntoskrnl.__chkstk = apihook('__chkstk', argc=0, conv=_arch.CALL_CONV_STDCALL)(_chkstk_fn)
        # _alloca_probe is the *old* x86 variant that DOES the allocation
        # itself (predates the probe-only contract). Keep its behaviour.
        def _alloca_probe(self, emu, argv, ctx={}):
            eax=emu.reg_read('eax'); esp=emu.reg_read('esp')
            emu.reg_write('esp', (esp-eax)&0xFFFFFFFF); return eax
        ntos_mod.Ntoskrnl._alloca_probe = apihook(
            '_alloca_probe', argc=0, conv=_arch.CALL_CONV_STDCALL)(_alloca_probe)
    else:
        # x64 __chkstk takes the probe size in rax and adjusts rsp by it.
        # NOTE: each apihook decoration stamps the function with metadata.
        # If you decorate the SAME function twice (e.g. once as `__chkstk`
        # and once as `_chkstk`) the second stamp clobbers the first and
        # only the latter name is registered. Use a fresh function per
        # name.
        def _make_chkstk():
            def fn(self, emu, argv, ctx={}):
                # x64 __chkstk on MSVC is a *probe only*: RAX = bytes to
                # commit; function preserves RAX; caller follows with
                # `sub rsp, rax` (alloca / variable-frame) or
                # `sub rsp, <const>` (fixed frame). We model the probe as a
                # no-op and preserve RAX through the return-value path so
                # the caller's adjustment runs with the right value.
                #
                # Previous behaviour (adjust RSP and return 0) double-
                # adjusted the stack for `sub rsp, const` callers and zeroed
                # RAX for `sub rsp, rax` callers — the latter collapses 5x
                # alloca during the Autel driver's (006e08f1*) DriverEntry
                # onto a single 0-byte block and corrupts the frame, which
                # eventually returns to a garbage RIP.
                return emu.reg_read('rax')
            return fn
        ntos_mod.Ntoskrnl.__chkstk = apihook(
            '__chkstk', argc=0, conv=_arch.CALL_CONV_FASTCALL)(_make_chkstk())
        ntos_mod.Ntoskrnl._chkstk = apihook(
            '_chkstk', argc=0, conv=_arch.CALL_CONV_FASTCALL)(_make_chkstk())

        # x64 SEH personality routines. Return "continue search" (1) so
        # unwind doesn't blow up — we have no real exception frames.
        def _make_seh():
            def fn(self, emu, argv, ctx={}): return 1
            return fn
        for nm in ('__C_specific_handler', '_C_specific_handler',
                   '__GSHandlerCheck', '__GSHandlerCheck_SEH'):
            setattr(ntos_mod.Ntoskrnl, nm,
                    apihook(nm, argc=4, conv=_arch.CALL_CONV_FASTCALL)(_make_seh()))

        # Stack-cookie checks (MSVC /GS).
        def _make_cookie():
            def fn(self, emu, argv, ctx={}): return 0
            return fn
        for nm, ac in (('__security_check_cookie', 1),
                       ('__security_init_cookie', 0)):
            setattr(ntos_mod.Ntoskrnl, nm,
                    apihook(nm, argc=ac, conv=_arch.CALL_CONV_FASTCALL)(_make_cookie()))

    # Comprehensive stub list. Names already implemented by Speakeasy are
    # automatically skipped at install time so we don't clobber working code.
    from shim_stub_lists import LIKELY_STUBS
    # Speakeasy uses CALL_CONV_FASTCALL for Windows x64 ABI (no CALL_CONV_MS64).
    conv = _arch.CALL_CONV_FASTCALL if arch_bits == 64 else _arch.CALL_CONV_STDCALL
    for name, ac in LIKELY_STUBS:
        # Don't clobber Speakeasy's working impls — stubs return 0 (often
        # STATUS_SUCCESS, sometimes NULL) which is wrong for many real APIs.
        if hasattr(ntos_mod.Ntoskrnl, name):
            continue
        def _make_stub():
            def stub_fn(self, emu, argv, ctx={}): return 0
            return stub_fn
        fn = _make_stub()
        setattr(ntos_mod.Ntoskrnl, name, apihook(name, argc=ac, conv=conv)(fn))

    from shim_stub_lists import HAL_STUBS
    for name, ac in HAL_STUBS:
        if hasattr(hal_mod.Hal, name):
            continue
        def _make_hal_stub():
            def s(self, emu, argv, ctx={}): return 0
            return s
        fn = _make_hal_stub()
        setattr(hal_mod.Hal, name, apihook(name, argc=ac, conv=conv)(fn))

    # #4 Loop-terminating returns for enumerators. Returning
    # STATUS_NO_MORE_ENTRIES (0x8000001A) on the first call collapses
    # what would otherwise be thousands of repeating ZwEnumerateKey/
    # ZwEnumerateValueKey calls into one — and lets emulation reach
    # whatever code follows the enumeration.
    STATUS_NO_MORE_ENTRIES = 0x8000001A
    from shim_stub_lists import ENUMERATORS
    def _make_no_more_entries():
        def fn(self, emu, argv, ctx={}):
            return STATUS_NO_MORE_ENTRIES
        return fn
    # Don't clobber explicit smart impls installed earlier (which have
    # real semantics, not just the loop-terminator).
    _ENUMERATOR_KEEPERS = {'IoEnumerateDeviceObjectList'}
    for name, ac in ENUMERATORS:
        if name in _ENUMERATOR_KEEPERS:
            continue
        setattr(ntos_mod.Ntoskrnl, name,
                apihook(name, argc=ac, conv=conv)(_make_no_more_entries()))

    # #1 Output-pointer-writing stubs. APIs whose contract is "write a
    # value/pointer to an out parameter" — if we leave the buffer
    # uninitialised, the driver reads garbage and crashes. We zero
    # `nbytes` at `argv[out_idx]` and return STATUS_SUCCESS.
    #
    # For pointer-typed out params we want a *non-NULL* sentinel so
    # subsequent null-checks pass. We reserve a 0x1000 page at startup
    # filled with zeros and hand its base out as the "fake object".
    # The driver can dereference it safely (reads zeros).
    from shim_stub_lists import OUT_PTR_STUBS
    def _make_out_ptr_stub(out_idx, nbytes, is_ptr, fake_obj_get):
        def fn(self, emu, argv, ctx={}):
            if out_idx is not None and out_idx < len(argv) and argv[out_idx]:
                try:
                    if is_ptr and nbytes >= 4:
                        fake = fake_obj_get()
                        emu.mem_write(argv[out_idx], fake.to_bytes(nbytes, 'little'))
                    else:
                        emu.mem_write(argv[out_idx], b'\x00' * nbytes)
                except Exception:
                    pass
            return 0
        return fn
    # The fake-object page is allocated lazily on first call (we don't
    # have an `emu` instance during install_shim).
    def _fake_obj_get():
        if state['fake_obj_addr']:
            return state['fake_obj_addr']
        # Allocate a 0x1000 zero page accessible from every emu via a
        # well-known address. We pick 0x6f6b0000 ("fake" in leet) as a
        # mostly-unused address far from normal pool ranges.
        # Note: caller binds an emu reference at runtime by side-effect.
        return 0x6f6b0000
    for name, ac, oi, sz, is_ptr in OUT_PTR_STUBS:
        # Don't clobber Speakeasy's real implementations — most of these
        # (KeQuerySystemTime, ZwOpenFile, …) actually work and write real
        # data; our zeros are strictly worse.
        if hasattr(ntos_mod.Ntoskrnl, name):
            continue
        # IoGetDeviceObjectPointer + IoAttachDeviceToDeviceStack get
        # real implementations below — skip the zeros stub.
        if name in ('IoGetDeviceObjectPointer',):
            continue
        setattr(ntos_mod.Ntoskrnl, name,
                apihook(name, argc=ac, conv=conv)(
                    _make_out_ptr_stub(oi, sz, is_ptr, _fake_obj_get)))

    # ---- Synthetic DEVICE_OBJECTs — extracted to shim_devobj.py
    from shim_devobj import install_synthetic_device_objects
    install_synthetic_device_objects(arch_bits, ntos_mod, conv, state, log_func)

    # ---- Speakeasy patches — extracted to shim_speakeasy_patches.py
    from shim_speakeasy_patches import install_speakeasy_patches
    install_speakeasy_patches(arch_bits, ntos_mod, conv, state)

    # ---- Fake I/O + DbgPrint logging — extracted to shim_dbgprint.py
    from shim_dbgprint import install_dbgprint_logging
    install_dbgprint_logging(arch_bits, ntos_mod, conv, state, log_func)


    # ---- TDI IRP fakery — extracted to shim_tdi_faker.py
    from shim_tdi_faker import install_tdi_faker
    install_tdi_faker(arch_bits, ntos_mod, conv, state)

    # ---- Fake DRIVER_OBJECTs for ObReferenceObjectByName (rootkit
    #      MajorFunction[] hooks). No-op when EMU_OPTS['fake_drivers']
    #      is empty: the override defers to Speakeasy's native impl
    #      for every name.
    from shim_fake_driver import install_fake_driver_hooks
    install_fake_driver_hooks(emu, arch_bits, log_func=log_func)


    return state

# Re-export key helpers ktrace expects from shim
def map_kernel_data_pages(emu, arch_bits=32):
    """RWX a few well-known kernel pages, and seed KUSER_SHARED_DATA
    with current host time so drivers that read SystemTime/TickCount
    from there (instead of via KeQuerySystemTime) see real values
    rather than zeros."""
    from speakeasy.common import PERM_MEM_RWX
    pages = [0x803d0000, 0x803d1000, 0xc1000000]
    kuser = None
    if arch_bits == 64:
        # KUSER_SHARED_DATA mirror on x64. Skip on x86 — the address is
        # >4 GiB and mem_protect there has odd side effects.
        kuser = 0xfffff78000000000
        pages.append(kuser)
    for base in pages:
        try: emu.emu.mem_protect(base, 0x1000, PERM_MEM_RWX)
        except: pass
    if kuser is not None:
        # Populate KUSER_SHARED_DATA.SystemTime (offset 0x14, 12 bytes:
        # ULONG LowPart, ULONG High1Time, ULONG High2Time — atomic
        # reader pattern) and InterruptTime (0x08, same layout).
        # Driver code that reads `_DAT_fffff78000000014` directly and
        # hands it to ExSystemTimeToLocalTime / RtlTimeToTimeFields
        # then renders real timestamps in its log output instead of
        # `0000-00-00 00:00:00`.
        import time as _time
        import struct as _struct
        # Ensure the page is mapped — mem_protect above only succeeds
        # if it was already mapped by Speakeasy; on some configs it
        # isn't, so try a mem_map and ignore "already mapped".
        try:
            emu.emu.mem_map(0x1000, base=kuser,
                            tag='ktrace.kuser_shared_data',
                            perms=PERM_MEM_RWX)
        except Exception:
            pass
        # Windows FILETIME = 100-ns intervals since 1601-01-01 UTC.
        # Python time.time() = seconds since 1970-01-01 UTC.
        # Delta seconds 1601→1970 = 11644473600.
        ft = int((_time.time() + 11644473600) * 10_000_000)
        low  = ft & 0xFFFFFFFF
        high = (ft >> 32) & 0xFFFFFFFF
        try:
            ksys = _struct.pack('<III', low, high, high)
            emu.emu.mem_write(kuser + 0x14, ksys)   # SystemTime
            emu.emu.mem_write(kuser + 0x08, ksys)   # InterruptTime — rough
        except Exception:
            pass

def rewrite_stubs(emu, decoy, mod_name, arch_bits):
    import struct
    base = decoy.get_base()
    try: hdr = bytes(emu.mem_read(base, 0x400))
    except: return 0
    e_lfa = struct.unpack('<I', hdr[0x3c:0x40])[0]
    opt_hdr_off = e_lfa + 0x18
    magic = struct.unpack('<H', hdr[opt_hdr_off:opt_hdr_off+2])[0]
    exp_rva_off = opt_hdr_off + (0x60 if magic == 0x10b else 0x70)
    exp_rva = struct.unpack('<I', hdr[exp_rva_off:exp_rva_off+4])[0]
    if exp_rva == 0: return 0
    exp_data = bytes(emu.mem_read(base + exp_rva, 0x28))
    _,_,_,_,_,_,n_funcs,n_names,af,an,ano = struct.unpack('<IIHHIIIIIII', exp_data)
    n = 0
    for i in range(n_names):
        try:
            np = struct.unpack('<I', emu.mem_read(base+an+i*4, 4))[0]
            nm = bytes(emu.mem_read(base+np, 64)).split(b'\x00',1)[0].decode('latin1')
            oi = struct.unpack('<H', emu.mem_read(base+ano+i*2, 2))[0]
            fr = struct.unpack('<I', emu.mem_read(base+af+oi*4, 4))[0]
            if fr == 0: continue
            sa = base+fr
            tg = emu.emu.get_proc(mod_name, nm)
            r32 = (tg - (sa+5)) & 0xFFFFFFFF
            emu.mem_write(sa, b'\xE9'+struct.pack('<I', r32))
            n += 1
        except: pass
    return n
