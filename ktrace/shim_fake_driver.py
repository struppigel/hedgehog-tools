"""Synthetic DRIVER_OBJECTs for nsiproxy-style hook targets.

Many rootkits hook another driver's MajorFunction[] table after looking
it up by name (e.g. \\Driver\\nsiproxy, \\Driver\\Tcpip, \\Driver\\Disk).
Pure Speakeasy auto-creates a zero-MajorFunction driver object on
ObReferenceObjectByName, but:

  1. The malware reads MajorFunction[+0xE0] to save as "original" —
     gets 0, then the CFG-protected indirect call to the saved value
     would crash if we ever fired the hooked path.
  2. ktrace never fires anything against the foreign driver, so the
     installed hook + its completion routine never execute.

This module fixes both:

  - `install_fake_driver_hooks(emu, arch_bits)` overrides
    `Ntoskrnl.ObReferenceObjectByName` so that names listed in
    `EMU_OPTS['fake_drivers']` get a freshly-allocated DRIVER_OBJECT
    with MajorFunction[IRP_MJ_DEVICE_CONTROL] pre-populated with a 4-
    byte stub (`xor eax,eax; ret`) we own. A code-hook fires on that
    stub; it captures the IRP's IO_STACK_LOCATION.CompletionRoutine /
    Context the malware installed, sets IoStatus.Status=SUCCESS and
    .Information=outlen, writes the user-supplied test payload into
    SystemBuffer, then lets `xor/ret` finish normally so the malware's
    hook returns.
  - `fire_fake_driver_irps(...)` is called by ktrace after the regular
    IOCTL synthesis phase. For each `--fake-driver-irp` spec, it reads
    the (now-possibly-hooked) MajorFunction[+0xE0] from the fake
    DRIVER_OBJECT, synthesises an IRP, calls the hooked dispatcher,
    then manually invokes the captured completion routine via
    `emu.call()` so its body gets traced.

Regression safety: when `EMU_OPTS['fake_drivers']` is empty, the
ObReferenceObjectByName override falls through to the original
Speakeasy implementation for every name, so no behaviour changes for
drivers that don't use the feature.
"""
from __future__ import annotations
import struct

from speakeasy.winenv.api.kernelmode import ntoskrnl as _ntos_mod
import speakeasy.winenv.defs.nt.ddk as ddk

import irp as _irp_layout
from shim_state import EMU_OPTS


# --- module-level state -----------------------------------------------------
# Populated lazily by the ObReferenceObjectByName override.
# Keyed by lowercase NT name (e.g. "\\driver\\nsiproxy").
FAKE_DRV_STATE = {
    # name -> {
    #   'addr': <DRIVER_OBJECT base>,
    #   'stub_addr': <4-byte xor/ret stub>,
    #   'last_irp': <IRP ptr captured by the stub hook>,
    #   'last_compl_rt': <CompletionRoutine captured from IOSL+0x38>,
    #   'last_compl_ctx': <Context captured from IOSL+0x40>,
    # }
}

# The original Speakeasy ObReferenceObjectByName method object. We save it
# at install time and delegate to it for names not in our list, so
# behaviour for non-fake-driver-using runs is bit-for-bit unchanged.
_ORIGINAL_OBREF = None


def set_fake_drivers(names):
    """Accept a list or comma-separated string of driver names. Stored
    lowercased so lookups are case-insensitive. Each name should look like
    "\\Driver\\nsiproxy"; we don't enforce that to allow looser matches."""
    if isinstance(names, str):
        items = [s.strip() for s in names.split(',') if s.strip()]
    else:
        items = list(names or [])
    EMU_OPTS['fake_drivers'] = [n.lower().replace('\x00', '') for n in items]


def _drvobj_size(arch_bits: int) -> int:
    L = _irp_layout.layout_for(arch_bits)
    # MajorFunction[] start + 28 slots × ptr_size. Speakeasy uses 0x150
    # on x64; we match.
    return L['do_MajorFunction'] + 28 * L['ptr_size']


def _alloc_fake_driver(emu, name: str, arch_bits: int):
    """Allocate + initialise a DRIVER_OBJECT for `name`. Returns the new
    state dict (also cached in FAKE_DRV_STATE).
    """
    L = _irp_layout.layout_for(arch_bits)
    do_size = _drvobj_size(arch_bits)

    # UNICODE_STRING name buffer follows the struct.
    name_buf = name.encode('utf-16le')
    total = do_size + len(name_buf)
    base = emu.mem_map(total, base=None,
                       tag=f'ktrace.fake_driver.{name}', perms=7)
    emu.mem_write(base, b'\x00' * total)

    # Standard DRIVER_OBJECT header.
    # +0x00 Type = IO_TYPE_DRIVER (4), +0x02 Size = do_size.
    emu.mem_write(base + 0x00, struct.pack('<H', 4))
    emu.mem_write(base + 0x02, struct.pack('<H', do_size))
    # +do_Flags = 2 (DO_VERIFY_VOLUME? — Speakeasy uses 2; mirror it).
    emu.mem_write(base + L['do_Flags'], struct.pack('<I', 2))

    # DriverName.Length / .MaximumLength / .Buffer.
    name_addr = base + do_size
    emu.mem_write(name_addr, name_buf)
    name_struct_off = L['do_DriverName_Length']
    emu.mem_write(base + name_struct_off,
                  struct.pack('<HH', len(name_buf), len(name_buf)))
    # Buffer pointer lives at do_DriverName_Buffer.
    emu.mem_write(base + L['do_DriverName_Buffer'],
                  struct.pack(L['pack'], name_addr))

    # Allocate a 4-byte xor/ret stub: 31 C0 C3.  RAX = STATUS_SUCCESS (0),
    # then near-return.  When the malware reads MajorFunction[+0xE0] from
    # our DRIVER_OBJECT and CFG-dispatches to that pointer, control lands
    # here. A code-hook (installed below) fires *before* the instructions
    # execute and captures the IRP's completion-routine pointer.
    stub_addr = emu.mem_map(0x10, base=None,
                            tag=f'ktrace.fake_driver.{name}.stub',
                            perms=7)
    emu.mem_write(stub_addr, b'\x31\xC0\xC3' + b'\x90' * 0x0D)

    # Allocate a synthetic DEVICE_OBJECT under this driver. Rootkits/
    # cheats that hook a foreign driver typically follow up by
    # IoEnumerateDeviceObjectList → walk the chain → IoAttachDevice
    # on the result. Without a device the walk returns
    # STATUS_NO_MORE_ENTRIES and the sample bails before installing
    # its attach. We just need ONE device per fake driver — its
    # back-pointer to the DRIVER_OBJECT is what the downstream code
    # actually reads (chain.DeviceObject.DriverObject == us).
    #
    # DEVICE_OBJECT layout (x64), only the fields a hook-walking
    # caller is likely to dereference:
    #   +0x00  SHORT Type = FILE_TYPE_DEVICE (3)
    #   +0x02  USHORT Size
    #   +0x04  LONG  ReferenceCount = 1
    #   +0x08  PDRIVER_OBJECT DriverObject ← back-pointer
    #   +0x10  PDEVICE_OBJECT NextDevice = 0  (single-device chain)
    #   +0x18  PDEVICE_OBJECT AttachedDevice = 0
    #   +0x30  ULONG Flags
    #   +0x34  ULONG Characteristics
    #   +0x48  ULONG DeviceType
    DO_SIZE = 0x150
    devobj_addr = emu.mem_map(DO_SIZE, base=None,
                              tag=f'ktrace.fake_driver.{name}.devobj',
                              perms=7)
    emu.mem_write(devobj_addr, b'\x00' * DO_SIZE)
    emu.mem_write(devobj_addr + 0x00, struct.pack('<H', 3))   # Type
    emu.mem_write(devobj_addr + 0x02, struct.pack('<H', DO_SIZE))
    emu.mem_write(devobj_addr + 0x04, struct.pack('<I', 1))   # RefCount
    emu.mem_write(devobj_addr + 0x08,
                  struct.pack(L['pack'], base))               # DriverObject
    # NextDevice / AttachedDevice / DeviceExtension stay zero.
    # Wire the DRIVER_OBJECT.DeviceObject head-of-chain to point here.
    emu.mem_write(base + L['do_DeviceObject'],
                  struct.pack(L['pack'], devobj_addr))

    # Pre-populate MajorFunction[IRP_MJ_DEVICE_CONTROL] (and the related
    # majors a hook-using rootkit might steal too: INTERNAL_DEVICE_CONTROL,
    # CREATE, CLEANUP, CLOSE) with the stub. The malware can hook any of
    # them; we want the saved-original it reads to be callable.
    HOOKED_MAJORS = (0x00,  # CREATE
                     0x02,  # CLOSE
                     0x0E,  # DEVICE_CONTROL  (the only one PoisonX uses)
                     0x0F,  # INTERNAL_DEVICE_CONTROL
                     0x12)  # CLEANUP
    mf_base = base + L['do_MajorFunction']
    for mj in HOOKED_MAJORS:
        emu.mem_write(mf_base + mj * L['ptr_size'],
                      struct.pack(L['pack'], stub_addr))

    state = {
        'addr': base,
        'stub_addr': stub_addr,
        'devobj_addr': devobj_addr,
        'name': name,
        'last_irp': 0,
        'last_compl_rt': 0,
        'last_compl_ctx': 0,
        'last_devobj': 0,
        'arch_bits': arch_bits,
    }
    FAKE_DRV_STATE[name.lower()] = state

    # Register the code-hook on the stub.  Speakeasy's add_code_hook takes
    # begin/end where end is exclusive; one-byte window matching `xor`
    # opcode at stub_addr is enough — that's the first instruction the
    # CFG indirect call lands on.
    def _on_stub(emu_obj, addr, size, cb_ctx):
        # We register the hook with begin=1/end=0 ("fire everywhere")
        # because narrow [begin, end) ranges are not respected by
        # every unicorn build paired with Speakeasy's wrapper. Filter
        # to our stub's actual address inside the callback. The hot-
        # path overhead is minimal — one int comparison per PC.
        st = state
        if addr != st['stub_addr']:
            return
        try:
            st['_stub_hits'] = st.get('_stub_hits', 0) + 1
            _stub_fire(emu_obj, st)
        except Exception as e:
            st['_stub_err'] = repr(e)

    # add_code_hook lives on the high-level Speakeasy object (emu.emu in
    # ktrace conventions). end=0 means "fire for every PC" which is way
    # too noisy; we want a tight window.
    try:
        # Register as a fire-everywhere hook (begin=1, end=0). The
        # callback filters internally on PC == stub_addr. ktrace's
        # existing add_mem_write_hook pattern uses this same idiom —
        # narrow ranges via begin/end are not reliable on every
        # unicorn build, but PC filtering inside the callback is.
        emu.add_code_hook(_on_stub, begin=1, end=0)
    except Exception:
        pass

    return state


def _stub_fire(emu_obj, state):
    """Code-hook callback. Fires when the malware's hook does
    `(*PTR_guard_dispatch_icall)(devobj, irp)` with the saved-original
    pointer in RAX — control lands on our `xor eax,eax; ret` stub.

    We grab the IRP (RDX), walk to its IO_STACK_LOCATION, capture the
    completion routine + context the hook just installed, then set
    IoStatus.Status = STATUS_SUCCESS and .Information = OutputBufferLength
    so the hooked dispatcher's wrapper sees a successful "original" call.
    """
    L = _irp_layout.layout_for(state['arch_bits'])
    if state['arch_bits'] == 64:
        irp_ptr = emu_obj.reg_read('rdx')
        devobj = emu_obj.reg_read('rcx')
    else:
        # __stdcall: devobj/irp are pushed; argv passed via stack.
        # x86 layout: ret_addr @ [esp], arg1 @ [esp+4], arg2 @ [esp+8]
        esp = emu_obj.reg_read('esp')
        devobj = struct.unpack('<I', bytes(emu_obj.mem_read(esp + 4, 4)))[0]
        irp_ptr = struct.unpack('<I', bytes(emu_obj.mem_read(esp + 8, 4)))[0]
    state['last_irp'] = irp_ptr
    state['last_devobj'] = devobj

    if not irp_ptr:
        return

    # Walk IRP -> CurrentStackLocation -> CompletionRoutine.
    iosl = struct.unpack(L['pack'], bytes(emu_obj.mem_read(
        irp_ptr + L['irp_CurrentStackLocation'], L['ptr_size'])))[0]
    if iosl:
        # CompletionRoutine at IOSL+0x38, Context at IOSL+0x40 (x64).
        # x86: +0x1C / +0x20.
        if state['arch_bits'] == 64:
            cr_off, ctx_off = 0x38, 0x40
        else:
            cr_off, ctx_off = 0x1C, 0x20
        state['last_compl_rt'] = struct.unpack(L['pack'], bytes(
            emu_obj.mem_read(iosl + cr_off, L['ptr_size'])))[0]
        state['last_compl_ctx'] = struct.unpack(L['pack'], bytes(
            emu_obj.mem_read(iosl + ctx_off, L['ptr_size'])))[0]

    # Mark the IRP completed with success + Information from the
    # IOSL's OutputBufferLength (so the completion routine sees a
    # buffer of the right size).
    try:
        out_len = struct.unpack('<I', bytes(emu_obj.mem_read(
            iosl + L['iostack_OutputBufferLength'], 4)))[0]
    except Exception:
        out_len = 0
    emu_obj.mem_write(irp_ptr + L['irp_IoStatus_Status'],
                      struct.pack('<I', 0))  # STATUS_SUCCESS
    emu_obj.mem_write(irp_ptr + L['irp_IoStatus_Information'],
                      struct.pack(L['pack'], out_len))


def prealloc_fake_drivers(emu_high, arch_bits, log_func=None):
    """Allocate fake DRIVER_OBJECTs + register their code hooks BEFORE
    any emulation begins. Called from ktrace.py after the Speakeasy
    instance is constructed but before run_module/call. Adding code
    hooks here (rather than lazily from inside an apihook callback)
    is required because unicorn won't re-route PC to a callback that
    was added mid-run."""
    if not (EMU_OPTS.get('fake_drivers') or []):
        return
    # emu_high is the high-level Speakeasy wrapper; the WinKernelEmulator
    # is at .emu.  Allocation needs the low-level emu, code-hook
    # registration is identical on both (the high-level just delegates).
    inner = getattr(emu_high, 'emu', None) or emu_high
    for name in EMU_OPTS['fake_drivers']:
        if name.lower() in FAKE_DRV_STATE:
            continue
        try:
            st = _alloc_fake_driver(inner, name, arch_bits)
        except Exception as e:
            if log_func:
                log_func(f"# fake-driver: prealloc failed for {name!r}: {e}")
            continue
        if log_func:
            log_func(f"# fake-driver: pre-allocated DRIVER_OBJECT for "
                     f"{name} at 0x{st['addr']:x} "
                     f"(stub @ 0x{st['stub_addr']:x})")


def install_fake_driver_hooks(emu, arch_bits, log_func=None):
    """Install the name-aware ObReferenceObjectByName override.

    Idempotent: calling twice doesn't re-wrap the original.
    """
    global _ORIGINAL_OBREF
    if EMU_OPTS.get('fake_drivers') is None:
        EMU_OPTS['fake_drivers'] = []

    if _ORIGINAL_OBREF is not None:
        return  # already installed

    # Save Speakeasy's native impl.  We grab the unbound function so we
    # can call it with (self, emu, argv, ctx) just like apihook would.
    _ORIGINAL_OBREF = _ntos_mod.Ntoskrnl.ObReferenceObjectByName

    from speakeasy.winenv.api import api as api_module
    apihook = api_module.ApiHandler.apihook

    def _our_obref(self, emu_arg, argv, ctx={}):
        """Name-aware override. If the requested name is in the
        --fake-driver list, return our fake DRIVER_OBJECT. Otherwise
        defer to Speakeasy's native impl."""
        fake_list = EMU_OPTS.get('fake_drivers') or []
        if not fake_list or not argv or not argv[0]:
            return _ORIGINAL_OBREF(self, emu_arg, argv, ctx)

        # Peek at the name WITHOUT clobbering argv[0]: Speakeasy's
        # native impl reads argv[0] again as a UNICODE_STRING pointer,
        # so if we overwrite it with a Python string and then fall
        # through, the native impl crashes.
        try:
            peek = self.read_unicode_string(argv[0]).replace('\x00', '')
        except Exception:
            return _ORIGINAL_OBREF(self, emu_arg, argv, ctx)

        if peek.lower() not in fake_list:
            return _ORIGINAL_OBREF(self, emu_arg, argv, ctx)

        # We're handling this one — now we can clobber argv[0] for the
        # tracer's decoder (matches Speakeasy native convention).
        argv[0] = peek
        name = peek

        # Lazy-allocate the fake DRIVER_OBJECT on first lookup.
        st = FAKE_DRV_STATE.get(name.lower())
        if st is None:
            try:
                st = _alloc_fake_driver(emu_arg, name, arch_bits)
            except Exception as e:
                if log_func:
                    log_func(f"# fake-driver: alloc failed for {name!r}: {e}")
                # Restore argv[0] so the native fallback can re-read.
                # (We can't recover the original pointer, so the
                # native call will see our string and fail — but at
                # least it'll be a tracked failure, not a silent one.)
                return _ORIGINAL_OBREF(self, emu_arg, argv, ctx)
            if log_func:
                log_func(f"# fake-driver: allocated DRIVER_OBJECT for "
                         f"{name} at 0x{st['addr']:x} "
                         f"(stub @ 0x{st['stub_addr']:x})")

        # Write our DRIVER_OBJECT pointer to *argv[7] (objptr param).
        if len(argv) > 7 and argv[7]:
            try:
                ptr_size = 8 if arch_bits == 64 else 4
                self.mem_write(argv[7],
                               st['addr'].to_bytes(ptr_size, 'little'))
            except Exception:
                pass
        return ddk.STATUS_SUCCESS

    # Reinstall via apihook so Speakeasy treats it the same as any other
    # tracked API (the existing argc=8 entry is preserved).
    _ntos_mod.Ntoskrnl.ObReferenceObjectByName = apihook(
        'ObReferenceObjectByName', argc=8)(_our_obref)


# ---------------------------------------------------------------------------
# Post-IRP-phase: fire IRPs through the (possibly-hooked) fake-driver
# dispatcher and invoke the captured completion routines.
# ---------------------------------------------------------------------------
def parse_irp_spec(spec: str):
    """Parse `NAME:IOCTL=CODE,OUT=N[,IN=HEX]` into a dict.

    Examples:
      \\Driver\\nsiproxy:IOCTL=0x12001B,OUT=0x70
      \\Driver\\nsiproxy:IOCTL=0x12001B,OUT=0x70,IN=DEADBEEF

    For sample-specific buffer shapes (NSI TCP keys, file-info layouts,
    registry value blobs, …), use a profile in profiles.py that declares
    a `fake_driver_irps` entry with an `input_builder` — ktrace's
    profile dispatcher converts those into pre-built specs before
    calling here.
    """
    name_part, _, rest = spec.partition(':')
    if not rest:
        raise ValueError(f"missing IOCTL=… part in {spec!r}")
    fields = {}
    for kv in rest.split(','):
        if '=' not in kv:
            continue
        k, v = kv.split('=', 1)
        fields[k.strip().upper()] = v.strip()
    if 'IOCTL' not in fields or 'OUT' not in fields:
        raise ValueError(f"--fake-driver-irp needs IOCTL=… and OUT=… "
                         f"(got {spec!r})")
    ioctl = int(fields['IOCTL'], 0)
    outlen = int(fields['OUT'], 0)
    in_hex = fields.get('IN', '')
    in_buf = bytes.fromhex(in_hex) if in_hex else b''
    return {'name': name_part.lower(), 'ioctl': ioctl,
            'outlen': outlen, 'input': in_buf,
            'extra_dumps': []}


def fire_fake_driver_irps(emu, tracer, log_fn, resolve_addr,
                          arch_bits, specs, decode_mod):
    """For each fake-driver IRP spec, fire an IRP through the
    fake-driver's +0xE0 dispatcher (whatever it now points at) and
    invoke the captured completion routine. Returns list of result dicts.
    """
    import irp as _irp
    L = _irp.layout_for(arch_bits)
    results = []
    if not specs:
        return results

    for spec in specs:
        name_key = spec['name']
        st = FAKE_DRV_STATE.get(name_key)
        if st is None:
            log_fn(f"# fake-driver-irp: {spec['name']!r} was never "
                   f"referenced by ObReferenceObjectByName — skipping. "
                   f"(Did the driver gate the lookup on a flag/state "
                   f"that ktrace didn't satisfy?)")
            continue

        # Read the current MajorFunction[IRP_MJ_DEVICE_CONTROL].
        mf_devctl_addr = (st['addr'] + L['do_MajorFunction']
                          + 0x0E * L['ptr_size'])
        cur_handler = struct.unpack(L['pack'], bytes(
            emu.mem_read(mf_devctl_addr, L['ptr_size'])))[0]
        if cur_handler == st['stub_addr']:
            log_fn(f"# fake-driver-irp: NO HOOK installed on "
                   f"{spec['name']} +0xE0 — still pointing at our stub "
                   f"0x{cur_handler:x}. Skipping IRP fire.")
            continue

        log_fn('')
        log_fn(f"--- Fake driver: {spec['name']} "
               f"(fake DRIVER_OBJECT @ 0x{st['addr']:x})")
        log_fn(f"  MajorFunction[IRP_MJ_DEVICE_CONTROL] = "
               f"0x{cur_handler:x} ({resolve_addr(cur_handler)}) "
               f"<-- sample's installed hook")

        # Allocate a fake DEVICE_OBJECT to pass to the hook. The hook
        # dereferences nothing on it (in PoisonX's case) but other
        # samples might, so give it a small block of zeros.
        try:
            fake_devobj = emu.emu.mem_map(0x100, base=None,
                                          tag=f'ktrace.fake_driver.{name_key}.devobj',
                                          perms=7)
            emu.mem_write(fake_devobj, b'\x00' * 0x100)
            # DriverObject backpointer at DEVICE_OBJECT+0x08 (x64) so
            # `Irp->Tail.Overlay.OriginalFileObject->DeviceObject->DriverObject`
            # chains (if used) point back to us.
            emu.mem_write(fake_devobj + 8,
                          struct.pack(L['pack'], st['addr']))
        except Exception:
            fake_devobj = st['addr']  # fall back

        # Reset capture slots before firing.
        st['last_irp'] = 0
        st['last_compl_rt'] = 0
        st['last_compl_ctx'] = 0

        # Build the IRP. The same buffer is used as both the user-
        # supplied descriptor (InputBufferLength) and the system buffer
        # the completion routine inspects.
        s, info, out_pre = _irp.synth_irp(
            emu, cur_handler, arch_bits, 0x0E, fake_devobj,
            ioctl_code=spec['ioctl'], output_len=spec['outlen'],
            input_buf=spec['input'])
        if s is None:
            log_fn(f"  [hook-fire IOCTL=0x{spec['ioctl']:x}] "
                   f"dispatcher raised — no result")
            continue

        log_fn(f"  [hook-fire IOCTL=0x{spec['ioctl']:x} OUT={spec['outlen']}] "
               f"hooked-dispatch returned status="
               f"{decode_mod.fmt_status(s)} Information={info}")
        if st.get('_stub_err'):
            log_fn(f"  [warn] stub @0x{st['stub_addr']:x} raised: "
                   f"{st['_stub_err']}")
        tracer.replay_new(section=(
            f"APIs inside hooked dispatcher 0x{cur_handler:x}:"))

        # The code-hook should have captured the completion routine the
        # malware installed.  Call it manually so its body gets traced.
        compl_rt = st['last_compl_rt']
        compl_ctx = st['last_compl_ctx']
        captured_irp = st['last_irp']
        if compl_rt:
            log_fn(f"  Captured CompletionRoutine = 0x{compl_rt:x} "
                   f"({resolve_addr(compl_rt)}); "
                   f"Context = 0x{compl_ctx:x}")
            # Pre-fill the IRP's SystemBuffer with the test payload now
            # that we know completion routine will read it. (We do this
            # AFTER the hooked dispatcher returns because the dispatcher
            # may have overwritten the buffer when forwarding.)
            sysbuf = struct.unpack(L['pack'], bytes(emu.mem_read(
                captured_irp + L['irp_AssociatedIrp_SystemBuffer'],
                L['ptr_size'])))[0]
            if sysbuf and spec['input']:
                try:
                    emu.mem_write(sysbuf,
                                  spec['input'][:spec['outlen']]
                                  .ljust(spec['outlen'], b'\x00'))
                except Exception:
                    pass
            try:
                emu.call(compl_rt, [fake_devobj, captured_irp, compl_ctx])
            except Exception as e:
                log_fn(f"  CompletionRoutine call raised: {e}")
            tracer.replay_new(section=(
                f"APIs inside CompletionRoutine 0x{compl_rt:x}:"))

            # Dump the response-header buffer (the descriptor the
            # completion routine reads its stride/count from).
            try:
                if sysbuf:
                    post = bytes(emu.mem_read(sysbuf, spec['outlen']))
                    log_fn(f"  Post-CompletionRoutine SystemBuffer "
                           f"({len(post)}B): {post.hex()}")
            except Exception:
                pass

            # Profiles can attach extra out-of-band buffers to dump
            # after the completion routine runs (e.g. an NSI entries
            # array that the response header pointed at). Each entry
            # is (label, addr, length[, formatter]). If no formatter
            # is provided we just hex-dump.
            for region in spec.get('extra_dumps') or []:
                if len(region) == 4:
                    label, addr, length, formatter = region
                else:
                    label, addr, length = region
                    formatter = None
                try:
                    rb = bytes(emu.mem_read(addr, length))
                except Exception as exc:
                    log_fn(f"  {label}: read failed @ 0x{addr:x}: {exc}")
                    continue
                if formatter:
                    try:
                        formatter(log_fn, label, addr, rb)
                    except Exception as exc:
                        log_fn(f"  {label} formatter raised: {exc}")
                else:
                    log_fn(f"  Post-CompletionRoutine {label} "
                           f"({length}B): {rb.hex()}")
        else:
            log_fn(f"  No CompletionRoutine was installed by the hooked "
                   f"dispatcher (IOSL+0x38 = 0).")

        results.append({
            'spec': spec,
            'hook_target': cur_handler,
            'compl_rt': compl_rt,
            'compl_ctx': compl_ctx,
        })
    return results
