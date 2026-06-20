"""TDI IRP fakery — ObReferenceObjectByHandle / IoGetRelatedDeviceObject /
IoBuildDeviceIoControlRequest / IofCallDriver / IoFreeIrp overrides that
synthesize the kernel-mode TDI dispatch chain for drivers that open
\\Device\\Udp or \\Device\\Tcp via ZwCreateFile and then issue TDI IRPs.

`install_tdi_faker` is called from install_shim with the same `state`
dict so the IRP/file-object tables persist for the duration of the run."""
import struct as _struct
from speakeasy.winenv.api import api as api_module
from speakeasy.winenv import arch as _arch
from shim_fake_io import FAKE_IO
apihook = api_module.ApiHandler.apihook


def install_tdi_faker(arch_bits, ntos_mod, conv, state):
    is64 = (arch_bits == 64)
    _fmt_ptr = '<Q' if is64 else '<I'
    _ptr_sz = 8 if is64 else 4

    state['tdi'] = {
        'fileobj_for_handle': {},
        'devobj_to_kind': {},
        'irp_meta': {},
    }

    def _canned_response_bytes():
        # Read at call-time, not install-time: ktrace.py's CLI handlers
        # set EMU_OPTS *after* install_shim runs. Lazy lookup so a
        # single --fake-tdi-response feeds both this IRP path and the
        # ZwReadFile-on-TDI-handle path in shim_fake_io.py.
        try:
            from shim_state import EMU_OPTS as _EO
            return _EO.get('canned_tdi_response') or b''
        except Exception:
            return b''

    def _tdi_kind_from_path(path):
        if not path:
            return 'other'
        p = path.lower()
        if 'udp' in p:
            return 'udp'
        if 'tcp' in p:
            return 'tcp'
        if 'rawip' in p or 'ip4' in p or 'ip6' in p:
            return 'rawip'
        return 'other'

    def _tdi_alloc_fileobj(emu_arg, handle, path):
        """Allocate a synthetic FILE_OBJECT (and back-pointed DEVICE_OBJECT
        + SECTION_OBJECT_POINTERS) for any handle that ObReferenceObjectByHandle
        is asked about. Originally for TDI sockets — kept the name — but now
        also serves any fake-io file handle since drivers commonly do
        `Ob*ByHandle(h, …, &FO); rcx = FO->SectionObjectPointer; …` for
        image-flush / self-delete / FS-filter patterns (e.g. the TpSafe.sys
        driver, sha 0856a1da…, self-deletes after init via
        MmFlushImageSection + ZwDeleteFile)."""
        if handle in state['tdi']['fileobj_for_handle']:
            return state['tdi']['fileobj_for_handle'][handle]
        from speakeasy.common import PERM_MEM_RWX
        fo_size = 0xc8
        do_size = 0x150
        sop_size = 0x30    # SECTION_OBJECT_POINTERS = 3 pointers, padded
        mm = (getattr(emu_arg, 'mem_map', None) or
              getattr(getattr(emu_arg, 'emu', None), 'mem_map', None))
        if not mm:
            return 0
        try:
            blk = mm(fo_size + do_size + sop_size, base=None,
                     tag='ktrace.fileobj', perms=PERM_MEM_RWX)
        except Exception:
            return 0
        fo = blk
        do = blk + fo_size
        sop = blk + fo_size + do_size
        try:
            emu_arg.mem_write(fo, b'\x05\x00')  # FILE_OBJECT.Type=5
            emu_arg.mem_write(fo + 2, _struct.pack('<H', fo_size))
            emu_arg.mem_write(fo + (8 if is64 else 4),
                              _struct.pack(_fmt_ptr, do))
            # FILE_OBJECT.SectionObjectPointer @ +0x28 (x64) / +0x14 (x86)
            sop_off = 0x28 if is64 else 0x14
            emu_arg.mem_write(fo + sop_off, _struct.pack(_fmt_ptr, sop))
            emu_arg.mem_write(sop, b'\x00' * sop_size)
            emu_arg.mem_write(do, b'\x03\x00')   # DEVICE_OBJECT.Type=3
            emu_arg.mem_write(do + 2, _struct.pack('<H', do_size))
        except Exception:
            pass
        state['tdi']['fileobj_for_handle'][handle] = fo
        state['tdi']['devobj_to_kind'][do] = _tdi_kind_from_path(path)
        return fo

    def _ob_ref_by_handle_common(self, emu_arg, hnd, out_obj):
        path = FAKE_IO.get('handle_to_path', {}).get(hnd)
        if path is not None:
            fo = _tdi_alloc_fileobj(emu_arg, hnd, path)
            if out_obj and fo:
                try:
                    emu_arg.mem_write(out_obj,
                                      fo.to_bytes(_ptr_sz, 'little'))
                except Exception:
                    pass
            return 0
        try:
            obj = self.get_object_from_handle(hnd)
        except Exception:
            obj = None
        if obj:
            if out_obj:
                try:
                    emu_arg.mem_write(out_obj,
                                      obj.address.to_bytes(_ptr_sz, 'little'))
                except Exception:
                    pass
            return 0
        return 0xC0000008  # STATUS_INVALID_HANDLE

    @apihook('ObReferenceObjectByHandle', argc=6, conv=conv)
    def ObReferenceObjectByHandle_tdi(self, emu_arg, argv, ctx={}):
        hnd, _access, _obtype, _mode, out_obj, _ohi = argv
        return _ob_ref_by_handle_common(self, emu_arg, hnd, out_obj)
    ntos_mod.Ntoskrnl.ObReferenceObjectByHandle = ObReferenceObjectByHandle_tdi

    @apihook('ObReferenceObjectByHandleWithTag', argc=7, conv=conv)
    def ObReferenceObjectByHandleWithTag_tdi(self, emu_arg, argv, ctx={}):
        # NTSTATUS ObReferenceObjectByHandleWithTag(
        #   HANDLE Handle, ACCESS_MASK Access, POBJECT_TYPE ObjectType,
        #   KPROCESSOR_MODE AccessMode, ULONG Tag, PVOID *Object,
        #   POBJECT_HANDLE_INFORMATION HandleInformation);
        hnd = argv[0]
        out_obj = argv[5] if len(argv) > 5 else 0
        return _ob_ref_by_handle_common(self, emu_arg, hnd, out_obj)
    ntos_mod.Ntoskrnl.ObReferenceObjectByHandleWithTag = (
        ObReferenceObjectByHandleWithTag_tdi)

    @apihook('IoGetRelatedDeviceObject', argc=1, conv=conv)
    def IoGetRelatedDeviceObject_tdi(self, emu_arg, argv, ctx={}):
        fo = argv[0] if argv else 0
        if not fo:
            return 0
        # If the caller passed a FILE_OBJECT (Type=5), return its
        # DeviceObject field. If they (incorrectly but commonly) passed a
        # DEVICE_OBJECT (Type=3) — fk_undead does this — return the input
        # itself instead of returning the device's ReferenceCount field
        # (which is at the same +4 offset and reads as ~1, producing
        # bogus device pointers downstream).
        try:
            obj_type = _struct.unpack('<H', bytes(emu_arg.mem_read(fo, 2)))[0]
        except Exception:
            obj_type = 0
        if obj_type == 0x03:          # DEVICE_OBJECT
            return fo
        try:
            return _struct.unpack(_fmt_ptr, bytes(emu_arg.mem_read(
                fo + (8 if is64 else 4), _ptr_sz)))[0]
        except Exception:
            return 0
    ntos_mod.Ntoskrnl.IoGetRelatedDeviceObject = IoGetRelatedDeviceObject_tdi

    @apihook('IoGetLowerDeviceObject', argc=1, conv=conv)
    def IoGetLowerDeviceObject_tdi(self, emu_arg, argv, ctx={}):
        # PDEVICE_OBJECT IoGetLowerDeviceObject(PDEVICE_OBJECT TargetDevice).
        # Returns the next lower device in the stack, or NULL if there is
        # none. Speakeasy's default stub doesn't implement this — the call
        # lands on a 0xfeedf118 sentinel and the emulator bails with
        # `unsupported_api`. For TDI / minifilter / arbitrary-stack-walking
        # drivers there's usually no actual lower device in our emulator;
        # returning the input device itself keeps the caller progressing
        # (typical pattern is `next = IoGetLowerDeviceObject(cur); …
        # ObDereferenceObject(cur); cur = next;` so a self-cycle is broken
        # the first iteration by the caller's own loop condition). The
        # alternative — NULL — makes most drivers bail on a stack-walk
        # before reaching the data-transfer path.
        return argv[0] if argv else 0
    ntos_mod.Ntoskrnl.IoGetLowerDeviceObject = IoGetLowerDeviceObject_tdi

    @apihook('IoGetAttachedDeviceReference', argc=1, conv=conv)
    def IoGetAttachedDeviceReference_tdi(self, emu_arg, argv, ctx={}):
        # PDEVICE_OBJECT IoGetAttachedDeviceReference(PDEVICE_OBJECT). The
        # top of the attach chain; same reasoning as IoGetLowerDeviceObject.
        return argv[0] if argv else 0
    ntos_mod.Ntoskrnl.IoGetAttachedDeviceReference = (
        IoGetAttachedDeviceReference_tdi)

    @apihook('IoGetAttachedDevice', argc=1, conv=conv)
    def IoGetAttachedDevice_tdi(self, emu_arg, argv, ctx={}):
        return argv[0] if argv else 0
    ntos_mod.Ntoskrnl.IoGetAttachedDevice = IoGetAttachedDevice_tdi

    @apihook('IoBuildDeviceIoControlRequest', argc=9, conv=conv)
    def IoBuildDeviceIoControlRequest_tdi(self, emu_arg, argv, ctx={}):
        (ioctl, devobj, in_buf, in_len, out_buf, out_len,
         internal, event, iosb_out) = argv
        from speakeasy.common import PERM_MEM_RWX
        irp_size = 0xe8 if is64 else 0x70
        ios_size = 0x48 if is64 else 0x24
        # Page-sized allocation with the IRP placed `ios_size` bytes into
        # it. Real Windows lays out the IO_STACK_LOCATION array *before*
        # the IRP body and `IoGetNextIrpStackLocation(Irp)` resolves to
        # `CurrentStack - sizeof(IO_STACK_LOCATION)`. The standard
        # `IoSetCompletionRoutine(Irp, fn, ctx, …)` macro then writes
        # `*(NextStack+0x1C)` = `*(CurrentStack-8)`, `*(NextStack+0x20)`
        # = `*(CurrentStack-4)`, `*(NextStack+0x03)` = `*(CurrentStack-
        # 0x21)`. With a tight `irp_size + ios_size` allocation those
        # negative offsets land in unmapped memory and Speakeasy bails
        # via the SEH-dispatch path (`_handle_invalid_write` → TEB
        # read_back, which is None in kernel mode).
        mm = (getattr(emu_arg, 'mem_map', None) or
              getattr(getattr(emu_arg, 'emu', None), 'mem_map', None))
        if not mm:
            return 0
        try:
            # Two pages so the IRP body has plenty of negative-offset
            # headroom (IO_STACK_LOCATION array prepends 0x24-byte slots
            # before the body) AND positive overflow (drivers occasionally
            # read AssociatedIrp at IRP+0x4, Tail.Overlay at IRP+0x60..,
            # CompletionContext blocks past the official size).
            blk = mm(0x2000, base=None,
                     tag='ktrace.tdi.irp', perms=PERM_MEM_RWX)
        except Exception:
            return 0
        # CRITICAL: place CurrentStackLocation BEFORE the IRP body, not
        # after. The IoSetCompletionRoutine macro writes Parameters fields
        # via negative offsets from CurrentStack: e.g. [CurrentStack-0x10]
        # is NextStack->Parameters.DeviceIoControl.OutputBufferLength.
        # If `ios = irp + irp_size`, [ios-0x10] = irp+0x60 = IRP's own
        # Tail.Overlay.CurrentStackLocation slot — the driver's write
        # clobbers CurrentStack to 1 (a Parameters value), and the next
        # `mov eax, [edx+0x60]` then loads 1 and faults at 0xfffffff9.
        # Real Windows places the IO_STACK_LOCATION array immediately
        # *before* the IRP body; replicate that.
        irp = blk + 0x800
        ios = irp - ios_size
        # Defensively touch every page Speakeasy may have lazily mapped so
        # subsequent driver writes don't trip _handle_invalid_write. The
        # pool_alloc path occasionally returns an address whose backing
        # page hasn't been registered with the Unicorn engine yet.
        try:
            for p in range(0, 0x2000, 0x1000):
                emu_arg.mem_write(blk + p, b'\x00')
        except Exception:
            pass
        try:
            emu_arg.mem_write(irp, b'\x00' * (irp_size + ios_size))
            cs_off = 0xb8 if is64 else 0x60
            emu_arg.mem_write(irp + cs_off, _struct.pack(_fmt_ptr, ios))
            mj = 0x0F if internal else 0x0E
            emu_arg.mem_write(ios + 0, bytes([mj & 0xff]))
            emu_arg.mem_write(ios + (0x08 if is64 else 0x04),
                              _struct.pack('<I', out_len & 0xffffffff))
            emu_arg.mem_write(ios + (0x10 if is64 else 0x08),
                              _struct.pack('<I', in_len & 0xffffffff))
            emu_arg.mem_write(ios + (0x18 if is64 else 0x0c),
                              _struct.pack('<I', ioctl & 0xffffffff))
            emu_arg.mem_write(irp + (0x70 if is64 else 0x3c),
                              _struct.pack(_fmt_ptr, out_buf or 0))
            emu_arg.mem_write(irp + (0x18 if is64 else 0x0c),
                              _struct.pack(_fmt_ptr, in_buf or 0))
        except Exception:
            pass
        state['tdi']['irp_meta'][irp] = {
            'ioctl': ioctl, 'devobj': devobj,
            'input_buf': in_buf, 'input_len': in_len,
            'output_buf': out_buf, 'output_len': out_len,
            'internal': bool(internal),
            'iosb_out': iosb_out,
        }
        return irp
    ntos_mod.Ntoskrnl.IoBuildDeviceIoControlRequest = (
        IoBuildDeviceIoControlRequest_tdi)

    def _craft_dns_response(_in_bytes):
        if len(_in_bytes) < 12:
            return b''
        txn = _in_bytes[0:2]
        qstart = 12
        i = qstart
        while i < len(_in_bytes) and _in_bytes[i] != 0:
            ln = _in_bytes[i]
            if ln & 0xC0:
                i += 2
                break
            i += 1 + ln
            if i > 0x200:
                return b''
        i += 1
        i += 4
        if i > len(_in_bytes):
            return b''
        question = _in_bytes[qstart:i]
        hdr = txn + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
        ans = (b'\xC0\x0C\x00\x01\x00\x01\x00\x00\x00\x3C\x00\x04'
               b'\xC0\x00\x02\x01')
        return hdr + question + ans

    @apihook('IofCallDriver', argc=2, conv=_arch.CALL_CONV_FASTCALL)
    def IofCallDriver_tdi(self, emu_arg, argv, ctx={}):
        devobj, irp = argv
        meta = state['tdi']['irp_meta'].get(irp)
        status = 0
        info = 0
        kind = state['tdi']['devobj_to_kind'].get(devobj, 'other')

        out_bytes = b''
        if meta:
            ioctl = meta['ioctl']
            in_bytes = b''
            if meta['input_buf'] and meta['input_len']:
                try:
                    n = min(meta['input_len'], 0x400)
                    in_bytes = bytes(emu_arg.mem_read(
                        meta['input_buf'], n))
                except Exception:
                    pass
            if ioctl in (9,):  # TDI_RECEIVE
                # Prefer analyst-supplied canned response (loaded via
                # --fake-tdi-response). Falls back to a tiny stub if not
                # supplied; many TDI-based unpackers need a *parseable*
                # response (sized payload after `\r\n\r\n` etc.) for the
                # decryption path to fire — see fk_undead_maindrv polling
                # `120.77.36.184:11153/msdvdlx32_up.dat`.
                canned = _canned_response_bytes()
                if canned:
                    out_bytes = canned
                else:
                    out_bytes = (b'HTTP/1.1 200 OK\r\n'
                                 b'Content-Type: image/jpeg\r\n'
                                 b'Content-Length: 4\r\n\r\n'
                                 b'\xff\xd8\xff\xd9')
            elif ioctl in (11,):  # TDI_RECEIVE_DATAGRAM
                canned = _canned_response_bytes()
                if canned:
                    out_bytes = canned
                elif kind == 'udp':
                    out_bytes = _craft_dns_response(in_bytes)
            if ioctl in (8, 10):
                info = meta['input_len']
            if out_bytes and meta['output_buf']:
                clip = out_bytes[:meta['output_len'] or len(out_bytes)]
                try:
                    emu_arg.mem_write(meta['output_buf'], clip)
                except Exception:
                    pass
                info = len(clip)

        try:
            ios_off = 0x30 if is64 else 0x18
            emu_arg.mem_write(irp + ios_off, _struct.pack('<I', status))
            emu_arg.mem_write(irp + ios_off + (8 if is64 else 4),
                              _struct.pack(_fmt_ptr, info))
        except Exception:
            pass
        if meta and meta.get('iosb_out'):
            try:
                emu_arg.mem_write(meta['iosb_out'],
                                  _struct.pack('<I', status))
                emu_arg.mem_write(meta['iosb_out'] + (8 if is64 else 4),
                                  _struct.pack(_fmt_ptr, info))
            except Exception:
                pass
        return status
    ntos_mod.Ntoskrnl.IofCallDriver = IofCallDriver_tdi

    @apihook('IoFreeIrp', argc=1, conv=conv)
    def IoFreeIrp_tdi(self, emu_arg, argv, ctx={}):
        irp = argv[0] if argv else 0
        state['tdi']['irp_meta'].pop(irp, None)
        return 0
    ntos_mod.Ntoskrnl.IoFreeIrp = IoFreeIrp_tdi
