"""Real-looking synthetic DEVICE_OBJECT installer. Filter / stacking
drivers read DeviceType / Characteristics / StackSize from the underlying
device they're attaching to; the default zero-filled stubs cause those
filters to bail out. This module populates the plausible defaults so the
attach path runs."""
import struct as _struct
from speakeasy.winenv.api import api as api_module
from speakeasy.winenv import arch as _arch
apihook = api_module.ApiHandler.apihook


def install_synthetic_device_objects(arch_bits, ntos_mod, conv, state, log_func):
    # ---- Real-looking synthetic DEVICE_OBJECTs ----------------------
    # Filter / stacking drivers read DeviceType/Characteristics/StackSize
    # from the underlying device they're attaching to. Bulk-stub zeros
    # cause the filter to create a malformed mirror device, and many
    # bail out. Populate plausible defaults so the attach path runs.
    #
    # Field offsets (x64 / x86 DEVICE_OBJECT). These are public ABI.
    _DO_OFF = {
        64: dict(Type=0x00, Size=0x02, ReferenceCount=0x04,
                 DriverObject=0x08, NextDevice=0x10, AttachedDevice=0x18,
                 CurrentIrp=0x20, Timer=0x28, Flags=0x30,
                 Characteristics=0x34, Vpb=0x38, DeviceExtension=0x40,
                 DeviceType=0x48, StackSize=0x4c, total=0x100),
        32: dict(Type=0x00, Size=0x02, ReferenceCount=0x04,
                 DriverObject=0x08, NextDevice=0x0c, AttachedDevice=0x10,
                 CurrentIrp=0x14, Timer=0x18, Flags=0x1c,
                 Characteristics=0x20, Vpb=0x24, DeviceExtension=0x28,
                 DeviceType=0x2c, StackSize=0x30, total=0x80),
    }[arch_bits]
    # FILE_OBJECT total size we care about (DeviceObject@+0x4 x86, +0x8 x64).
    _FO_TOTAL = 0x80

    # name → (DeviceObject*, FileObject*) so repeated lookups of the
    # same target return the same pair.
    state['fake_devs'] = {}
    state['attach_lower'] = {}
    # Allocate synthetic DEVICE_OBJECTs at a fixed high base, well away
    # from Speakeasy's own pool / driver-object allocations so its
    # get_object_from_addr lookups don't misclassify our pages as
    # Speakeasy-tracked objects.
    # 0x6f6b1000+ chosen by analogy with the 0x6f6b0000 fake-obj page.
    state['synth_dev_base'] = 0x6f6c0000
    state['synth_dev_next'] = 0x6f6c0000

    def _read_ustr(addr):
        if not addr:
            return ''
        try:
            if arch_bits == 64:
                hdr = bytes(emu.mem_read(addr, 16))
                length = _struct.unpack('<H', hdr[0:2])[0]
                buf = _struct.unpack('<Q', hdr[8:16])[0]
            else:
                hdr = bytes(emu.mem_read(addr, 8))
                length = _struct.unpack('<H', hdr[0:2])[0]
                buf = _struct.unpack('<I', hdr[4:8])[0]
            if not buf or length == 0 or length > 0x400:
                return ''
            data = bytes(emu.mem_read(buf, length))
            return data.decode('utf-16-le', errors='replace').rstrip('\x00')
        except Exception:
            return ''

    def _guess_devtype(name):
        n = name.lower()
        # Built-in name → DEVICE_TYPE heuristics.
        if 'tcp' in n or 'udp' in n or 'ip' in n or 'tdi' in n:
            return 0x12  # FILE_DEVICE_NETWORK
        if 'disk' in n or 'volume' in n or 'physicaldrive' in n:
            return 0x07  # FILE_DEVICE_DISK
        if 'beep' in n or 'null' in n:
            return 0x01  # FILE_DEVICE_BEEP
        if 'keyboard' in n:
            return 0x0b
        if 'mouse' in n or 'pointer' in n:
            return 0x0f
        if 'serial' in n:
            return 0x1b
        if 'parallel' in n:
            return 0x16
        return 0x22  # FILE_DEVICE_UNKNOWN-ish (also matches netfilter chars)

    def _alloc_synthetic_devobj(name='', emu_for_alloc=None):
        if name in state['fake_devs']:
            return state['fake_devs'][name]
        # apihook handlers receive the WinKernelEmulator directly;
        # install_shim's `emu` is the Speakeasy wrapper. Find one with
        # both mem_map and mem_write.
        e = emu_for_alloc if emu_for_alloc is not None else emu
        try:
            from speakeasy.common import PERM_MEM_RWX
            # WinKernelEmulator inherits mem_map from MemoryManager.
            mem_map = getattr(e, 'mem_map', None) or getattr(
                getattr(e, 'emu', None), 'mem_map', None)
            mem_write = getattr(e, 'mem_write', None) or getattr(
                getattr(e, 'emu', None), 'mem_write', None)
            if not mem_map or not mem_write:
                return (0, 0)
            # Round up to page so each pair lives on its own 0x1000.
            dev_base = state['synth_dev_next']
            file_base = dev_base + 0x1000
            state['synth_dev_next'] = file_base + 0x1000
            try:
                dev_addr = mem_map(_DO_OFF['total'], base=dev_base,
                                   tag='ktrace.fake_devobj',
                                   perms=PERM_MEM_RWX)
            except Exception:
                dev_addr = mem_map(_DO_OFF['total'], base=None,
                                   tag='ktrace.fake_devobj',
                                   perms=PERM_MEM_RWX)
            try:
                file_addr = mem_map(_FO_TOTAL, base=file_base,
                                    tag='ktrace.fake_fileobj',
                                    perms=PERM_MEM_RWX)
            except Exception:
                file_addr = mem_map(_FO_TOTAL, base=None,
                                    tag='ktrace.fake_fileobj',
                                    perms=PERM_MEM_RWX)
            mem_write(dev_addr, b'\x00' * _DO_OFF['total'])
            mem_write(file_addr, b'\x00' * _FO_TOTAL)
            # Populate DEVICE_OBJECT.
            buf = bytearray(_DO_OFF['total'])
            _struct.pack_into('<H', buf, _DO_OFF['Type'], 3)   # IO_TYPE_DEVICE
            _struct.pack_into('<H', buf, _DO_OFF['Size'], _DO_OFF['total'])
            _struct.pack_into('<I', buf, _DO_OFF['ReferenceCount'], 1)
            _struct.pack_into('<I', buf, _DO_OFF['Flags'],
                              0x40 | 0x04)  # DO_BUFFERED_IO | DO_EXCLUSIVE
            _struct.pack_into('<I', buf, _DO_OFF['Characteristics'], 0)
            _struct.pack_into('<I', buf, _DO_OFF['DeviceType'],
                              _guess_devtype(name))
            buf[_DO_OFF['StackSize']] = 4
            mem_write(dev_addr, bytes(buf))
            # FILE_OBJECT: link DeviceObject back-ref so dispatchers that
            # read FileObject->DeviceObject get a sensible pointer.
            fbuf = bytearray(_FO_TOTAL)
            _struct.pack_into('<H', fbuf, 0, 5)   # IO_TYPE_FILE
            _struct.pack_into('<H', fbuf, 2, _FO_TOTAL)
            if arch_bits == 64:
                _struct.pack_into('<Q', fbuf, 8, dev_addr)  # DeviceObject
            else:
                _struct.pack_into('<I', fbuf, 4, dev_addr)
            mem_write(file_addr, bytes(fbuf))
        except Exception as exc:
            if log_func:
                log_func(f"  [synth-devobj] alloc failed for {name!r}: {exc}")
            return (0, 0)
        state['fake_devs'][name] = (dev_addr, file_addr)
        return (dev_addr, file_addr)

    state['alloc_synth_devobj'] = _alloc_synthetic_devobj

    _PTR_BYTES = 8 if arch_bits == 64 else 4
    _PTR_FMT = '<Q' if arch_bits == 64 else '<I'

    def _emu_read(emu_arg, addr, n):
        # Both WinKernelEmulator and Speakeasy wrapper expose mem_read.
        return bytes((getattr(emu_arg, 'mem_read', None) or
                      emu_arg.emu.mem_read)(addr, n))

    def _emu_write(emu_arg, addr, data):
        (getattr(emu_arg, 'mem_write', None) or
         emu_arg.emu.mem_write)(addr, data)

    def _read_ustr_emu(emu_arg, addr):
        if not addr:
            return ''
        try:
            if arch_bits == 64:
                hdr = _emu_read(emu_arg, addr, 16)
                length = _struct.unpack('<H', hdr[0:2])[0]
                buf = _struct.unpack('<Q', hdr[8:16])[0]
            else:
                hdr = _emu_read(emu_arg, addr, 8)
                length = _struct.unpack('<H', hdr[0:2])[0]
                buf = _struct.unpack('<I', hdr[4:8])[0]
            if not buf or length == 0 or length > 0x400:
                return ''
            return _emu_read(emu_arg, buf, length).decode(
                'utf-16-le', errors='replace').rstrip('\x00')
        except Exception:
            return ''

    def _io_get_device_object_pointer(self, emu_arg, argv, ctx={}):
        # PUNICODE_STRING ObjectName, ACCESS_MASK Desired,
        # PFILE_OBJECT *FileObject, PDEVICE_OBJECT *DeviceObject
        name = _read_ustr_emu(emu_arg, argv[0]) if argv else ''
        dev_addr, file_addr = _alloc_synthetic_devobj(name, emu_arg)
        if not dev_addr:
            return 0xC0000001  # STATUS_UNSUCCESSFUL
        try:
            if len(argv) > 2 and argv[2]:
                _emu_write(emu_arg, argv[2],
                           file_addr.to_bytes(_PTR_BYTES, 'little'))
            if len(argv) > 3 and argv[3]:
                _emu_write(emu_arg, argv[3],
                           dev_addr.to_bytes(_PTR_BYTES, 'little'))
        except Exception:
            pass
        return 0  # STATUS_SUCCESS

    setattr(ntos_mod.Ntoskrnl, 'IoGetDeviceObjectPointer',
            apihook('IoGetDeviceObjectPointer', argc=4, conv=conv)(
                _io_get_device_object_pointer))

    # IoAttachDeviceToDeviceStack: bulk stub returns 0 -> filter drivers
    # bail out of their attach path. Return a non-NULL "lower" pointer
    # so the filter chain proceeds; subsequent IofCallDriver(lower, irp)
    # will hit our hooked 0-returning stub.
    def _io_attach_to_stack(self, emu_arg, argv, ctx={}):
        # PDEVICE_OBJECT IoAttachDeviceToDeviceStack(
        #   PDEVICE_OBJECT SourceDevice, PDEVICE_OBJECT TargetDevice)
        if len(argv) < 2:
            return 0
        target = argv[1]
        if not target:
            # Make up a synthetic target so the chain doesn't break.
            target, _ = _alloc_synthetic_devobj('attach_target', emu_arg)
        # Link AttachedDevice on target if writable (best-effort).
        source = argv[0] or 0
        try:
            if source and target:
                _emu_write(emu_arg,
                           target + _DO_OFF['AttachedDevice'],
                           source.to_bytes(_PTR_BYTES, 'little'))
        except Exception:
            pass
        return target

    setattr(ntos_mod.Ntoskrnl, 'IoAttachDeviceToDeviceStack',
            apihook('IoAttachDeviceToDeviceStack', argc=2, conv=conv)(
                _io_attach_to_stack))

    def _io_attach_device(self, emu_arg, argv, ctx={}):
        # IoAttachDevice(SourceDevice, PUNICODE_STRING TargetName,
        #                PDEVICE_OBJECT *AttachedDevice)
        if len(argv) < 3:
            return 0xC0000001
        name = _read_ustr_emu(emu_arg, argv[1])
        target, _ = _alloc_synthetic_devobj(name, emu_arg)
        if not target:
            return 0xC0000001
        try:
            if argv[2]:
                _emu_write(emu_arg, argv[2],
                           target.to_bytes(_PTR_BYTES, 'little'))
        except Exception:
            pass
        return 0

    setattr(ntos_mod.Ntoskrnl, 'IoAttachDevice',
            apihook('IoAttachDevice', argc=3, conv=conv)(_io_attach_device))

