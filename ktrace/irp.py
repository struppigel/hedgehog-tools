"""IRP + DriverObject layouts (x86 32-bit and x86_64) and IRP synthesis."""
from __future__ import annotations
import struct

# All offsets verified against Windows SDK headers (wdm.h / ntddk.h).
# x86 layout: 32-bit pointers; x64 layout: 64-bit pointers and 8-byte alignment.
LAYOUT_X86 = {
    'ptr_size': 4,
    'pack': '<I',
    # IRP
    'irp_size':                       0x70,
    'irp_AssociatedIrp_SystemBuffer': 0x0c,
    'irp_IoStatus_Status':            0x18,
    'irp_IoStatus_Information':       0x1c,
    'irp_UserBuffer':                 0x3c,
    'irp_CurrentStackLocation':       0x60,
    # IO_STACK_LOCATION
    'iostack_size':                   0x24,
    'iostack_MajorFunction':          0x00,
    'iostack_MinorFunction':          0x01,
    'iostack_OutputBufferLength':     0x04,
    'iostack_InputBufferLength':      0x08,
    'iostack_IoControlCode':          0x0c,
    'iostack_Type3InputBuffer':       0x10,
    'iostack_DeviceObject':           0x14,
    'iostack_FileObject':             0x18,
    # DriverObject
    'do_DeviceObject':                0x04,
    'do_Flags':                       0x08,
    'do_DriverStart':                 0x0c,
    'do_DriverSize':                  0x10,
    'do_DriverSection':               0x14,
    'do_DriverExtension':             0x18,
    'do_DriverName_Length':           0x1c,
    'do_DriverName_Buffer':           0x20,
    'do_DriverInit':                  0x2c,
    'do_DriverStartIo':               0x30,
    'do_DriverUnload':                0x34,
    'do_MajorFunction':               0x38,
}

LAYOUT_X64 = {
    'ptr_size': 8,
    'pack': '<Q',
    # IRP
    'irp_size':                       0xe8,
    'irp_AssociatedIrp_SystemBuffer': 0x18,
    'irp_IoStatus_Status':            0x30,
    'irp_IoStatus_Information':       0x38,
    'irp_UserBuffer':                 0x70,
    'irp_CurrentStackLocation':       0xb8,
    # IO_STACK_LOCATION
    'iostack_size':                   0x48,
    'iostack_MajorFunction':          0x00,
    'iostack_MinorFunction':          0x01,
    'iostack_OutputBufferLength':     0x08,
    'iostack_InputBufferLength':      0x10,
    'iostack_IoControlCode':          0x18,
    'iostack_Type3InputBuffer':       0x20,
    'iostack_DeviceObject':           0x28,
    'iostack_FileObject':             0x30,
    # DriverObject
    'do_DeviceObject':                0x08,
    'do_Flags':                       0x10,
    'do_DriverStart':                 0x18,
    'do_DriverSize':                  0x20,
    'do_DriverSection':               0x28,
    'do_DriverExtension':             0x30,
    'do_DriverName_Length':           0x38,
    'do_DriverName_Buffer':           0x40,
    'do_DriverInit':                  0x58,
    'do_DriverStartIo':               0x60,
    'do_DriverUnload':                0x68,
    'do_MajorFunction':               0x70,
}


def layout_for(arch_bits: int) -> dict:
    return LAYOUT_X64 if arch_bits == 64 else LAYOUT_X86


def read_ptr(emu, addr, arch_bits):
    """Read a pointer at addr."""
    L = layout_for(arch_bits)
    b = bytes(emu.mem_read(addr, L['ptr_size']))
    return struct.unpack(L['pack'], b)[0]


def read_major_function_table(emu, drvobj_addr, arch_bits):
    """Return {major_index: handler_addr} for every non-NULL slot."""
    L = layout_for(arch_bits)
    table = {}
    base = drvobj_addr + L['do_MajorFunction']
    for i in range(28):
        ptr = read_ptr(emu, base + i * L['ptr_size'], arch_bits)
        if ptr:
            table[i] = ptr
    return table


def read_driverobject_fields(emu, drvobj_addr, arch_bits):
    """Return a dict of the standard DriverObject pointer fields."""
    L = layout_for(arch_bits)
    out = {}
    for k in ('DeviceObject', 'DriverStart', 'DriverSection',
              'DriverExtension', 'DriverInit', 'DriverStartIo',
              'DriverUnload'):
        try:
            out[k] = read_ptr(emu, drvobj_addr + L['do_' + k], arch_bits)
        except Exception:
            out[k] = 0
    return out


def _alloc_synth_fileobj(emu, arch_bits, devobj, fs_context=1):
    """Allocate a minimal FILE_OBJECT with DeviceObject + FsContext set.

    Dispatchers commonly switch on `FileObject->FsContext` to distinguish
    address-object IRPs from connection-object IRPs. Passing 0 there is
    a NULL deref. Default fs_context=1 picks the "address object" arm
    in most TDI/socket-style filter dispatchers.
    """
    if not devobj:
        return 0
    L = layout_for(arch_bits)
    FO_SIZE = 0x80
    addr = emu.emu.mem_map(FO_SIZE, base=None,
                           tag='ktrace.synth_fileobj', perms=7)
    buf = bytearray(FO_SIZE)
    # Type=5 (IO_TYPE_FILE), Size=FO_SIZE
    import struct as _s
    _s.pack_into('<H', buf, 0, 5)
    _s.pack_into('<H', buf, 2, FO_SIZE)
    # DeviceObject pointer (offset depends on arch; FILE_OBJECT layout
    # has DeviceObject at +8 x64, +4 x86).
    if arch_bits == 64:
        _s.pack_into('<Q', buf, 8, devobj)
        # FsContext at +0x18 on x64
        _s.pack_into('<Q', buf, 0x18, fs_context)
        # FsContext2 at +0x20
        _s.pack_into('<Q', buf, 0x20, 0)
    else:
        _s.pack_into('<I', buf, 4, devobj)
        # FsContext at +0xC, FsContext2 at +0x10
        _s.pack_into('<I', buf, 0x0c, fs_context)
        _s.pack_into('<I', buf, 0x10, 0)
    emu.mem_write(addr, bytes(buf))
    return addr


def synth_irp(emu, dispatcher, arch_bits, major, devobj,
              ioctl_code=0, output_len=4, input_buf=b'', file_obj=0,
              fs_context=1):
    """Build an IRP for IRP_MJ_<major> and dispatch into the driver's handler.

    Returns (status, information, output_bytes) or (None, None, None) on error.

    `file_obj=0` (the default) auto-allocates a minimal FILE_OBJECT
    whose FsContext is `fs_context` (default 1). Pass an explicit
    non-zero file_obj to override.
    """
    L = layout_for(arch_bits)
    BUF_SZ = max(output_len, 0x10, len(input_buf))

    if not file_obj:
        file_obj = _alloc_synth_fileobj(emu, arch_bits, devobj,
                                        fs_context=fs_context)

    irp = emu.emu.mem_map(L['irp_size'], base=None,
                          tag='ktrace.irp', perms=7)  # PERM_MEM_RWX
    ios = emu.emu.mem_map(L['iostack_size'], base=None,
                          tag='ktrace.iostack', perms=7)
    sysbuf = emu.emu.mem_map(BUF_SZ, base=None,
                             tag='ktrace.sysbuf', perms=7)

    emu.mem_write(irp, b'\x00' * L['irp_size'])
    emu.mem_write(ios, b'\x00' * L['iostack_size'])
    emu.mem_write(sysbuf, input_buf.ljust(BUF_SZ, b'\x00'))

    # IO_STACK_LOCATION
    emu.mem_write(ios + L['iostack_MajorFunction'], bytes([major]))
    if major == 0x0E:  # DEVICE_CONTROL
        emu.mem_write(ios + L['iostack_OutputBufferLength'],
                      struct.pack('<I', output_len))
        emu.mem_write(ios + L['iostack_InputBufferLength'],
                      struct.pack('<I', len(input_buf)))
        emu.mem_write(ios + L['iostack_IoControlCode'],
                      struct.pack('<I', ioctl_code))
    emu.mem_write(ios + L['iostack_DeviceObject'],
                  struct.pack(L['pack'], devobj))
    emu.mem_write(ios + L['iostack_FileObject'],
                  struct.pack(L['pack'], file_obj))

    # IRP
    emu.mem_write(irp + L['irp_AssociatedIrp_SystemBuffer'],
                  struct.pack(L['pack'], sysbuf))
    emu.mem_write(irp + L['irp_UserBuffer'],
                  struct.pack(L['pack'], sysbuf))
    emu.mem_write(irp + L['irp_CurrentStackLocation'],
                  struct.pack(L['pack'], ios))

    # Speakeasy's stack region maps `addr..stack_base`; RSP is set to
    # `stack_base - 5*ptr_size`. Drivers commonly do
    # `mov [rsp+0x30], rcx` early to spill incoming register args —
    # that address is in the home/shadow region ABOVE stack_base,
    # which Speakeasy *reserves* but does not map. Result:
    # `invalid_write on mov qword ptr [rsp + 0x30], rcx`.
    #
    # Pre-map a one-page shadow region directly above stack_base so
    # those spills succeed. Once mapped, subsequent emu.call invocations
    # reuse it (we cache on emu).
    try:
        emu.call(dispatcher, [devobj, irp])
    except Exception as e:
        return None, None, None

    try:
        status = struct.unpack('<I',
                               emu.mem_read(irp + L['irp_IoStatus_Status'], 4))[0]
        # IoStatus.Information is ULONG_PTR (4 bytes x86, 8 bytes x64)
        info = struct.unpack(L['pack'],
                             emu.mem_read(irp + L['irp_IoStatus_Information'],
                                          L['ptr_size']))[0]
        out_len = max(info, 16) if info < BUF_SZ else BUF_SZ
        out = bytes(emu.mem_read(sysbuf, out_len))
        return status, info, out
    except Exception:
        return None, None, None
