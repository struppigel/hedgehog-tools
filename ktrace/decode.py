"""Semantic decoding tables + helpers used by ktrace.

No Speakeasy dependency — pure data + formatting functions.
"""
from __future__ import annotations
import bisect

POOL_TYPE = {
    0: 'NonPagedPool', 1: 'PagedPool', 2: 'NonPagedPoolMustSucceed',
    4: 'NonPagedPoolCacheAligned', 5: 'PagedPoolCacheAligned',
    0x20: 'PagedPoolSession', 0x40: 'NonPagedPoolSession',
    0x200: 'NonPagedPoolNx', 0x201: 'PagedPoolNx',
    0x202: 'NonPagedPoolNxCacheAligned',
}

NT_STATUS = {
    0x00000000: 'STATUS_SUCCESS', 0x00000103: 'STATUS_PENDING',
    0x40000000: 'STATUS_OBJECT_NAME_EXISTS',
    0x80000005: 'STATUS_BUFFER_OVERFLOW',
    0x8000000B: 'STATUS_NO_MORE_ENTRIES',
    0xC0000001: 'STATUS_UNSUCCESSFUL', 0xC0000002: 'STATUS_NOT_IMPLEMENTED',
    0xC0000003: 'STATUS_INVALID_INFO_CLASS',
    0xC0000004: 'STATUS_INFO_LENGTH_MISMATCH',
    0xC0000005: 'STATUS_ACCESS_VIOLATION', 0xC0000008: 'STATUS_INVALID_HANDLE',
    0xC000000D: 'STATUS_INVALID_PARAMETER',
    0xC000000E: 'STATUS_NO_SUCH_DEVICE',
    0xC000000F: 'STATUS_NO_SUCH_FILE',
    0xC0000010: 'STATUS_INVALID_DEVICE_REQUEST',
    0xC0000011: 'STATUS_END_OF_FILE',
    0xC0000022: 'STATUS_ACCESS_DENIED',
    0xC0000023: 'STATUS_BUFFER_TOO_SMALL',
    0xC0000024: 'STATUS_OBJECT_TYPE_MISMATCH',
    0xC0000034: 'STATUS_OBJECT_NAME_NOT_FOUND',
    0xC0000035: 'STATUS_OBJECT_NAME_COLLISION',
    0xC000003A: 'STATUS_OBJECT_PATH_NOT_FOUND',
    0xC000003B: 'STATUS_OBJECT_PATH_SYNTAX_BAD',
    0xC0000043: 'STATUS_SHARING_VIOLATION',
    0xC0000061: 'STATUS_PRIVILEGE_NOT_HELD',
    0xC000007B: 'STATUS_INVALID_IMAGE_FORMAT',
    0xC00000BB: 'STATUS_NOT_SUPPORTED',
    0xC0000135: 'STATUS_DLL_NOT_FOUND',
}

SYS_INFO_CLASS = {
    0x00: 'SystemBasicInformation', 0x01: 'SystemProcessorInformation',
    0x02: 'SystemPerformanceInformation', 0x03: 'SystemTimeOfDayInformation',
    0x05: 'SystemProcessInformation', 0x08: 'SystemProcessorPerformanceInformation',
    0x0B: 'SystemModuleInformation', 0x10: 'SystemHandleInformation',
    0x13: 'SystemRegistryQuotaInformation',
    0x16: 'SystemFileCacheInformation',
    0x29: 'SystemFirmwareTableInformation',
    0x4D: 'SystemBigPoolInformation',
    0x59: 'SystemModuleInformationEx',
    0x70: 'SystemCodeIntegrityInformation',
}

IRP_MJ = [
    'IRP_MJ_CREATE', 'IRP_MJ_CREATE_NAMED_PIPE', 'IRP_MJ_CLOSE', 'IRP_MJ_READ',
    'IRP_MJ_WRITE', 'IRP_MJ_QUERY_INFORMATION', 'IRP_MJ_SET_INFORMATION',
    'IRP_MJ_QUERY_EA', 'IRP_MJ_SET_EA', 'IRP_MJ_FLUSH_BUFFERS',
    'IRP_MJ_QUERY_VOLUME_INFORMATION', 'IRP_MJ_SET_VOLUME_INFORMATION',
    'IRP_MJ_DIRECTORY_CONTROL', 'IRP_MJ_FILE_SYSTEM_CONTROL',
    'IRP_MJ_DEVICE_CONTROL', 'IRP_MJ_INTERNAL_DEVICE_CONTROL',
    'IRP_MJ_SHUTDOWN', 'IRP_MJ_LOCK_CONTROL', 'IRP_MJ_CLEANUP',
    'IRP_MJ_CREATE_MAILSLOT', 'IRP_MJ_QUERY_SECURITY', 'IRP_MJ_SET_SECURITY',
    'IRP_MJ_POWER', 'IRP_MJ_SYSTEM_CONTROL', 'IRP_MJ_DEVICE_CHANGE',
    'IRP_MJ_QUERY_QUOTA', 'IRP_MJ_SET_QUOTA', 'IRP_MJ_PNP',
]

FILE_DEVICE = {
    0x01: 'BEEP', 0x02: 'CD_ROM', 0x07: 'DISK', 0x08: 'DVD',
    0x0B: 'KEYBOARD', 0x0F: 'MOUSE', 0x12: 'NAMED_PIPE',
    0x16: 'PARALLEL_PORT', 0x17: 'NETWORK', 0x1B: 'SERIAL_PORT',
    0x22: 'UNKNOWN', 0x29: 'BATTERY', 0x33: 'FILE_SYSTEM',
}

IOCTL_METHOD = ['METHOD_BUFFERED', 'METHOD_IN_DIRECT',
                'METHOD_OUT_DIRECT', 'METHOD_NEITHER']
IOCTL_ACCESS = ['FILE_ANY_ACCESS', 'FILE_READ_ACCESS',
                'FILE_WRITE_ACCESS', 'FILE_READ_WRITE_ACCESS']

# Generic ACCESS_MASK bits common to all object types.
GENERIC_ACCESS = {
    0x80000000: 'GENERIC_READ',  0x40000000: 'GENERIC_WRITE',
    0x20000000: 'GENERIC_EXECUTE', 0x10000000: 'GENERIC_ALL',
    0x01000000: 'ACCESS_SYSTEM_SECURITY',
    0x00100000: 'SYNCHRONIZE',
    0x00080000: 'WRITE_OWNER', 0x00040000: 'WRITE_DAC',
    0x00020000: 'READ_CONTROL', 0x00010000: 'DELETE',
}
FILE_ACCESS = {
    0x0001: 'FILE_READ_DATA',     0x0002: 'FILE_WRITE_DATA',
    0x0004: 'FILE_APPEND_DATA',   0x0008: 'FILE_READ_EA',
    0x0010: 'FILE_WRITE_EA',      0x0020: 'FILE_EXECUTE',
    0x0040: 'FILE_DELETE_CHILD',  0x0080: 'FILE_READ_ATTRIBUTES',
    0x0100: 'FILE_WRITE_ATTRIBUTES',
}
KEY_ACCESS = {
    0x0001: 'KEY_QUERY_VALUE',   0x0002: 'KEY_SET_VALUE',
    0x0004: 'KEY_CREATE_SUB_KEY', 0x0008: 'KEY_ENUMERATE_SUB_KEYS',
    0x0010: 'KEY_NOTIFY',        0x0020: 'KEY_CREATE_LINK',
    0x0100: 'KEY_WOW64_64KEY',   0x0200: 'KEY_WOW64_32KEY',
}
PROCESS_ACCESS = {
    0x0001: 'PROCESS_TERMINATE',     0x0002: 'PROCESS_CREATE_THREAD',
    0x0008: 'PROCESS_VM_OPERATION',  0x0010: 'PROCESS_VM_READ',
    0x0020: 'PROCESS_VM_WRITE',      0x0040: 'PROCESS_DUP_HANDLE',
    0x0080: 'PROCESS_CREATE_PROCESS', 0x0100: 'PROCESS_SET_QUOTA',
    0x0200: 'PROCESS_SET_INFORMATION', 0x0400: 'PROCESS_QUERY_INFORMATION',
    0x0800: 'PROCESS_SUSPEND_RESUME', 0x1000: 'PROCESS_QUERY_LIMITED_INFORMATION',
}
THREAD_ACCESS = {
    0x0001: 'THREAD_TERMINATE',     0x0002: 'THREAD_SUSPEND_RESUME',
    0x0008: 'THREAD_GET_CONTEXT',   0x0010: 'THREAD_SET_CONTEXT',
    0x0020: 'THREAD_SET_INFORMATION', 0x0040: 'THREAD_QUERY_INFORMATION',
    0x0080: 'THREAD_SET_THREAD_TOKEN', 0x0100: 'THREAD_IMPERSONATE',
    0x0200: 'THREAD_DIRECT_IMPERSONATION',
}
# Common pre-combined macros.
ACCESS_MACROS = {
    'file':    {0x1F01FF: 'FILE_ALL_ACCESS',
                0x120089: 'FILE_GENERIC_READ',
                0x120116: 'FILE_GENERIC_WRITE',
                0x1200A0: 'FILE_GENERIC_EXECUTE'},
    'key':     {0x000F003F: 'KEY_ALL_ACCESS',
                0x00020019: 'KEY_READ',
                0x00020006: 'KEY_WRITE',
                0x00020019: 'KEY_EXECUTE'},
    'process': {0x001FFFFF: 'PROCESS_ALL_ACCESS'},
    'thread':  {0x001FFFFF: 'THREAD_ALL_ACCESS'},
}

DEVICE_CHARS = {
    0x00000001: 'FILE_REMOVABLE_MEDIA',
    0x00000002: 'FILE_READ_ONLY_DEVICE',
    0x00000004: 'FILE_FLOPPY_DISKETTE',
    0x00000008: 'FILE_WRITE_ONCE_MEDIA',
    0x00000010: 'FILE_REMOTE_DEVICE',
    0x00000020: 'FILE_DEVICE_IS_MOUNTED',
    0x00000040: 'FILE_VIRTUAL_VOLUME',
    0x00000080: 'FILE_AUTOGENERATED_DEVICE_NAME',
    0x00000100: 'FILE_DEVICE_SECURE_OPEN',
    0x00000800: 'FILE_CHARACTERISTIC_PNP_DEVICE',
    0x00001000: 'FILE_CHARACTERISTIC_TS_DEVICE',
    0x00002000: 'FILE_CHARACTERISTIC_WEBDAV_DEVICE',
}

IRQL_NAMES = {0: 'PASSIVE_LEVEL', 1: 'APC_LEVEL', 2: 'DISPATCH_LEVEL',
              3: 'CMCI_LEVEL', 13: 'CLOCK_LEVEL', 14: 'IPI_LEVEL',
              15: 'POWER_LEVEL', 0x1f: 'HIGH_LEVEL'}

WAIT_REASON = {
    0: 'Executive', 1: 'FreePage', 2: 'PageIn', 3: 'PoolAllocation',
    4: 'DelayExecution', 5: 'Suspended', 6: 'UserRequest',
    8: 'EventPairHigh', 9: 'EventPairLow', 10: 'LpcReceive',
    11: 'LpcReply', 12: 'VirtualMemory', 13: 'PageOut',
}
WAIT_MODE = {0: 'KernelMode', 1: 'UserMode'}

POOL_FLAGS = {
    0x00000001: 'POOL_FLAG_REQUIRED_START', 0x00000040: 'POOL_FLAG_NX_ALLOCATION',
    0x00000010: 'POOL_FLAG_NON_PAGED',  0x00000020: 'POOL_FLAG_NON_PAGED_EXECUTE',
    0x00000100: 'POOL_FLAG_PAGED',
    0x00000004: 'POOL_FLAG_USE_QUOTA',
    0x00000008: 'POOL_FLAG_UNINITIALIZED',
    0x00000002: 'POOL_FLAG_PRIORITY_NORMAL',
    0x00000040: 'POOL_FLAG_CACHE_ALIGNED',
}

# Top bug-check codes — full list is huge; cover the ones drivers use
# intentionally (BSOD on self-protect tamper, anti-debug).
BUGCHECK_CODES = {
    0x0000007E: 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED',
    0x000000C2: 'BAD_POOL_CALLER',
    0x000000C4: 'DRIVER_VERIFIER_DETECTED_VIOLATION',
    0x000000C5: 'DRIVER_CORRUPTED_EXPOOL',
    0x000000D1: 'DRIVER_IRQL_NOT_LESS_OR_EQUAL',
    0x000000F4: 'CRITICAL_OBJECT_TERMINATION',
    0x00000050: 'PAGE_FAULT_IN_NONPAGED_AREA',
    0x0000003B: 'SYSTEM_SERVICE_EXCEPTION',
    0x0000007F: 'UNEXPECTED_KERNEL_MODE_TRAP',
    0x00000124: 'WHEA_UNCORRECTABLE_ERROR',
    0x000000EF: 'CRITICAL_PROCESS_DIED',
    0x000000FE: 'BUGCODE_USB_DRIVER',
    0xDEADDEAD: 'MANUALLY_INITIATED_CRASH',
}

# Run-scoped handle → human-readable name. Cleared per run by
# `reset_handle_state()`. ktrace.py main calls that before each driver.
HANDLE_NAMES: dict[int, str] = {}


def reset_handle_state():
    HANDLE_NAMES.clear()


def remember_handle(h, name):
    n = as_int(h)
    if n is None or not name:
        return
    HANDLE_NAMES[n & 0xFFFFFFFFFFFFFFFF] = str(name)


def lookup_handle(h):
    n = as_int(h)
    return HANDLE_NAMES.get(n) if n is not None else None


# Cached lowercase set of AV/EDR exe names sourced from the
# FAKE_PROCESS_PRESETS['av'] list in shim_state. Lazily populated on
# first lookup to avoid a circular import at module load.
_AV_EDR_NAMES: set[str] | None = None


def _is_av_edr_name(name: str) -> bool:
    """True iff `name` matches an exe in FAKE_PROCESS_PRESETS['av'].

    Used by the ZwTerminateProcess decoder to tag kills against
    AV/EDR processes only, not against arbitrary synthetic placeholders
    ('proc_NN.exe', 'System.exe', '[pid=N unset/idle]', user-supplied
    --fake-processes entries).
    """
    global _AV_EDR_NAMES
    if _AV_EDR_NAMES is None:
        try:
            from shim_state import FAKE_PROCESS_PRESETS
            _AV_EDR_NAMES = {n.lower()
                             for _pid, n in FAKE_PROCESS_PRESETS.get('av', [])}
        except Exception:
            _AV_EDR_NAMES = set()
    return name.lower() in _AV_EDR_NAMES


def _decompose_mask(n, table):
    """Walk known bits, return (matched_names, residual_bits)."""
    names = []
    residual = n
    for bit, name in table.items():
        if n & bit == bit:
            names.append(name)
            residual &= ~bit
    return names, residual


def fmt_access_mask(v, kind='generic'):
    """Render an ACCESS_MASK as `MACRO_NAME` or `BIT1|BIT2|0xresidual`."""
    n = as_int(v)
    if n is None:
        return str(v)
    n &= 0xFFFFFFFF
    if n == 0:
        return '0'
    # Common compiled macros first.
    macros = ACCESS_MACROS.get(kind, {})
    if n in macros:
        return macros[n]
    # Generic-only macros.
    if n in ACCESS_MACROS.get('file', {}) and kind in ('generic', ''):
        return ACCESS_MACROS['file'][n]
    tables = {
        'file':    [FILE_ACCESS,    GENERIC_ACCESS],
        'key':     [KEY_ACCESS,     GENERIC_ACCESS],
        'process': [PROCESS_ACCESS, GENERIC_ACCESS],
        'thread':  [THREAD_ACCESS,  GENERIC_ACCESS],
        'generic': [GENERIC_ACCESS],
    }.get(kind, [GENERIC_ACCESS])
    names = []
    residual = n
    for tbl in tables:
        got, residual = _decompose_mask(residual, tbl)
        names.extend(got)
    if residual:
        names.append(f"0x{residual:x}")
    return '|'.join(names) if names else f"0x{n:x}"


def fmt_device_chars(v):
    n = as_int(v)
    if n is None:
        return str(v)
    n &= 0xFFFFFFFF
    if n == 0:
        return '0'
    names, residual = _decompose_mask(n, DEVICE_CHARS)
    if residual:
        names.append(f"0x{residual:x}")
    return '|'.join(names) if names else f"0x{n:x}"


def fmt_device_type(v):
    n = as_int(v)
    if n is None:
        return str(v)
    return f"FILE_DEVICE_{FILE_DEVICE[n]}" if n in FILE_DEVICE \
        else f"FILE_DEVICE_0x{n & 0xFFFF:x}"


def fmt_irql(v):
    n = as_int(v)
    if n is None:
        return str(v)
    return IRQL_NAMES.get(n, f"IRQL_0x{n:x}")


def fmt_wait_reason(v):
    n = as_int(v)
    if n is None:
        return str(v)
    return WAIT_REASON.get(n, f"WaitReason_0x{n:x}")


def fmt_wait_mode(v):
    n = as_int(v)
    if n is None:
        return str(v)
    return WAIT_MODE.get(n, f"Mode_0x{n:x}")


def fmt_pool_flags(v):
    n = as_int(v)
    if n is None:
        return str(v)
    if n == 0:
        return '0'
    names, residual = _decompose_mask(n, POOL_FLAGS)
    if residual:
        names.append(f"0x{residual:x}")
    return '|'.join(names) if names else f"0x{n:x}"


def fmt_bugcheck(v):
    n = as_int(v)
    if n is None:
        return str(v)
    return BUGCHECK_CODES.get(n & 0xFFFFFFFF, f"0x{n & 0xFFFFFFFF:08x}")


def read_cstr(emu, addr, max_len=512):
    """Read a NUL-terminated ASCII C string from emulated memory."""
    if not addr:
        return ''
    try:
        data = bytes(emu.mem_read(addr, max_len))
    except Exception:
        return ''
    nul = data.find(b'\x00')
    return data[:nul if nul >= 0 else len(data)].decode(
        'latin1', errors='replace')


def fmt_sockaddr(emu, addr):
    """Format a SOCKADDR (v4 or v6) at `addr`. Returns a human string."""
    if not addr:
        return '<null>'
    try:
        family_bytes = bytes(emu.mem_read(addr, 2))
        family = int.from_bytes(family_bytes, 'little')
    except Exception:
        return f'<sockaddr@0x{addr:x}>'
    if family == 2:  # AF_INET
        try:
            buf = bytes(emu.mem_read(addr, 16))
            port = int.from_bytes(buf[2:4], 'big')
            ip = '.'.join(str(b) for b in buf[4:8])
            return f"AF_INET {ip}:{port}"
        except Exception:
            return f'<sockaddr_in@0x{addr:x}>'
    if family == 23:  # AF_INET6
        try:
            buf = bytes(emu.mem_read(addr, 28))
            port = int.from_bytes(buf[2:4], 'big')
            ip6 = ':'.join(f"{int.from_bytes(buf[8 + i:8 + i + 2], 'big'):x}"
                           for i in range(0, 16, 2))
            return f"AF_INET6 [{ip6}]:{port}"
        except Exception:
            return f'<sockaddr_in6@0x{addr:x}>'
    return f"sockaddr(family=0x{family:x})@0x{addr:x}"


def _read_irp_status(emu, irp_addr, arch_bits):
    """Read (IoStatus.Status, IoStatus.Information) from an IRP. Returns
    (None, None) if the IRP pointer isn't readable."""
    try:
        if arch_bits == 64:
            data = bytes(emu.mem_read(irp_addr + 0x30, 16))
            import struct
            status = struct.unpack('<I', data[:4])[0]
            info = struct.unpack('<Q', data[8:16])[0]
        else:
            data = bytes(emu.mem_read(irp_addr + 0x18, 8))
            import struct
            status = struct.unpack('<I', data[:4])[0]
            info = struct.unpack('<I', data[4:8])[0]
        return status, info
    except Exception:
        return None, None


def as_int(v):
    """Best-effort cast to int from str/int (handles '0x...' and decimal)."""
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip()
        try:
            if s.startswith(('0x', '-0x', '0X')):
                return int(s, 16)
            return int(s, 0)
        except (ValueError, TypeError):
            return None
    return None


def H(v):
    n = as_int(v)
    if n is None:
        return str(v)
    # 32-bit signed quickfix: small negative ints (like cmp results)
    # render as -1/-2 not "0x-1". Anything that LOOKS like a kernel
    # pointer (≥ 0x10000) or NTSTATUS-shaped (top bit set) stays hex.
    if -0x10 <= n < 0 or 0 <= n < 0x100:
        return str(n)
    return f"0x{n:x}" if n >= 0 else f"-0x{-n:x}"


def fmt_status(v):
    n = as_int(v)
    if n is None:
        return str(v)
    nm = NT_STATUS.get(n & 0xFFFFFFFF)
    if nm is None:
        return f"0x{n & 0xFFFFFFFF:08X}"
    # Append raw value so caller can see the numeric code alongside
    # the symbolic NTSTATUS name (e.g. STATUS_SUCCESS (0x0)).
    return f"{nm} (0x{n & 0xFFFFFFFF:x})"


def fmt_pool(v):
    n = as_int(v)
    if n is None:
        return str(v)
    return POOL_TYPE.get(n, f"PoolType(0x{n:x})")


# RTL_REGISTRY_* RelativeTo flags for RtlQueryRegistryValues /
# RtlCreateRegistryKey / RtlWriteRegistryValue.
_RTL_REGISTRY_NAMES = {
    0: 'RTL_REGISTRY_ABSOLUTE',
    1: 'RTL_REGISTRY_SERVICES',     # \Registry\Machine\System\CurrentControlSet\Services
    2: 'RTL_REGISTRY_CONTROL',      # \Registry\Machine\System\CurrentControlSet\Control
    3: 'RTL_REGISTRY_WINDOWS_NT',   # \Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion
    4: 'RTL_REGISTRY_DEVICEMAP',    # \Registry\Machine\Hardware\DeviceMap
    5: 'RTL_REGISTRY_USER',         # \Registry\User\CurrentUser
    6: 'RTL_REGISTRY_MAXIMUM',
}


def fmt_rtl_relative_to(v):
    n = as_int(v)
    if n is None:
        return str(v)
    base = n & 0xFF
    extra = []
    if n & 0x40000000:
        extra.append('RTL_REGISTRY_HANDLE')
    if n & 0x80000000:
        extra.append('RTL_REGISTRY_OPTIONAL')
    nm = _RTL_REGISTRY_NAMES.get(base, f'RelativeTo(0x{base:x})')
    if extra:
        return f"{nm}|{'|'.join(extra)}"
    return nm


# REG_* value-type names. Used to decode the `type` arg of
# RtlWriteRegistryValue / ZwSetValueKey / etc. so the `data` arg can be
# rendered semantically (REG_SZ -> string, REG_DWORD -> int, etc.).
_REG_TYPE_NAMES = {
    0: 'REG_NONE',
    1: 'REG_SZ',
    2: 'REG_EXPAND_SZ',
    3: 'REG_BINARY',
    4: 'REG_DWORD',           # REG_DWORD_LITTLE_ENDIAN
    5: 'REG_DWORD_BIG_ENDIAN',
    6: 'REG_LINK',
    7: 'REG_MULTI_SZ',
    8: 'REG_RESOURCE_LIST',
    9: 'REG_FULL_RESOURCE_DESCRIPTOR',
    10: 'REG_RESOURCE_REQUIREMENTS_LIST',
    11: 'REG_QWORD',          # REG_QWORD_LITTLE_ENDIAN
}


def fmt_reg_type(v):
    n = as_int(v)
    if n is None:
        return str(v)
    return _REG_TYPE_NAMES.get(n & 0xFF, f'REG_TYPE(0x{n:x})')


# ---- ZwCreateFile flag decoders ----

_FILE_ATTRIBUTE = {
    0x0001: 'READONLY',     0x0002: 'HIDDEN',       0x0004: 'SYSTEM',
    0x0010: 'DIRECTORY',    0x0020: 'ARCHIVE',      0x0040: 'DEVICE',
    0x0080: 'NORMAL',       0x0100: 'TEMPORARY',    0x0200: 'SPARSE_FILE',
    0x0400: 'REPARSE_POINT',0x0800: 'COMPRESSED',   0x1000: 'OFFLINE',
    0x2000: 'NOT_CONTENT_INDEXED',                  0x4000: 'ENCRYPTED',
    0x8000: 'INTEGRITY_STREAM',                     0x20000: 'NO_SCRUB_DATA',
}

_FILE_SHARE = {
    0x1: 'READ', 0x2: 'WRITE', 0x4: 'DELETE',
}

_FILE_DISPOSITION = {
    0: 'SUPERSEDE',  1: 'OPEN',          2: 'CREATE',
    3: 'OPEN_IF',    4: 'OVERWRITE',     5: 'OVERWRITE_IF',
}

_FILE_OPTIONS = {
    0x00000001: 'DIRECTORY_FILE',           0x00000002: 'WRITE_THROUGH',
    0x00000004: 'SEQUENTIAL_ONLY',          0x00000008: 'NO_INTERMEDIATE_BUFFERING',
    0x00000010: 'SYNCHRONOUS_IO_ALERT',     0x00000020: 'SYNCHRONOUS_IO_NONALERT',
    0x00000040: 'NON_DIRECTORY_FILE',       0x00000080: 'CREATE_TREE_CONNECTION',
    0x00000100: 'COMPLETE_IF_OPLOCKED',     0x00000200: 'NO_EA_KNOWLEDGE',
    0x00000400: 'OPEN_REMOTE_INSTANCE',     0x00000800: 'RANDOM_ACCESS',
    0x00001000: 'DELETE_ON_CLOSE',          0x00002000: 'OPEN_BY_FILE_ID',
    0x00004000: 'OPEN_FOR_BACKUP_INTENT',   0x00008000: 'NO_COMPRESSION',
    0x00010000: 'OPEN_REQUIRING_OPLOCK',    0x00020000: 'DISALLOW_EXCLUSIVE',
    0x00100000: 'RESERVE_OPFILTER',         0x00200000: 'OPEN_REPARSE_POINT',
    0x00400000: 'OPEN_NO_RECALL',           0x00800000: 'OPEN_FOR_FREE_SPACE_QUERY',
}


def _fmt_bitflags(v, table, prefix=''):
    """Render `v` as `FOO|BAR` from a {bit: name} table. Unknown bits
    surface as `0x?` suffix. `prefix` is prepended to each name."""
    n = as_int(v)
    if n is None:
        return str(v)
    n &= 0xFFFFFFFF
    if n == 0:
        return '0'
    parts = []
    remaining = n
    for bit, nm in sorted(table.items()):
        if (n & bit) == bit:
            parts.append(prefix + nm)
            remaining &= ~bit
    if remaining:
        parts.append(f'0x{remaining:x}')
    return '|'.join(parts) if parts else f'0x{n:x}'


def fmt_file_attributes(v):
    n = as_int(v)
    if n is None:
        return str(v)
    if (n & 0xFFFFFFFF) == 0:
        return 'FILE_ATTRIBUTE_NONE'
    return _fmt_bitflags(v, _FILE_ATTRIBUTE, prefix='FILE_ATTRIBUTE_')


def fmt_file_share(v):
    n = as_int(v)
    if n is None:
        return str(v)
    if (n & 0xFFFFFFFF) == 0:
        return 'FILE_SHARE_NONE'
    return _fmt_bitflags(v, _FILE_SHARE, prefix='FILE_SHARE_')


def fmt_file_disposition(v):
    n = as_int(v)
    if n is None:
        return str(v)
    nm = _FILE_DISPOSITION.get(n & 0xFFFFFFFF)
    return f'FILE_{nm}' if nm else f'0x{n & 0xFFFFFFFF:x}'


def fmt_file_options(v):
    n = as_int(v)
    if n is None:
        return str(v)
    if (n & 0xFFFFFFFF) == 0:
        return '0'
    return _fmt_bitflags(v, _FILE_OPTIONS, prefix='FILE_')


# ============================================================================
# Buffer-preview machinery. Drivers pass (data_ptr, length) pairs to
# RtlWriteRegistryValue / ZwSetValueKey / similar; the bytes are the
# *interesting* part of the call but the trace used to show the pointer.
# `set_data_preview(n)` controls how many bytes generic previews show
# (0 = disabled, default 20). Callers that know the data type (REG_SZ
# etc.) decode semantically via fmt_reg_data; everything else falls
# back to preview_buffer which produces a Python-style escaped string.
# ============================================================================
_DATA_PREVIEW_BYTES = 20


def set_data_preview(n):
    """Set the default cap for generic buffer previews. 0 disables them."""
    global _DATA_PREVIEW_BYTES
    try:
        _DATA_PREVIEW_BYTES = max(0, int(n))
    except Exception:
        pass


def _emu_read(emu, addr, n):
    if not emu or not addr or n <= 0:
        return b''
    try:
        return bytes((getattr(emu, 'mem_read', None) or
                      emu.emu.mem_read)(addr, n))
    except Exception:
        return b''


def _escape_preview(data, total_len):
    """Render `data` as a Python-bytes literal-style string. Printable
    ASCII stays as-is; everything else gets `\\xNN`. Appends `…(+N more)`
    if `total_len > len(data)`."""
    out = []
    for b in data:
        if b == 0x5c:                # backslash
            out.append('\\\\')
        elif b == 0x27:              # single quote
            out.append("\\'")
        elif 0x20 <= b < 0x7f:
            out.append(chr(b))
        elif b == 0x0a:
            out.append('\\n')
        elif b == 0x0d:
            out.append('\\r')
        elif b == 0x09:
            out.append('\\t')
        else:
            out.append(f'\\x{b:02x}')
    body = ''.join(out)
    suffix = f' …(+{total_len - len(data)} more)' if total_len > len(data) else ''
    return f"b'{body}'{suffix}"


def preview_buffer(emu, addr_val, len_val, max_bytes=None):
    """Read up to `max_bytes` (default `_DATA_PREVIEW_BYTES`) from the
    emulator at `addr_val` and return an escaped-string preview. Returns
    None when previews are disabled or the buffer cannot be read."""
    cap = _DATA_PREVIEW_BYTES if max_bytes is None else int(max_bytes)
    if cap <= 0:
        return None
    addr = as_int(addr_val)
    n = as_int(len_val)
    if not addr or n is None or n <= 0:
        return None
    # `len` args in kernel APIs occasionally arrive packed-high-uint
    # (Speakeasy's ApiHandler reads a 64-bit reg even for 32-bit fields).
    # Mask to the low 32 bits so we don't try to read 4 GB.
    n &= 0xFFFFFFFF
    if n == 0:
        return None
    take = min(n, cap)
    data = _emu_read(emu, addr, take)
    if not data:
        return None
    return _escape_preview(data, n)


def fmt_reg_data(emu, type_val, data_addr, len_val, max_bytes=None):
    """Decode a (Type, Data, Length) triple by REG_TYPE. Returns a string
    like `REG_SZ('FltMgr')`, `REG_DWORD(0x140055)`, `REG_BINARY(b'...')`.
    Falls back to the raw pointer when the data can't be read.

    Our apihook for RtlWriteRegistryValue / ZwSetValueKey already
    snapshots the data at call time (before the buffer can be freed)
    and stores the rendered string in argv[4]; recognise that here
    and return it verbatim."""
    if isinstance(data_addr, str) and not data_addr.startswith('0x'):
        return data_addr
    t = as_int(type_val)
    addr = as_int(data_addr)
    n = as_int(len_val)
    if t is None or addr is None or n is None:
        return None
    n &= 0xFFFFFFFF
    label = _REG_TYPE_NAMES.get(t & 0xFF, f'REG_TYPE(0x{t:x})')
    if n == 0 or not addr:
        return f"{label}(<empty>)"
    if t in (1, 2, 6):   # REG_SZ / REG_EXPAND_SZ / REG_LINK
        raw = _emu_read(emu, addr, min(n, 0x800))
        # Strip trailing NUL terminator.
        if len(raw) >= 2 and raw.endswith(b'\x00\x00'):
            raw = raw[:-2]
        try:
            s = raw.decode('utf-16-le', errors='replace').rstrip('\x00')
        except Exception:
            s = ''
        return f"{label}({s!r})"
    if t == 7:           # REG_MULTI_SZ
        raw = _emu_read(emu, addr, min(n, 0x1000))
        try:
            text = raw.decode('utf-16-le', errors='replace')
        except Exception:
            text = ''
        parts = [p for p in text.split('\x00') if p]
        return f"{label}({parts!r})"
    if t == 4:           # REG_DWORD
        raw = _emu_read(emu, addr, 4)
        if len(raw) == 4:
            return f"{label}(0x{int.from_bytes(raw, 'little'):x})"
    if t == 5:           # REG_DWORD_BIG_ENDIAN
        raw = _emu_read(emu, addr, 4)
        if len(raw) == 4:
            return f"{label}(0x{int.from_bytes(raw, 'big'):x})"
    if t == 11:          # REG_QWORD
        raw = _emu_read(emu, addr, 8)
        if len(raw) == 8:
            return f"{label}(0x{int.from_bytes(raw, 'little'):x})"
    # Everything else (REG_BINARY, resource lists, ...) -> escaped preview.
    prev = preview_buffer(emu, addr, n, max_bytes=max_bytes)
    if prev is None:
        return f"{label}({n} bytes @ {H(addr)})"
    return f"{label}({prev})"


def fmt_pool_tag(v):
    if isinstance(v, str) and v and not v.startswith('0x'):
        return f"'{v}'"
    n = as_int(v)
    if n is None:
        return str(v)
    b = n.to_bytes(4, 'little')
    if all(0x20 <= c < 0x7f for c in b):
        return f"'{b.decode('latin1')}'"
    return f"0x{n:08x}"


def fmt_ioctl(v):
    n = as_int(v)
    if n is None:
        return str(v)
    dev = (n >> 16) & 0xFFFF
    access = (n >> 14) & 0x3
    func = (n >> 2) & 0xFFF
    meth = n & 0x3
    dev_name = FILE_DEVICE.get(dev, f"0x{dev:x}")
    return (f"IOCTL(dev=FILE_DEVICE_{dev_name}, fn=0x{func:x}, "
            f"{IOCTL_METHOD[meth]}, {IOCTL_ACCESS[access]})")


def fmt_sys_info_class(v):
    n = as_int(v)
    if n is None:
        return str(v)
    return SYS_INFO_CLASS.get(n, f"0x{n:x}")


def _looks_like_real_wstring(s):
    """Heuristic: a decoded UTF-16-LE string is "real" if most of its
    characters are printable ASCII / common path glyphs. Uninitialized
    stack data decoded as UTF-16 typically produces high-codepoint
    Asian/Cyrillic noise; reject so callers can fall back to a hex
    pointer instead of misleading garbage."""
    if not s:
        return False
    sane = sum(1 for c in s
               if (0x20 <= ord(c) < 0x7F) or c in '\\/:*?"<>| \t\r\n')
    return sane * 4 >= len(s) * 3


def normalize_nt_path(s):
    """Collapse buggy doubled prefixes like '\\??\\\\??\\…' produced by
    drivers that concatenate a path which already starts with '\\??\\'
    onto another '\\??\\' literal. Affects both the displayed value AND
    fake-io path matching: a `--fake-io-data` entry written with the
    canonical '\\??\\X' would otherwise silently miss the doubled form
    the driver actually uses.

    Idempotent: a path with no doubling is returned unchanged.
    """
    if not s:
        return s
    # Collapse the specific NT-namespace doublings we've seen in the
    # corpus. Apply repeatedly so triple-prefixes also collapse.
    DOUBLES = (
        ('\\??\\\\??\\', '\\??\\'),
        ('\\??\\\\Device\\', '\\Device\\'),
        ('\\??\\\\DosDevices\\', '\\DosDevices\\'),
        ('\\Device\\\\Device\\', '\\Device\\'),
    )
    prev = None
    while prev != s:
        prev = s
        for bad, good in DOUBLES:
            s = s.replace(bad, good)
    return s


def read_unicode_string(emu, addr, arch_bits=32, max_bytes=512):
    """Read a UNICODE_STRING (Length/MaximumLength/Buffer) at `addr`.

    Returns the decoded Python str or None if the read fails.

    Layout:
      x86: Length(USHORT,2) MaximumLength(USHORT,2) Buffer(PWSTR,4) = 8 bytes
      x64: Length(USHORT,2) MaximumLength(USHORT,2) pad(4) Buffer(PWSTR,8) = 16 bytes
    """
    if not addr:
        return None
    import struct
    try:
        if arch_bits == 64:
            hdr = bytes(emu.mem_read(addr, 16))
            length = struct.unpack('<H', hdr[0:2])[0]
            maxlen = struct.unpack('<H', hdr[2:4])[0]
            buf = struct.unpack('<Q', hdr[8:16])[0]
        else:
            hdr = bytes(emu.mem_read(addr, 8))
            length = struct.unpack('<H', hdr[0:2])[0]
            maxlen = struct.unpack('<H', hdr[2:4])[0]
            buf = struct.unpack('<I', hdr[4:8])[0]
    except Exception:
        return None
    # Sanity-reject garbage UNICODE_STRINGs (stale stack). Real
    # UNICODE_STRINGs have Length <= MaximumLength and Length is even.
    if not buf or length == 0 or length > max_bytes:
        return None
    if length % 2 != 0:
        return None
    if maxlen and length > maxlen:
        return None
    try:
        raw = bytes(emu.mem_read(buf, length))
    except Exception:
        return None
    try:
        s = raw.decode('utf-16-le', errors='replace').rstrip('\x00')
    except Exception:
        return None
    if not _looks_like_real_wstring(s):
        return None
    return normalize_nt_path(s)


def read_ansi_string(emu, addr, arch_bits=32, max_bytes=512):
    """Read an ANSI_STRING / STRING (Length/MaximumLength/Buffer) at `addr`.
    Same layout as UNICODE_STRING but Buffer is PCHAR."""
    if not addr:
        return None
    import struct
    try:
        if arch_bits == 64:
            hdr = bytes(emu.mem_read(addr, 16))
            length = struct.unpack('<H', hdr[0:2])[0]
            buf = struct.unpack('<Q', hdr[8:16])[0]
        else:
            hdr = bytes(emu.mem_read(addr, 8))
            length = struct.unpack('<H', hdr[0:2])[0]
            buf = struct.unpack('<I', hdr[4:8])[0]
    except Exception:
        return None
    if not buf or length == 0 or length > max_bytes:
        return None
    try:
        raw = bytes(emu.mem_read(buf, length))
    except Exception:
        return None
    return raw.decode('latin-1', errors='replace').rstrip('\x00')


def read_object_attributes_name(emu, addr, arch_bits=32):
    """Follow an OBJECT_ATTRIBUTES*.ObjectName chain and return the
    contained UNICODE_STRING value (or None).

    Layout (x86):
      +0x00 ULONG Length
      +0x04 HANDLE RootDirectory  (4 bytes)
      +0x08 PUNICODE_STRING ObjectName
      ...
    Layout (x64):
      +0x00 ULONG Length      (4)
      +0x04 ULONG padding
      +0x08 HANDLE RootDirectory (8)
      +0x10 PUNICODE_STRING ObjectName
      ...
    """
    if not addr:
        return None
    import struct
    try:
        if arch_bits == 64:
            ptr_bytes = bytes(emu.mem_read(addr + 0x10, 8))
            name_ptr = struct.unpack('<Q', ptr_bytes)[0]
        else:
            ptr_bytes = bytes(emu.mem_read(addr + 0x08, 4))
            name_ptr = struct.unpack('<I', ptr_bytes)[0]
    except Exception:
        return None
    return read_unicode_string(emu, name_ptr, arch_bits)


def read_cstring_w(emu, addr, max_chars=256):
    """Read a NUL-terminated wide (UTF-16) C string at `addr`."""
    if not addr:
        return None
    try:
        raw = bytes(emu.mem_read(addr, max_chars * 2))
    except Exception:
        return None
    end = raw.find(b'\x00\x00')
    if end >= 0:
        # Align to even offset so we don't split a wchar.
        end = end if end % 2 == 0 else end + 1
        raw = raw[:end]
    if not raw:
        return None
    try:
        return raw.decode('utf-16-le', errors='replace').rstrip('\x00')
    except Exception:
        return None


def read_cstring_a(emu, addr, max_chars=512):
    """Read a NUL-terminated ANSI C string at `addr`."""
    if not addr:
        return None
    try:
        raw = bytes(emu.mem_read(addr, max_chars))
    except Exception:
        return None
    end = raw.find(b'\x00')
    if end >= 0:
        raw = raw[:end]
    if not raw:
        return None
    return raw.decode('latin-1', errors='replace')


def deref_arg(emu, arch_bits, val, kind):
    """Generic post-emulation arg dereferencer.

    `val` is whatever Speakeasy stored in the API report — already a
    string (Speakeasy auto-decoded it), or a numeric/hex pointer we
    need to follow ourselves.

    `kind` is one of: 'UNICODE_STRING', 'ANSI_STRING',
    'OBJECT_ATTRIBUTES', 'PWSTR', 'PCSTR'.

    Returns either a Python repr-quoted string, or `H(val)` as fallback.
    """
    # If Speakeasy already gave us a non-hex string, trust it — but
    # still collapse doubled NT path prefixes ('\??\\??\X' → '\??\X')
    # produced by buggy drivers that concatenate a path containing an
    # existing '\??\' onto another '\??\' literal.
    if isinstance(val, str) and not val.startswith(('0x', '0X')):
        return repr(normalize_nt_path(val))
    addr = as_int(val)
    if addr is None or addr == 0 or emu is None:
        # Speakeasy decoders for some APIs (RtlInitUnicodeString,
        # RtlInitAnsiString, …) replace the pointer arg with the
        # already-decoded Python string before format_call runs, so
        # `val` may already BE the path text. Normalize in that case
        # too, otherwise the doubled-prefix collapse misses those APIs.
        if isinstance(val, str):
            return repr(normalize_nt_path(val))
        return H(val)
    if kind == 'UNICODE_STRING':
        s = read_unicode_string(emu, addr, arch_bits)
    elif kind == 'ANSI_STRING':
        s = read_ansi_string(emu, addr, arch_bits)
    elif kind == 'OBJECT_ATTRIBUTES':
        s = read_object_attributes_name(emu, addr, arch_bits)
    elif kind == 'PWSTR':
        s = read_cstring_w(emu, addr)
    elif kind == 'PCSTR':
        s = read_cstring_a(emu, addr)
    else:
        s = None
    if s:
        # Same prefix-doubling collapse as read_unicode_string. Applies
        # uniformly to PWSTR / PCSTR / OBJECT_ATTRIBUTES paths the
        # driver feeds to RtlInitUnicodeString and friends.
        s = normalize_nt_path(s)
        return repr(s)
    return H(val)


def resolve_pc(pc, symbols):
    """Find nearest preceding symbol (offset <0x800)."""
    n = as_int(pc)
    if n is None:
        return str(pc)
    if not symbols:
        return f"0x{n:08x}"
    keys = sorted(symbols.keys())
    idx = bisect.bisect_right(keys, n) - 1
    if idx >= 0:
        base = keys[idx]
        off = n - base
        if 0 <= off < 0x800:
            return f"{symbols[base]}+0x{off:x}" if off else symbols[base]
    return f"0x{n:08x}"


# ============================================================================
# Per-API pretty-printer. Receives raw args from Speakeasy's report (a list
# of strings or ints) and returns one human-readable line.
# ============================================================================
def format_call(api_full, raw_args, ret_val, resolve=None,
                emu=None, arch_bits=32):
    """Render an API call line with the `library.Function(...)` prefix
    (matching `speakeasy -t` output, e.g. `ntoskrnl.IoCreateDevice(...)`).
    Internally we still match on the short name; the wrapper prepends
    the library at the end so we don't have to touch 80+ format strings."""
    result = _format_call_inner(api_full, raw_args, ret_val, resolve,
                                emu, arch_bits)
    if api_full and '.' in api_full:
        lib = api_full.rsplit('.', 1)[0]
        short = api_full.rsplit('.', 1)[1]
        prefix = lib + '.'
        if not result.startswith(prefix):
            # Result starts with the short name; splice the library in.
            if result.startswith(short + '(') or result.startswith(short + ' '):
                result = prefix + result
            else:
                # Fallback (formatter returned something unexpected).
                result = prefix + result
    return result


def _format_call_inner(api_full, raw_args, ret_val, resolve=None,
                       emu=None, arch_bits=32):
    """Render an API call line.

    `resolve` is an optional PC->name function.
    `emu` (optional) lets us follow UNICODE_STRING / OBJECT_ATTRIBUTES /
    ANSI_STRING / PWSTR pointers and substitute the actual string. We
    use this only for APIs where Speakeasy didn't already pre-decode
    the arg (Speakeasy handles some of these for us).
    """
    short = api_full.split('.')[-1] if api_full else '?'
    a = list(raw_args) if raw_args else []

    def G(i):
        return H(a[i]) if i < len(a) else '?'

    def U32(i):
        """Same as G(i) but masks to 32 bits — for arguments typed as
        ULONG in the Windows headers. On x64, Speakeasy hands us the
        full 8-byte register value, which for a ULONG arg ends up
        carrying garbage in the high 32 bits (whatever was previously
        in that register). E.g. ZwWriteFile's `Length` arg coming
        through as `0x1dcee7b00000001` when the real length is 1.
        On x86 the high bits are already zero so masking is a no-op."""
        if i >= len(a):
            return '?'
        n = as_int(a[i])
        return H(n & 0xFFFFFFFF) if n is not None else H(a[i])

    def S(i):
        if i >= len(a):
            return '?'
        v = a[i]
        if isinstance(v, str) and not v.startswith('0x'):
            return repr(v)
        return G(i)

    def D(i, kind):
        """Dereference arg `i` as `kind` (UNICODE_STRING, etc.). Falls
        back to S(i)/G(i) if no emu / bad pointer."""
        if i >= len(a):
            return '?'
        return deref_arg(emu, arch_bits, a[i], kind)

    def code(addr):
        return f" [{resolve(addr)}]" if resolve and addr is not None else ""

    # Allocations / frees
    if short == 'ExAllocatePool':
        return f"ExAllocatePool({fmt_pool(a[0]) if a else '?'}, {G(1)}) -> {H(ret_val)}"
    if short == 'ExAllocatePoolWithTag':
        return (f"ExAllocatePoolWithTag({fmt_pool(a[0]) if a else '?'}, "
                f"{G(1)}, tag={fmt_pool_tag(a[2]) if len(a) > 2 else '?'}) -> {H(ret_val)}")
    if short == 'ExAllocatePool2':
        return (f"ExAllocatePool2(flags={fmt_pool_flags(a[0]) if a else '?'}, "
                f"size={G(1)}, "
                f"tag={fmt_pool_tag(a[2]) if len(a) > 2 else '?'}) -> {H(ret_val)}")
    if short == 'ExAllocatePool3':
        return (f"ExAllocatePool3(flags={fmt_pool_flags(a[0]) if a else '?'}, "
                f"size={G(1)}, "
                f"tag={fmt_pool_tag(a[2]) if len(a) > 2 else '?'}, "
                f"...) -> {H(ret_val)}")
    if short == 'ExFreePoolWithTag':
        return f"ExFreePoolWithTag({G(0)}, tag={fmt_pool_tag(a[1]) if len(a) > 1 else '?'})"
    if short == 'ExFreePool':
        return f"ExFreePool({G(0)})"
    # Module enumeration
    if short == 'NtQuerySystemInformation' or short == 'ZwQuerySystemInformation':
        return (f"{short}({fmt_sys_info_class(a[0]) if a else '?'}, "
                f"buf={G(1)}, len={U32(2)}, ret_len_p={G(3)}) -> {fmt_status(ret_val)}")
    # MDLs
    if short == 'IoAllocateMdl':
        return (f"IoAllocateMdl(va={G(0)}, len={U32(1)}, secondary={G(2)}, "
                f"chargeQuota={G(3)}, irp={G(4)}) -> mdl={H(ret_val)}")
    if short == 'MmProbeAndLockPages':
        return f"MmProbeAndLockPages(mdl={G(0)}, mode={G(1)}, op={G(2)})"
    if short == 'MmMapLockedPagesSpecifyCache':
        return (f"MmMapLockedPagesSpecifyCache(mdl={G(0)}, mode={G(1)}, "
                f"cache={G(2)}, req={G(3)}, bugcheck={G(4)}, prio={G(5)}) -> va={H(ret_val)}")
    if short == 'MmUnlockPages':
        return f"MmUnlockPages(mdl={G(0)})"
    if short == 'IoFreeMdl':
        return f"IoFreeMdl(mdl={G(0)})"
    # Device + symlink registration
    if short == 'IoCreateDevice':
        # excl is BOOLEAN (UCHAR) — mask to 1 byte; Speakeasy hands us
        # the full register, so the high bits carry whatever was there
        # before (e.g. 0x96be45e900000000 against an actual TRUE/FALSE
        # value of 0). DeviceExtensionSize is ULONG — mask to 32 bits.
        excl_n = as_int(a[5]) if len(a) > 5 else None
        excl_disp = (str(excl_n & 0xFF) if excl_n is not None
                     else G(5))
        return (f"IoCreateDevice(drv={G(0)}, extSize={U32(1)}, name={D(2, 'UNICODE_STRING')}, "
                f"type={fmt_device_type(a[3]) if len(a)>3 else '?'}, "
                f"chars={fmt_device_chars(a[4]) if len(a)>4 else '?'}, "
                f"excl={excl_disp}, devobj_out={G(6)}) "
                f"-> {fmt_status(ret_val)}")
    if short == 'IoCreateSymbolicLink':
        return (f"IoCreateSymbolicLink(link={D(0, 'UNICODE_STRING')}, "
                f"target={D(1, 'UNICODE_STRING')}) -> {fmt_status(ret_val)}")
    if short == 'IoDeleteDevice':
        return f"IoDeleteDevice(devobj={G(0)})"
    if short == 'IoDeleteSymbolicLink':
        return f"IoDeleteSymbolicLink(link={D(0, 'UNICODE_STRING')})"
    # IRP completion
    if short in ('IofCompleteRequest', 'IoCompleteRequest'):
        irp_addr = as_int(a[0]) if a else None
        if emu is not None and irp_addr:
            st, info = _read_irp_status(emu, irp_addr, arch_bits)
            if st is not None:
                return (f"{short}(irp={G(0)}, boost={G(1)})  "
                        f"[completes: status={fmt_status(st)}, info={info}]")
        return f"{short}(irp={G(0)}, boost={G(1)})"
    # Reinit
    if short == 'IoRegisterDriverReinitialization':
        return (f"IoRegisterDriverReinitialization(drv={G(0)}, reinitFn={G(1)}"
                f"{code(as_int(a[1]) if len(a) > 1 else None)}, ctx={G(2)})")
    if short == 'IoRegisterBootDriverReinitialization':
        return (f"IoRegisterBootDriverReinitialization(drv={G(0)}, "
                f"reinitFn={G(1)}{code(as_int(a[1]) if len(a) > 1 else None)}, ctx={G(2)})")
    # Time
    if short == 'KeQuerySystemTime':
        return f"KeQuerySystemTime(out={G(0)})"
    if short == 'ExSystemTimeToLocalTime':
        return f"ExSystemTimeToLocalTime(sys={G(0)}, local={G(1)})"
    # Memory ops
    if short in ('memcpy', 'memset', 'RtlCopyMemory', 'RtlFillMemory',
                 'RtlMoveMemory', 'RtlZeroMemory'):
        return f"{short}({G(0)}, {G(1)}, {G(2)})"
    # MSVC 64-bit intrinsics
    if short in ('_alldvrm', '_aulldvrm'):
        return f"{short}({G(0)}/{G(1)}, {G(2)}/{G(3)}) -> {H(ret_val)}"
    if short in ('_alldiv', '_aulldiv', '_allmul', '_allrem', '_aullrem'):
        return f"{short}({G(0)}/{G(1)}, {G(2)}/{G(3)}) -> {H(ret_val)}"
    # Affinity / processor
    if short in ('KeQueryActiveProcessors', 'KeQueryActiveProcessorCount',
                 'KeNumberProcessors'):
        return f"{short}() -> {H(ret_val)}"
    if short in ('KeSetSystemAffinityThread', 'KeRevertToUserAffinityThread',
                 'KeStallExecutionProcessor'):
        return f"{short}({', '.join(str(x) for x in a)})"
    # File I/O
    if short in ('ZwOpenFile', 'NtOpenFile'):
        return (f"{short}(handle_out={G(0)}, access={fmt_access_mask(a[1] if len(a)>1 else 0, 'file')}, "
                f"attrs={D(2, 'OBJECT_ATTRIBUTES')}, "
                f"iosb={G(3)}, "
                f"share={fmt_file_share(a[4]) if len(a) > 4 else '?'}, "
                f"opts={fmt_file_options(a[5]) if len(a) > 5 else '?'}) "
                f"-> {fmt_status(ret_val)}")
    if short in ('ZwCreateFile', 'NtCreateFile'):
        return (f"{short}(handle_out={G(0)}, access={fmt_access_mask(a[1] if len(a)>1 else 0, 'file')}, "
                f"attrs={D(2, 'OBJECT_ATTRIBUTES')}, "
                f"iosb={G(3)}, size={G(4)}, "
                f"attrib={fmt_file_attributes(a[5]) if len(a) > 5 else '?'}, "
                f"share={fmt_file_share(a[6]) if len(a) > 6 else '?'}, "
                f"disp={fmt_file_disposition(a[7]) if len(a) > 7 else '?'}, "
                f"opts={fmt_file_options(a[8]) if len(a) > 8 else '?'}, "
                f"eabuf={G(9)}, ealen={G(10)}) "
                f"-> {fmt_status(ret_val)}")
    if short in ('ZwReadFile', 'NtReadFile'):
        h = G(0)
        name = lookup_handle(a[0]) if a else None
        h_disp = f"{h}({name})" if name else h
        return (f"{short}(handle={h_disp}, evt={G(1)}, apc={G(2)}, ctx={G(3)}, "
                f"iosb={G(4)}, buf={G(5)}, len={U32(6)}, off={G(7)}, key={G(8)}) "
                f"-> {fmt_status(ret_val)}")
    if short in ('ZwWriteFile', 'NtWriteFile'):
        h = G(0)
        name = lookup_handle(a[0]) if a else None
        h_disp = f"{h}({name})" if name else h
        # Mask Length (arg6 = ULONG) to 32 bits for the buffer preview too,
        # otherwise preview_buffer will try to read garbage-sized blocks.
        len_raw = a[6] if len(a) > 6 else 0
        len_n = as_int(len_raw)
        len_safe = (len_n & 0xFFFFFFFF) if len_n is not None else len_raw
        prev = preview_buffer(emu, a[5] if len(a) > 5 else 0, len_safe)
        buf_disp = (f"buf={prev}" if prev is not None
                    else f"buf={G(5)}, len={U32(6)}")
        if prev is not None:
            buf_disp = f"{buf_disp}, len={U32(6)}"
        return (f"{short}(handle={h_disp}, ..., {buf_disp}) "
                f"-> {fmt_status(ret_val)}")
    if short in ('ZwClose', 'NtClose'):
        h = G(0)
        name = lookup_handle(a[0]) if a else None
        h_disp = f"{h}({name})" if name else h
        return f"{short}(handle={h_disp}) -> {fmt_status(ret_val)}"
    # Registry
    if short in ('ZwOpenKey', 'NtOpenKey'):
        return (f"{short}(handle_out={G(0)}, access={fmt_access_mask(a[1] if len(a)>1 else 0, 'key')}, "
                f"attrs={D(2, 'OBJECT_ATTRIBUTES')}) -> {fmt_status(ret_val)}")
    if short in ('ZwCreateKey', 'NtCreateKey'):
        return (f"{short}(handle_out={G(0)}, access={fmt_access_mask(a[1] if len(a)>1 else 0, 'key')}, "
                f"attrs={D(2, 'OBJECT_ATTRIBUTES')}, ...) -> {fmt_status(ret_val)}")
    if short in ('ZwOpenSymbolicLinkObject', 'NtOpenSymbolicLinkObject'):
        return (f"{short}(handle_out={G(0)}, access={fmt_access_mask(a[1] if len(a)>1 else 0)}, "
                f"attrs={D(2, 'OBJECT_ATTRIBUTES')}) -> {fmt_status(ret_val)}")
    if short in ('ZwQueryValueKey', 'NtQueryValueKey'):
        h = G(0)
        name_h = lookup_handle(a[0]) if a else None
        h_disp = f"{h}({name_h})" if name_h else h
        return (f"{short}(key={h_disp}, name={D(1, 'UNICODE_STRING')}, "
                f"infoClass={G(2)}, buf={G(3)}, len={U32(4)}, retlen={G(5)}) "
                f"-> {fmt_status(ret_val)}")
    if short in ('ZwSetValueKey', 'NtSetValueKey'):
        h = G(0)
        name_h = lookup_handle(a[0]) if a else None
        h_disp = f"{h}({name_h})" if name_h else h
        data_repr = (fmt_reg_data(emu, a[3] if len(a) > 3 else 0,
                                  a[4] if len(a) > 4 else 0,
                                  a[5] if len(a) > 5 else 0)
                     if len(a) > 5 else None)
        if data_repr is None:
            data_repr = (f"type={fmt_reg_type(a[3]) if len(a) > 3 else '?'}, "
                         f"data={G(4)}, len={U32(5)}")
        else:
            data_repr = f"value={data_repr}"
        return (f"{short}(key={h_disp}, name={D(1, 'UNICODE_STRING')}, "
                f"idx={G(2)}, {data_repr}) "
                f"-> {fmt_status(ret_val)}")
    if short in ('ZwEnumerateKey', 'NtEnumerateKey',
                 'ZwEnumerateValueKey', 'NtEnumerateValueKey'):
        h = G(0)
        name_h = lookup_handle(a[0]) if a else None
        h_disp = f"{h}({name_h})" if name_h else h
        return (f"{short}(key={h_disp}, idx={G(1)}, infoClass={G(2)}, "
                f"buf={G(3)}, len={U32(4)}, retlen={G(5)}) "
                f"-> {fmt_status(ret_val)}")
    # Rtl* registry helpers — RelativeTo + PCWSTR path; the path is the
    # interesting value (service-key field name, SafeBoot subkey, etc.).
    if short == 'RtlQueryRegistryValues':
        path = D(1, 'PWSTR')
        return (f"RtlQueryRegistryValues(rel={fmt_rtl_relative_to(a[0]) if a else '?'}, "
                f"path={path}, qtbl={G(2)}, ctx={G(3)}, env={G(4)}) "
                f"-> {fmt_status(ret_val)}")
    if short == 'RtlCreateRegistryKey':
        path = D(1, 'PWSTR')
        return (f"RtlCreateRegistryKey(rel={fmt_rtl_relative_to(a[0]) if a else '?'}, "
                f"path={path}) -> {fmt_status(ret_val)}")
    if short == 'RtlWriteRegistryValue':
        # RelativeTo, KeyName (PCWSTR), ValueName (PCWSTR), ValueType,
        # ValueData, ValueLength
        data_repr = (fmt_reg_data(emu, a[3] if len(a) > 3 else 0,
                                  a[4] if len(a) > 4 else 0,
                                  a[5] if len(a) > 5 else 0)
                     if len(a) > 5 else None)
        if data_repr is None:
            data_repr = (f"type={fmt_reg_type(a[3]) if len(a) > 3 else '?'}, "
                         f"data={G(4)}, len={U32(5)}")
        else:
            data_repr = f"value={data_repr}"
        return (f"RtlWriteRegistryValue(rel={fmt_rtl_relative_to(a[0]) if a else '?'}, "
                f"key={D(1, 'PWSTR')}, name={D(2, 'PWSTR')}, "
                f"{data_repr}) -> {fmt_status(ret_val)}")
    if short == 'RtlDeleteRegistryValue':
        return (f"RtlDeleteRegistryValue(rel={fmt_rtl_relative_to(a[0]) if a else '?'}, "
                f"key={D(1, 'PWSTR')}, name={D(2, 'PWSTR')}) "
                f"-> {fmt_status(ret_val)}")
    if short == 'RtlCheckRegistryKey':
        return (f"RtlCheckRegistryKey(rel={fmt_rtl_relative_to(a[0]) if a else '?'}, "
                f"path={D(1, 'PWSTR')}) -> {fmt_status(ret_val)}")
    # Process / thread
    if short == 'PsLookupProcessByProcessId':
        return f"PsLookupProcessByProcessId(pid={G(0)}, eproc_out={G(1)}) -> {fmt_status(ret_val)}"
    if short == 'ZwOpenProcess' or short == 'NtOpenProcess':
        # Our ZwOpenProcess shim resolves CLIENT_ID → "pid=N name=...",
        # stuffs that into argv[3]. If it's still a bare int, the
        # caller didn't reach the shim or the CLIENT_ID read failed —
        # show the pointer.
        cid_arg = a[3] if len(a) > 3 else 0
        if isinstance(cid_arg, str) and not cid_arg.startswith('0x'):
            cid_disp = cid_arg
        else:
            cid_disp = f"cid={G(3)}"
        return (f"{short}(handle_out={G(0)}, "
                f"access={fmt_access_mask(a[1] if len(a)>1 else 0, 'process')}, "
                f"attrs={G(2)}, {cid_disp}) -> {fmt_status(ret_val)}")
    if short == 'ZwOpenThread' or short == 'NtOpenThread':
        return (f"{short}(handle_out={G(0)}, "
                f"access={fmt_access_mask(a[1] if len(a)>1 else 0, 'thread')}, "
                f"attrs={G(2)}, cid={G(3)}) -> {fmt_status(ret_val)}")
    if short in ('ZwTerminateProcess', 'NtTerminateProcess'):
        h = G(0)
        name = lookup_handle(a[0]) if a else None
        h_disp = f"{h}({name})" if name else h
        # Only tag as AV/EDR-kill if the handle's associated name matches
        # one of the AV/EDR process names from FAKE_PROCESS_PRESETS['av'].
        # Synthetic placeholders ('proc_NN.exe', 'System.exe', '[pid=N…]')
        # and arbitrary user-supplied entries are NOT verdicts the trace
        # can justify on its own — they shouldn't carry an AV/EDR label.
        annotate = ''
        if name and _is_av_edr_name(name):
            annotate = '  [!! AV/EDR kill target !!]'
        return (f"{short}(handle={h_disp}, status={G(1)}) "
                f"-> {fmt_status(ret_val)}{annotate}")
    # BOOLEAN-returning APIs (NOT NTSTATUS — render TRUE/FALSE so we
    # don't mislabel 0 as STATUS_SUCCESS).
    if short in ('IoIs32bitProcess',
                 'PsIsThreadTerminating', 'PsIsSystemThread',
                 'MmIsAddressValid',
                 'KeAreApcsDisabled', 'KeAreAllApcsDisabled',
                 'KdRefreshDebuggerNotPresent',
                 'ExAcquireRundownProtection',
                 'ExAcquireResourceExclusiveLite',
                 'ExAcquireResourceSharedLite',
                 'ExTryToAcquireFastMutex',
                 'KeTestSpinLock', 'KeTryToAcquireSpinLockAtDpcLevel'):
        rn = as_int(ret_val)
        bret = 'TRUE' if rn else 'FALSE'
        args_str = ', '.join(G(i) for i in range(len(a)))
        return f"{short}({args_str}) -> {bret}"
    if short == 'PsCreateSystemThread':
        return (f"PsCreateSystemThread(handle_out={G(0)}, access={G(1)}, "
                f"attrs={G(2)}, proc={G(3)}, cid={G(4)}, start={G(5)}{code(as_int(a[5]) if len(a) > 5 else None)}, "
                f"ctx={G(6)}) -> {fmt_status(ret_val)}")
    if short == 'PsSetCreateProcessNotifyRoutine':
        return (f"PsSetCreateProcessNotifyRoutine(routine={G(0)}{code(as_int(a[0]) if a else None)}, "
                f"remove={G(1)}) -> {fmt_status(ret_val)}")
    if short in ('PsSetLoadImageNotifyRoutine',
                 'PsSetCreateThreadNotifyRoutine'):
        return f"{short}(routine={G(0)}{code(as_int(a[0]) if a else None)}) -> {fmt_status(ret_val)}"
    # Unicode strings
    if short == 'RtlInitUnicodeString':
        # 1st arg is OUT (PUNICODE_STRING to initialise); 2nd arg is PCWSTR
        # raw wide string. Display the source string.
        return f"RtlInitUnicodeString(out={G(0)}, src={D(1, 'PWSTR')})"
    if short == 'RtlInitAnsiString':
        return f"RtlInitAnsiString(out={G(0)}, src={D(1, 'PCSTR')})"
    if short == 'RtlInitEmptyUnicodeString':
        return f"RtlInitEmptyUnicodeString(out={G(0)}, buf={G(1)}, buflen={G(2)})"
    if short == 'RtlCopyUnicodeString':
        return f"RtlCopyUnicodeString(dst={G(0)}, src={D(1, 'UNICODE_STRING')})"
    if short == 'RtlCompareUnicodeString':
        return (f"RtlCompareUnicodeString(s1={D(0, 'UNICODE_STRING')}, "
                f"s2={D(1, 'UNICODE_STRING')}, ci={G(2)}) -> {H(ret_val)}")
    if short == 'RtlEqualUnicodeString':
        return (f"RtlEqualUnicodeString(s1={D(0, 'UNICODE_STRING')}, "
                f"s2={D(1, 'UNICODE_STRING')}, ci={G(2)}) -> {H(ret_val)}")
    if short == 'RtlPrefixUnicodeString':
        return (f"RtlPrefixUnicodeString(s1={D(0, 'UNICODE_STRING')}, "
                f"s2={D(1, 'UNICODE_STRING')}, ci={G(2)}) -> {H(ret_val)}")
    if short == 'RtlAppendUnicodeStringToString':
        return (f"RtlAppendUnicodeStringToString(dst={G(0)}, "
                f"src={D(1, 'UNICODE_STRING')}) -> {fmt_status(ret_val)}")
    if short == 'RtlAppendUnicodeToString':
        return (f"RtlAppendUnicodeToString(dst={G(0)}, src={D(1, 'PWSTR')}) "
                f"-> {fmt_status(ret_val)}")
    if short == 'RtlAnsiStringToUnicodeString':
        return (f"RtlAnsiStringToUnicodeString(dst={G(0)}, "
                f"src={D(1, 'ANSI_STRING')}, alloc={G(2)}) "
                f"-> {fmt_status(ret_val)}")
    if short == 'RtlUnicodeStringToAnsiString':
        return (f"RtlUnicodeStringToAnsiString(dst={G(0)}, "
                f"src={D(1, 'UNICODE_STRING')}, alloc={G(2)}) "
                f"-> {fmt_status(ret_val)}")
    if short == 'RtlFreeUnicodeString':
        return f"RtlFreeUnicodeString(s={D(0, 'UNICODE_STRING')})"
    if short == 'RtlCreateUnicodeString':
        # BOOLEAN RtlCreateUnicodeString(PUNICODE_STRING dst, PCWSTR src);
        # Source is a NUL-terminated wide string; the new buffer is
        # allocated and copied into dst by the impl. Show the source so
        # the trace records *what was stored*, not just pointer values.
        return (f"RtlCreateUnicodeString(dst={G(0)}, src={D(1, 'PWSTR')}) "
                f"-> {H(ret_val)}")
    if short == 'RtlCreateUnicodeStringFromAsciiz':
        return (f"RtlCreateUnicodeStringFromAsciiz(dst={G(0)}, "
                f"src={D(1, 'PCSTR')}) -> {H(ret_val)}")
    if short == 'RtlDuplicateUnicodeString':
        return (f"RtlDuplicateUnicodeString(flags={G(0)}, "
                f"src={D(1, 'UNICODE_STRING')}, dst={G(2)}) "
                f"-> {fmt_status(ret_val)}")
    if short == 'MmGetSystemRoutineAddress':
        return f"MmGetSystemRoutineAddress(name={D(0, 'UNICODE_STRING')}) -> {H(ret_val)}"
    # Object manager
    if short == 'ObReferenceObjectByName':
        return (f"ObReferenceObjectByName(name={D(0, 'UNICODE_STRING')}, "
                f"attrs={G(1)}, access={G(2)}, type={G(3)}, "
                f"..., obj_out={G(6)}) -> {fmt_status(ret_val)}")
    if short == 'ObReferenceObjectByHandle':
        return (f"ObReferenceObjectByHandle(handle={G(0)}, access={G(1)}, "
                f"type={G(2)}, mode={G(3)}, obj_out={G(4)}, info={G(5)}) "
                f"-> {fmt_status(ret_val)}")
    if short in ('ObfDereferenceObject', 'ObDereferenceObject',
                 'ObfReferenceObject', 'ObReferenceObject'):
        return f"{short}(obj={G(0)})"
    if short == 'MmGetSystemRoutineAddress':
        return f"MmGetSystemRoutineAddress(name={G(0)}) -> {H(ret_val)}"
    # Synchronisation
    if short == 'KeInitializeEvent':
        return f"KeInitializeEvent(event={G(0)}, type={G(1)}, signaled={G(2)})"
    if short == 'KeSetEvent':
        return f"KeSetEvent(event={G(0)}, incr={G(1)}, wait={G(2)}) -> {H(ret_val)}"
    if short == 'KeWaitForSingleObject':
        return (f"KeWaitForSingleObject(obj={G(0)}, "
                f"reason={fmt_wait_reason(a[1]) if len(a)>1 else '?'}, "
                f"mode={fmt_wait_mode(a[2]) if len(a)>2 else '?'}, "
                f"alertable={G(3)}, timeout={G(4)}) -> {fmt_status(ret_val)}")
    if short == 'KeWaitForMultipleObjects':
        return (f"KeWaitForMultipleObjects(n={G(0)}, objs={G(1)}, type={G(2)}, "
                f"reason={fmt_wait_reason(a[3]) if len(a)>3 else '?'}, "
                f"mode={fmt_wait_mode(a[4]) if len(a)>4 else '?'}, "
                f"alertable={G(5)}, timeout={G(6)}, blk={G(7)}) -> {fmt_status(ret_val)}")
    if short == 'KeDelayExecutionThread':
        return f"KeDelayExecutionThread(mode={G(0)}, alertable={G(1)}, interval={G(2)}) -> {fmt_status(ret_val)}"
    if short == 'ExInitializePushLock':
        return f"ExInitializePushLock(lock={G(0)})"
    # KMDF
    if short == 'WdfVersionBind':
        return f"WdfVersionBind(drv={G(0)}, regpath={G(1)}, ver_info={G(2)}, fn_table={G(3)}) -> {fmt_status(ret_val)}"
    # C runtime — show the actual strings being compared / searched.
    # Big readability win: malware-style "compare against own service
    # path" anti-emulation checks become obvious in the trace.
    # C ctype: single char int → 0/1. Show the printable representation
    # of the input plus the boolean result; avoid the generic-fallback
    # treating 0 as STATUS_SUCCESS.
    if short in ('isdigit', 'isspace', 'isxdigit', 'isalpha',
                 'isalnum', 'islower', 'isupper', 'isprint',
                 'iscntrl', 'tolower', 'toupper'):
        n = as_int(a[0]) if a else 0
        n = (n or 0) & 0xFF
        if 0x20 <= n < 0x7f:
            disp = repr(chr(n))
        else:
            disp = f"0x{n:02x}"
        rv = as_int(ret_val)
        if short in ('tolower', 'toupper'):
            rn = (rv or 0) & 0xFF
            if 0x20 <= rn < 0x7f:
                ret_disp = repr(chr(rn))
            else:
                ret_disp = f"0x{rn:02x}"
        else:
            ret_disp = str(rv) if rv is not None else '?'
        return f"{short}({disp}) -> {ret_disp}"

    if short in ('wcslen', 'wcsdup'):
        # PCWSTR -> length / dup. Show the source string.
        def _wread(addr):
            if not emu or not addr:
                return ''
            try:
                raw = bytes(emu.mem_read(addr, 1024))
            except Exception:
                return ''
            for i in range(0, len(raw) - 1, 2):
                if raw[i] == 0 and raw[i + 1] == 0:
                    return raw[:i].decode('utf-16-le', errors='replace')
            return raw.decode('utf-16-le', errors='replace')
        v = a[0] if a else 0
        if isinstance(v, str) and not v.startswith('0x'):
            s = v
        else:
            s = _wread(as_int(v) or 0)
        return f"{short}({s!r}) -> {H(ret_val)}"
    if short in ('wcschr', 'wcsrchr'):
        # PCWSTR, wint_t. Show source string + the wchar searched for.
        def _wread(addr):
            if not emu or not addr:
                return ''
            try:
                raw = bytes(emu.mem_read(addr, 1024))
            except Exception:
                return ''
            for i in range(0, len(raw) - 1, 2):
                if raw[i] == 0 and raw[i + 1] == 0:
                    return raw[:i].decode('utf-16-le', errors='replace')
            return raw.decode('utf-16-le', errors='replace')
        s0 = a[0] if a else 0
        if isinstance(s0, str) and not s0.startswith('0x'):
            s = s0
        else:
            s = _wread(as_int(s0) or 0)
        # Char arg: Speakeasy may have already passed us a 1-char string
        # (e.g. ','); otherwise it's an int wchar.
        c0 = a[1] if len(a) > 1 else 0
        if isinstance(c0, str) and not c0.startswith('0x'):
            ch_disp = repr(c0)
        else:
            ch = as_int(c0) or 0
            ch_disp = repr(chr(ch & 0xFFFF)) if 0x20 <= (ch & 0xFFFF) < 0x10000 \
                      else f"0x{ch:x}"
        return f"{short}({s!r}, {ch_disp}) -> {H(ret_val)}"
    if short in ('strchr', 'strrchr'):
        s = read_cstr(emu, as_int(a[0]) if a else 0, max_len=512)
        c0 = a[1] if len(a) > 1 else 0
        if isinstance(c0, str) and not c0.startswith('0x'):
            ch_disp = repr(c0)
        else:
            ch = as_int(c0) or 0
            ch_disp = repr(chr(ch & 0xFF)) if 0x20 <= (ch & 0xFF) < 0x7f \
                      else f"0x{ch:x}"
        return f"{short}({s!r}, {ch_disp}) -> {H(ret_val)}"
    if short in ('atoi', 'atol', '_atoi64', 'strtol', 'strtoul'):
        s = read_cstr(emu, as_int(a[0]) if a else 0, max_len=64)
        return f"{short}({s!r}) -> {H(ret_val)}"
    if short in ('strcpy', 'strcat', 'wcscpy', 'wcscat'):
        # dst, src — show src content. Use cstr/wcs read appropriately.
        if short.startswith('w'):
            def _wread(addr):
                if not emu or not addr:
                    return ''
                try:
                    raw = bytes(emu.mem_read(addr, 1024))
                except Exception:
                    return ''
                for i in range(0, len(raw) - 1, 2):
                    if raw[i] == 0 and raw[i + 1] == 0:
                        return raw[:i].decode('utf-16-le', errors='replace')
                return raw.decode('utf-16-le', errors='replace')
            s = _wread(as_int(a[1]) if len(a) > 1 else 0)
        else:
            s = read_cstr(emu, as_int(a[1]) if len(a) > 1 else 0, max_len=512)
        return f"{short}(dst={G(0)}, src={s!r}) -> {H(ret_val)}"
    if short in ('strstr', 'strncmp', 'strcmp', 'strlen',
                 'wcscmp', 'memcpy_s', '_strnicmp', '_stricmp',
                 '_wcsicmp', 'wcsstr'):
        if emu is None:
            args_str = ', '.join(str(x) for x in a)
            return f"{short}({args_str}) -> {H(ret_val)}"
        if short == 'strlen':
            s = read_cstr(emu, as_int(a[0]) if a else 0)
            return f"strlen({s!r}) -> {H(ret_val)}"
        if short in ('strncmp', '_strnicmp'):
            s1 = read_cstr(emu, as_int(a[0]) if a else 0,
                           max_len=as_int(a[2]) if len(a) > 2 else 64)
            s2 = read_cstr(emu, as_int(a[1]) if len(a) > 1 else 0,
                           max_len=as_int(a[2]) if len(a) > 2 else 64)
            return f"{short}({s1!r}, {s2!r}, n={G(2)}) -> {H(ret_val)}"
        if short == 'memcpy_s':
            return (f"memcpy_s(dst={G(0)}, dst_sz={G(1)}, "
                    f"src={G(2)}, n={G(3)}) -> {H(ret_val)}")
        if short in ('wcscmp', '_wcsicmp', 'wcsstr'):
            # Wide-string comparisons: read both as UTF-16
            def _wide(addr):
                if not addr:
                    return ''
                try:
                    raw = bytes(emu.mem_read(addr, 1024))
                except Exception:
                    return ''
                for i in range(0, len(raw) - 1, 2):
                    if raw[i] == 0 and raw[i + 1] == 0:
                        return raw[:i].decode('utf-16-le', errors='replace')
                return raw.decode('utf-16-le', errors='replace')
            w1 = _wide(as_int(a[0]) if a else 0)
            w2 = _wide(as_int(a[1]) if len(a) > 1 else 0)
            return f"{short}({w1!r}, {w2!r}) -> {H(ret_val)}"
        # strstr, strcmp, _stricmp
        s1 = read_cstr(emu, as_int(a[0]) if a else 0, max_len=512)
        s2 = read_cstr(emu, as_int(a[1]) if len(a) > 1 else 0, max_len=128)
        annotate = ''
        if short == 'strstr':
            # Heuristic: if the haystack is the driver's own service
            # registry path, this is almost certainly an anti-emulation
            # guard (driver checks for a machine-binding marker in its
            # own install path).
            if r'\Registry\Machine\System\CurrentControlSet\Services\\' in s1:
                annotate = '  [anti-emu: searching own service path]'
            elif r'\\Services\\' in s1.replace(chr(92), chr(92)+chr(92)):
                annotate = '  [anti-emu suspect]'
            elif 'Services\\' in s1:
                annotate = '  [anti-emu suspect]'
        return f"{short}({s1!r}, {s2!r}) -> {H(ret_val)}{annotate}"
    # WSK kernel sockets — surface destination IP+port in the trace.
    if short in ('WskSocket_NPI',):
        return (f"WskSocket(client={G(0)}, "
                f"family={G(1)}, type={G(2)}, proto={G(3)}, flags={G(4)}) "
                f"-> {fmt_status(ret_val)}")
    if short in ('WskSocketConnect_NPI',):
        # PFN_WSK_SOCKET_CONNECT(Client, SocketType, Protocol,
        #   LocalAddress, RemoteAddress, Flags, SecurityDescriptor,
        #   SocketContext, Dispatch, OwningProcess, OwningThread, Irp)
        remote = fmt_sockaddr(emu, as_int(a[4])) if emu and len(a) > 4 else '?'
        local = fmt_sockaddr(emu, as_int(a[3])) if emu and len(a) > 3 else '?'
        return (f"WskSocketConnect(type={G(1)}, proto={G(2)}, "
                f"local={local}, remote={remote}, flags={G(5)}) "
                f"-> {fmt_status(ret_val)}")
    if short in ('WskGetAddressInfo_NPI',):
        # WskGetAddressInfo(Client, NodeName, ServiceName, NameSpace,
        #   Provider, Hints, Result, OwningProcess, OwningThread, Irp)
        node = read_unicode_string(emu, as_int(a[1]), arch_bits) \
            if emu and len(a) > 1 else '?'
        svc = read_unicode_string(emu, as_int(a[2]), arch_bits) \
            if emu and len(a) > 2 else '?'
        return (f"WskGetAddressInfo(node='{node}', service='{svc}') "
                f"-> {fmt_status(ret_val)}")
    if short in ('WskControlClient_NPI',):
        return (f"WskControlClient(ControlCode={G(1)}, in_len={G(2)}, "
                f"out_len={G(3)}) -> {fmt_status(ret_val)}")
    # IRQL — return is the *previous* IRQL for AcquireSpinLock variants
    if short in ('KeAcquireSpinLockRaiseToDpc', 'KeAcquireSpinLock',
                 'KfAcquireSpinLock'):
        return (f"{short}({G(0)}) -> oldIrql={fmt_irql(ret_val)}")
    if short in ('KeReleaseSpinLock', 'KfReleaseSpinLock'):
        return f"{short}({G(0)}, newIrql={fmt_irql(a[1]) if len(a)>1 else '?'})"
    if short in ('KeRaiseIrql', 'KfRaiseIrql'):
        return (f"{short}(newIrql={fmt_irql(a[0]) if a else '?'}, "
                f"oldOut={G(1)}) -> oldIrql={fmt_irql(ret_val)}")
    if short in ('KeLowerIrql', 'KfLowerIrql'):
        return f"{short}(newIrql={fmt_irql(a[0]) if a else '?'})"
    if short == 'KeGetCurrentIrql':
        return f"KeGetCurrentIrql() -> {fmt_irql(ret_val)}"
    # Bug checks
    if short in ('KeBugCheckEx', 'KeBugCheck'):
        return (f"{short}(code={fmt_bugcheck(a[0]) if a else '?'}, "
                f"p1={G(1)}, p2={G(2)}, p3={G(3)}, p4={G(4)})")
    # Generic fallback. NTSTATUS-looking returns get rendered
    # symbolically; truly-void (None / empty) returns omit `->`.
    # When a `resolve` callback is set (profile or --symbols supplied
    # PC→name map), int args within the driver image range (≥0x10000)
    # get annotated with their nearest symbol: `0x140006298[g_RuleListLock]`.
    # Saves a Ghidra round-trip when reading the trace.
    def _fmt_arg(x):
        # Speakeasy may give us args as ints OR as already-formatted
        # hex strings like '0x140006298'. Try int-conversion first so
        # symbol resolution applies uniformly.
        n = as_int(x)
        if isinstance(x, str):
            if x.startswith('0x') or x.lstrip('-').isdigit():
                if resolve and n is not None and n >= 0x10000:
                    try:
                        s = resolve(n)
                    except Exception:
                        s = None
                    if s and not s.startswith('0x'):
                        return f"{x}[{s}]"
                return x
            return repr(x)
        if n is None:
            return str(x)
        if resolve and n >= 0x10000:
            try:
                s = resolve(n)
            except Exception:
                s = None
            if s and not s.startswith('0x'):
                return f"0x{n:x}[{s}]"
        return f"0x{n:x}"

    args_str = ', '.join(_fmt_arg(x) for x in a)
    if ret_val is None:
        return f"{short}({args_str})"
    rn = as_int(ret_val)
    # Looks like NTSTATUS? High nibble is 8 (warning), 4 (info), C (error)
    if rn is not None and ((rn >> 28) in (0x8, 0x4, 0xC)
                           or rn in NT_STATUS):
        return f"{short}({args_str}) -> {fmt_status(ret_val)}"
    return f"{short}({args_str}) -> {H(ret_val)}"
