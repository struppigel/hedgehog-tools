"""External-module API stubs that Speakeasy doesn't ship: TDI, FltMgr,
NetIo (WSK), CNG, KsecDD, Fwpkclnt. Each is an ApiHandler subclass that
returns STATUS_SUCCESS for the imports we know about; registration happens
at import time so shim.py just needs to import this module."""
from speakeasy.winenv.api import api as api_module
from speakeasy.winenv.api import winapi as _winapi
from speakeasy.winenv import arch as _arch
apihook = api_module.ApiHandler.apihook

# ----------------------------------------------------------------------
# TDI.SYS stub module. Speakeasy doesn't ship TDI handlers, so any TDI
# import (TdiMapUserRequest is the canonical one) lands on an apihook
# trigger with no registered handler and halts emulation with
# `unsupported_api on disasm_failed api=TDI.<name>`.
#
# We register a minimal ApiHandler subclass that returns STATUS_SUCCESS
# for the imports we know about, and inject it into winapi.API_HANDLERS
# so Speakeasy's resolver finds it.
# ----------------------------------------------------------------------
class _TdiStub(api_module.ApiHandler):
    name = 'tdi'
    apihook = api_module.ApiHandler.apihook
    impdata = api_module.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        # Parent __init__ already walked `dir(self)` and populated
        # self.funcs from our @apihook-decorated methods. Don't clobber.
        self.emu = emu

    @apihook('TdiMapUserRequest', argc=3)
    def TdiMapUserRequest(self, emu, argv, ctx={}):
        # NTSTATUS TdiMapUserRequest(PDEVICE_OBJECT, PIRP, PIO_STACK_LOCATION)
        # Returning STATUS_SUCCESS makes the filter dispatcher fall
        # through to its internal-TDI dispatch path (the per-minor
        # ASSOCIATE/CONNECT/LISTEN/RECEIVE/SEND handlers).
        return 0

    @apihook('TdiCopyMdlToBuffer', argc=4)
    def TdiCopyMdlToBuffer(self, emu, argv, ctx={}): return 0

    @apihook('TdiCopyBufferToMdl', argc=6)
    def TdiCopyBufferToMdl(self, emu, argv, ctx={}): return 0

    @apihook('TdiCopyLookaheadData', argc=4)
    def TdiCopyLookaheadData(self, emu, argv, ctx={}): return 0

    @apihook('TdiBuildNetbiosAddress', argc=3)
    def TdiBuildNetbiosAddress(self, emu, argv, ctx={}): return 0

    @apihook('TdiBuildNetbiosAddressEa', argc=3)
    def TdiBuildNetbiosAddressEa(self, emu, argv, ctx={}): return 0

    @apihook('TdiOpenNetbiosAddress', argc=4)
    def TdiOpenNetbiosAddress(self, emu, argv, ctx={}): return 0

    @apihook('TdiDefaultRcvHandler', argc=9)
    def TdiDefaultRcvHandler(self, emu, argv, ctx={}): return 0

    @apihook('TdiDefaultDisconnectHandler', argc=6)
    def TdiDefaultDisconnectHandler(self, emu, argv, ctx={}): return 0

    @apihook('TdiDefaultErrorHandler', argc=2)
    def TdiDefaultErrorHandler(self, emu, argv, ctx={}): return 0

    @apihook('TdiDefaultConnectHandler', argc=10)
    def TdiDefaultConnectHandler(self, emu, argv, ctx={}): return 0

    @apihook('TdiDefaultRcvDatagramHandler', argc=10)
    def TdiDefaultRcvDatagramHandler(self, emu, argv, ctx={}): return 0

    @apihook('TdiDefaultChainedRcvHandler', argc=8)
    def TdiDefaultChainedRcvHandler(self, emu, argv, ctx={}): return 0

    @apihook('TdiDefaultChainedRcvDatagramHandler', argc=9)
    def TdiDefaultChainedRcvDatagramHandler(self, emu, argv, ctx={}): return 0

    @apihook('TdiDefaultSendPossibleHandler', argc=3)
    def TdiDefaultSendPossibleHandler(self, emu, argv, ctx={}): return 0

    @apihook('TdiDefaultExpeditedRcvHandler', argc=9)
    def TdiDefaultExpeditedRcvHandler(self, emu, argv, ctx={}): return 0

    @apihook('TdiDefaultListenHandler', argc=5)
    def TdiDefaultListenHandler(self, emu, argv, ctx={}): return 0

    @apihook('TdiInitialize', argc=0)
    def TdiInitialize(self, emu, argv, ctx={}): return 0

    @apihook('TdiPnPPowerComplete', argc=3)
    def TdiPnPPowerComplete(self, emu, argv, ctx={}): return 0

    @apihook('TdiPnPPowerRequest', argc=4)
    def TdiPnPPowerRequest(self, emu, argv, ctx={}): return 0

    @apihook('TdiProviderReady', argc=1)
    def TdiProviderReady(self, emu, argv, ctx={}): return 0

    @apihook('TdiRegisterDeviceObject', argc=2)
    def TdiRegisterDeviceObject(self, emu, argv, ctx={}): return 0

    @apihook('TdiDeregisterDeviceObject', argc=1)
    def TdiDeregisterDeviceObject(self, emu, argv, ctx={}): return 0

    @apihook('TdiRegisterNotificationHandler', argc=3)
    def TdiRegisterNotificationHandler(self, emu, argv, ctx={}): return 0

    @apihook('TdiDeregisterNotificationHandler', argc=1)
    def TdiDeregisterNotificationHandler(self, emu, argv, ctx={}): return 0

    @apihook('TdiRegisterProvider', argc=2)
    def TdiRegisterProvider(self, emu, argv, ctx={}): return 0

    @apihook('TdiDeregisterProvider', argc=1)
    def TdiDeregisterProvider(self, emu, argv, ctx={}): return 0


# Append into Speakeasy's autodiscovered handler tuple so
# `load_api_handler('tdi')` returns our class instead of None.
def _ensure_tdi_registered():
    for name, _ in _winapi.API_HANDLERS:
        if name and name.lower() == 'tdi':
            return
    _winapi.API_HANDLERS = _winapi.API_HANDLERS + (('tdi', _TdiStub),)


_ensure_tdi_registered()


# ----------------------------------------------------------------------
# FLTMGR.SYS stub module. Speakeasy doesn't ship FltMgr handlers, so
# any minifilter halts on FltRegisterFilter / FltStartFiltering.
# We register stubs that return STATUS_SUCCESS so DriverEntry proceeds
# and the driver populates its DriverUnload + FLT_REGISTRATION pointer.
#
# `FLT_REGISTRATION_PTRS` is a per-run list of (driver_object,
# FLT_REGISTRATION pointer) tuples captured here; ktrace.py picks it
# up after DriverEntry to walk the operation table and synthetically
# invoke pre-operation callbacks.
# ----------------------------------------------------------------------
FLT_REGISTRATION_PTRS: list[tuple[int, int]] = []


def _reset_flt_state():
    FLT_REGISTRATION_PTRS.clear()


class _FltMgr(api_module.ApiHandler):
    name = 'fltmgr'
    apihook = api_module.ApiHandler.apihook
    impdata = api_module.ApiHandler.impdata

    def __init__(self, emu):
        super().__init__(emu)
        self.emu = emu

    @apihook('FltRegisterFilter', argc=3)
    def FltRegisterFilter(self, emu, argv, ctx={}):
        # NTSTATUS FltRegisterFilter(PDRIVER_OBJECT Driver,
        #     PCFLT_REGISTRATION Registration,
        #     PFLT_FILTER *RetFilter)
        if len(argv) >= 2:
            FLT_REGISTRATION_PTRS.append((argv[0] or 0, argv[1] or 0))
        # Write a non-NULL "filter handle" to the OUT param so the
        # driver doesn't bail out.
        try:
            if len(argv) >= 3 and argv[2]:
                ptr_size = 8 if emu.get_ptr_size() == 8 else 4
                fake_handle = (0x6f6b1000).to_bytes(ptr_size, 'little')
                emu.mem_write(argv[2], fake_handle)
        except Exception:
            pass
        return 0

    @apihook('FltStartFiltering', argc=1)
    def FltStartFiltering(self, emu, argv, ctx={}): return 0

    @apihook('FltUnregisterFilter', argc=1)
    def FltUnregisterFilter(self, emu, argv, ctx={}): return 0

    @apihook('FltGetFileNameInformation', argc=4)
    def FltGetFileNameInformation(self, emu, argv, ctx={}):
        # NTSTATUS FltGetFileNameInformation(PFLT_CALLBACK_DATA,
        #   FLT_FILE_NAME_OPTIONS, PFLT_FILE_NAME_INFORMATION *FileNameInformation)
        # Allocate a populated FLT_FILE_NAME_INFORMATION so callers
        # that read Name.Length / Name.Buffer don't NULL-deref.
        #
        # Layout (x64):
        #   +0x00 USHORT Size
        #   +0x02 USHORT NameParsedFlags (low) + padding
        #   +0x04 ULONG  NameParsedFlags (full)
        #   +0x08 UNICODE_STRING Name        (size 0x10)
        #   +0x18 UNICODE_STRING Volume      (size 0x10)
        #   +0x28 UNICODE_STRING Share       (size 0x10)
        #   +0x38 UNICODE_STRING Extension
        #   +0x48 UNICODE_STRING Stream
        #   +0x58 UNICODE_STRING FinalComponent
        #   +0x68 UNICODE_STRING ParentDir
        #   +0x78 PVOID Format
        if len(argv) < 3 or not argv[2]:
            return 0
        try:
            import struct as _s
            from speakeasy.common import PERM_MEM_RWX
            mm = getattr(emu, 'mem_map', None) or emu.emu.mem_map
            mw = getattr(emu, 'mem_write', None) or emu.emu.mem_write
            ps = emu.get_ptr_size()
            ufmt = '<Q' if ps == 8 else '<I'
            # Backing buffer for the UNICODE_STRING.Buffer text.
            name = '\\Device\\HarddiskVolume1\\example.txt'
            wname = name.encode('utf-16-le')
            buf = mm(len(wname) + 2, base=None,
                     tag='ktrace.flt_name_buf', perms=PERM_MEM_RWX)
            mw(buf, wname + b'\x00\x00')
            info_sz = 0x80
            info = mm(info_sz, base=None,
                      tag='ktrace.flt_name_info', perms=PERM_MEM_RWX)
            blob = bytearray(info_sz)
            _s.pack_into('<H', blob, 0x00, info_sz)  # Size
            # All UNICODE_STRINGs point at the same buffer so a caller
            # touching any of them gets a valid wide string.
            ustr_offsets_x64 = (0x08, 0x18, 0x28, 0x38, 0x48, 0x58, 0x68)
            ustr_offsets_x86 = (0x04, 0x10, 0x1c, 0x28, 0x34, 0x40, 0x4c)
            for off in (ustr_offsets_x64 if ps == 8 else ustr_offsets_x86):
                _s.pack_into('<H', blob, off, len(wname))      # Length
                _s.pack_into('<H', blob, off + 2, len(wname) + 2)  # Max
                _s.pack_into(ufmt, blob,
                             off + (8 if ps == 8 else 4), buf)  # Buffer
            mw(info, bytes(blob))
            mw(argv[2], info.to_bytes(ps, 'little'))
        except Exception:
            pass
        return 0

    @apihook('FltReleaseFileNameInformation', argc=1)
    def FltReleaseFileNameInformation(self, emu, argv, ctx={}): return 0

    @apihook('FltParseFileNameInformation', argc=1)
    def FltParseFileNameInformation(self, emu, argv, ctx={}): return 0

    @apihook('FltSetCallbackDataDirty', argc=1)
    def FltSetCallbackDataDirty(self, emu, argv, ctx={}): return 0

    @apihook('FltGetVolumeFromFileObject', argc=3)
    def FltGetVolumeFromFileObject(self, emu, argv, ctx={}): return 0

    @apihook('FltGetVolumeProperties', argc=4)
    def FltGetVolumeProperties(self, emu, argv, ctx={}): return 0

    @apihook('FltObjectDereference', argc=1)
    def FltObjectDereference(self, emu, argv, ctx={}): return 0

    @apihook('FltObjectReference', argc=1)
    def FltObjectReference(self, emu, argv, ctx={}): return 0

    @apihook('FltCancelFileOpen', argc=1)
    def FltCancelFileOpen(self, emu, argv, ctx={}): return 0

    @apihook('FltGetRequestorProcess', argc=1)
    def FltGetRequestorProcess(self, emu, argv, ctx={}): return 0

    @apihook('FltGetRequestorProcessId', argc=1)
    def FltGetRequestorProcessId(self, emu, argv, ctx={}): return 0

    @apihook('FltGetRequestorSessionId', argc=2)
    def FltGetRequestorSessionId(self, emu, argv, ctx={}): return 0

    @apihook('FltCreateCommunicationPort', argc=7)
    def FltCreateCommunicationPort(self, emu, argv, ctx={}): return 0

    @apihook('FltCloseCommunicationPort', argc=1)
    def FltCloseCommunicationPort(self, emu, argv, ctx={}): return 0

    @apihook('FltCloseClientPort', argc=2)
    def FltCloseClientPort(self, emu, argv, ctx={}): return 0

    @apihook('FltSendMessage', argc=7)
    def FltSendMessage(self, emu, argv, ctx={}): return 0

    @apihook('FltBuildDefaultSecurityDescriptor', argc=2)
    def FltBuildDefaultSecurityDescriptor(self, emu, argv, ctx={}): return 0

    @apihook('FltFreeSecurityDescriptor', argc=1)
    def FltFreeSecurityDescriptor(self, emu, argv, ctx={}): return 0

    @apihook('FltAllocateContext', argc=5)
    def FltAllocateContext(self, emu, argv, ctx={}): return 0

    @apihook('FltSetFileContext', argc=5)
    def FltSetFileContext(self, emu, argv, ctx={}): return 0

    @apihook('FltGetFileContext', argc=3)
    def FltGetFileContext(self, emu, argv, ctx={}): return 0

    @apihook('FltSetStreamContext', argc=5)
    def FltSetStreamContext(self, emu, argv, ctx={}): return 0

    @apihook('FltGetStreamContext', argc=3)
    def FltGetStreamContext(self, emu, argv, ctx={}): return 0

    @apihook('FltSetStreamHandleContext', argc=5)
    def FltSetStreamHandleContext(self, emu, argv, ctx={}): return 0

    @apihook('FltGetStreamHandleContext', argc=3)
    def FltGetStreamHandleContext(self, emu, argv, ctx={}): return 0

    @apihook('FltReleaseContext', argc=1)
    def FltReleaseContext(self, emu, argv, ctx={}): return 0

    @apihook('FltAttachVolume', argc=4)
    def FltAttachVolume(self, emu, argv, ctx={}): return 0

    @apihook('FltDetachVolume', argc=3)
    def FltDetachVolume(self, emu, argv, ctx={}): return 0

    @apihook('FltEnumerateFilters', argc=3)
    def FltEnumerateFilters(self, emu, argv, ctx={}): return 0

    @apihook('FltCreateFile', argc=14)
    def FltCreateFile(self, emu, argv, ctx={}): return 0

    @apihook('FltClose', argc=1)
    def FltClose(self, emu, argv, ctx={}): return 0

    @apihook('FltAllocatePoolAlignedWithTag', argc=4)
    def FltAllocatePoolAlignedWithTag(self, emu, argv, ctx={}): return 0

    @apihook('FltFreePoolAlignedWithTag', argc=3)
    def FltFreePoolAlignedWithTag(self, emu, argv, ctx={}): return 0


def _ensure_fltmgr_registered():
    for name, _ in _winapi.API_HANDLERS:
        if name and name.lower() == 'fltmgr':
            return
    _winapi.API_HANDLERS = _winapi.API_HANDLERS + (('fltmgr', _FltMgr),)


_ensure_fltmgr_registered()


# ----------------------------------------------------------------------
# WSK (Winsock Kernel, NETIO.SYS) stubs. Drivers that open kernel
# sockets call WskRegister + WskCaptureProviderNPI. Without handlers
# emulation halts.
# ----------------------------------------------------------------------
class _NetIo(api_module.ApiHandler):
    name = 'netio'
    apihook = api_module.ApiHandler.apihook

    def __init__(self, emu):
        super().__init__(emu)
        self.emu = emu
        # Lazy-allocated synthetic WSK_PROVIDER_DISPATCH table base.
        self._wsk_dispatch_addr = 0

    @apihook('WskRegister', argc=2)
    def WskRegister(self, emu, argv, ctx={}):
        try:
            if len(argv) >= 2 and argv[1]:
                ptr_size = emu.get_ptr_size()
                (getattr(emu, 'mem_write', None) or emu.emu.mem_write)(
                    argv[1], (0x6f6b2000).to_bytes(ptr_size, 'little'))
        except Exception:
            pass
        return 0

    @apihook('WskDeregister', argc=1)
    def WskDeregister(self, emu, argv, ctx={}): return 0

    @apihook('WskCaptureProviderNPI', argc=3)
    def WskCaptureProviderNPI(self, emu, argv, ctx={}):
        # NTSTATUS WskCaptureProviderNPI(PWSK_REGISTRATION,
        #   ULONG WaitTimeout, PWSK_PROVIDER_NPI ProviderNpi)
        #
        # ProviderNpi (PWSK_PROVIDER_NPI) is the OUT — fill it with:
        #   +0  Client   (PWSK_CLIENT)         <- fake non-NULL
        #   +8  Dispatch (PWSK_PROVIDER_DISPATCH) <- synthetic table
        #
        # WSK_PROVIDER_DISPATCH layout (x64):
        #   +0   USHORT Version
        #   +2   USHORT Reserved
        #   +8   PFN_WSK_SOCKET
        #   +16  PFN_WSK_SOCKET_CONNECT
        #   +24  PFN_WSK_CONTROL_CLIENT
        #   +32  PFN_WSK_GET_ADDRESS_INFO
        #   +40  PFN_WSK_FREE_ADDRESS_INFO
        if len(argv) < 3 or not argv[2]:
            return 0
        try:
            ptr_size = emu.get_ptr_size()
            fmt = '<Q' if ptr_size == 8 else '<I'
            # Resolve apihook trigger addresses for each dispatch slot.
            slots = ['WskSocket_NPI', 'WskSocketConnect_NPI',
                     'WskControlClient_NPI', 'WskGetAddressInfo_NPI',
                     'WskFreeAddressInfo_NPI', 'WskGetNameInfo_NPI']
            addrs = []
            for n in slots:
                try:
                    addrs.append(emu.emu.get_proc('netio', n)
                                 if hasattr(emu, 'emu')
                                 else emu.get_proc('netio', n))
                except Exception:
                    addrs.append(0)
            try:
                fallback = (emu.emu.get_proc('netio', 'WskDispatchUnknown_NPI')
                            if hasattr(emu, 'emu')
                            else emu.get_proc('netio',
                                              'WskDispatchUnknown_NPI'))
            except Exception:
                fallback = 0
            if self._wsk_dispatch_addr == 0:
                from speakeasy.common import PERM_MEM_RWX
                mem_map = (getattr(emu, 'mem_map', None) or
                           emu.emu.mem_map)
                self._wsk_dispatch_addr = mem_map(
                    0x80, base=None, tag='ktrace.wsk_dispatch',
                    perms=PERM_MEM_RWX)
            mem_write = (getattr(emu, 'mem_write', None) or
                         emu.emu.mem_write)
            import struct as _ws
            buf = bytearray(0x80)
            _ws.pack_into('<H', buf, 0, 1)   # Version
            _ws.pack_into('<H', buf, 2, 0)   # Reserved
            # Pre-fill all pointer slots in the table with the
            # `WskDispatchUnknown_NPI` fallback so calls to any
            # not-yet-stubbed function pointer log + return
            # STATUS_PENDING instead of crashing at PC=0.
            if fallback:
                for off in range(8, 0x80, ptr_size):
                    _ws.pack_into(fmt, buf, off, fallback)
            for i, a in enumerate(addrs):
                if a:
                    _ws.pack_into(fmt, buf, 8 + i * ptr_size, a)
            mem_write(self._wsk_dispatch_addr, bytes(buf))
            # Now fill ProviderNpi.
            npi = bytearray(0x10)
            _ws.pack_into(fmt, npi, 0, 0x6f6b2100)  # fake Client
            _ws.pack_into(fmt, npi, ptr_size, self._wsk_dispatch_addr)
            mem_write(argv[2], bytes(npi))
        except Exception:
            pass
        return 0

    @apihook('WskReleaseProviderNPI', argc=1)
    def WskReleaseProviderNPI(self, emu, argv, ctx={}): return 0

    @apihook('WskQueryProviderCharacteristics', argc=2)
    def WskQueryProviderCharacteristics(self, emu, argv, ctx={}): return 0

    # ---- WSK_PROVIDER_DISPATCH slots — invoked via function pointer
    # from the driver. Naming ends in _NPI so we don't collide with
    # any future Speakeasy export named `WskSocket`. format_call has
    # decoders for these that surface SOCKADDR / nodename strings.
    @apihook('WskSocket_NPI', argc=8)
    def WskSocket_NPI(self, emu, argv, ctx={}):
        # Driver registers an async I/O completion via Irp; return
        # STATUS_PENDING so it doesn't try to read a synchronous
        # socket handle that isn't there.
        return 0x00000103  # STATUS_PENDING

    @apihook('WskSocketConnect_NPI', argc=12)
    def WskSocketConnect_NPI(self, emu, argv, ctx={}):
        return 0x00000103

    @apihook('WskControlClient_NPI', argc=8)
    def WskControlClient_NPI(self, emu, argv, ctx={}):
        return 0

    @apihook('WskGetAddressInfo_NPI', argc=10)
    def WskGetAddressInfo_NPI(self, emu, argv, ctx={}):
        return 0x00000103

    @apihook('WskFreeAddressInfo_NPI', argc=2)
    def WskFreeAddressInfo_NPI(self, emu, argv, ctx={}):
        return 0

    # WSK_PROVIDER_DISPATCH offset +0x30 (after WskFreeAddressInfo at
    # +0x28). Real netfilter drivers call this to reverse-resolve an
    # SOCKADDR to a name; returning STATUS_PENDING is fine (driver gets
    # an async-style "still in progress, IRP will complete later"
    # answer and proceeds without dereferencing a buffer).
    @apihook('WskGetNameInfo_NPI', argc=9)
    def WskGetNameInfo_NPI(self, emu, argv, ctx={}):
        return 0x00000103

    # Generic any-slot fallback. Drivers occasionally use a
    # WSK_PROVIDER_DISPATCH offset beyond the documented v1 layout
    # (private debug-build symbols or v2-only members); any unfilled
    # slot otherwise stays NULL and the indirect-call crashes with
    # `pc=0: invalid_fetch`. Returning STATUS_PENDING is the most
    # benign answer for any async WSK operation. Seen on
    # `netfilterdrv.sys` (115034373fc0…) WFP-redirect installer.
    @apihook('WskDispatchUnknown_NPI', argc=8)
    def WskDispatchUnknown_NPI(self, emu, argv, ctx={}):
        return 0x00000103


class _Cng(api_module.ApiHandler):
    """cng.sys — kernel CNG (Cryptography Next Generation) BCrypt APIs.
    Drivers use these for hashing / random / signing. Stub each to
    return STATUS_SUCCESS so the driver proceeds; algorithm-correct
    output isn't needed for control-flow tracing."""
    name = 'cng'
    apihook = api_module.ApiHandler.apihook

    def __init__(self, emu):
        super().__init__(emu)
        self.emu = emu

    @apihook('BCryptOpenAlgorithmProvider', argc=4)
    def BCryptOpenAlgorithmProvider(self, emu, argv, ctx={}):
        # NTSTATUS BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE *handle,
        #   LPCWSTR pszAlgId, LPCWSTR pszImpl, ULONG dwFlags)
        try:
            if argv and argv[0]:
                ptr_size = emu.get_ptr_size()
                (getattr(emu, 'mem_write', None) or emu.emu.mem_write)(
                    argv[0], (0x6f6e1000).to_bytes(ptr_size, 'little'))
        except Exception:
            pass
        return 0

    @apihook('BCryptCloseAlgorithmProvider', argc=2)
    def BCryptCloseAlgorithmProvider(self, emu, argv, ctx={}): return 0

    @apihook('BCryptCreateHash', argc=7)
    def BCryptCreateHash(self, emu, argv, ctx={}):
        # NTSTATUS BCryptCreateHash(BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE *hh,
        #   PUCHAR pbHashObject, ULONG cbHashObject, PUCHAR pbSecret,
        #   ULONG cbSecret, ULONG dwFlags)
        try:
            if len(argv) >= 2 and argv[1]:
                ptr_size = emu.get_ptr_size()
                (getattr(emu, 'mem_write', None) or emu.emu.mem_write)(
                    argv[1], (0x6f6e2000).to_bytes(ptr_size, 'little'))
        except Exception:
            pass
        return 0

    @apihook('BCryptDestroyHash', argc=1)
    def BCryptDestroyHash(self, emu, argv, ctx={}): return 0

    @apihook('BCryptHashData', argc=4)
    def BCryptHashData(self, emu, argv, ctx={}): return 0

    @apihook('BCryptFinishHash', argc=4)
    def BCryptFinishHash(self, emu, argv, ctx={}):
        # Write zero-filled hash output so the caller doesn't crash
        # comparing it.
        try:
            if len(argv) >= 3 and argv[1] and argv[2]:
                sz = int(argv[2])
                if 0 < sz <= 256:
                    (getattr(emu, 'mem_write', None) or emu.emu.mem_write)(
                        argv[1], b'\x00' * sz)
        except Exception:
            pass
        return 0

    @apihook('BCryptGenRandom', argc=4)
    def BCryptGenRandom(self, emu, argv, ctx={}):
        try:
            if len(argv) >= 3 and argv[1] and argv[2]:
                sz = int(argv[2])
                if 0 < sz <= 0x10000:
                    # Deterministic non-zero pattern for trace
                    # reproducibility.
                    pattern = bytes((i & 0xff) for i in range(sz))
                    (getattr(emu, 'mem_write', None) or emu.emu.mem_write)(
                        argv[1], pattern)
        except Exception:
            pass
        return 0

    @apihook('BCryptDestroyKey', argc=1)
    def BCryptDestroyKey(self, emu, argv, ctx={}): return 0

    @apihook('BCryptGenerateSymmetricKey', argc=7)
    def BCryptGenerateSymmetricKey(self, emu, argv, ctx={}):
        try:
            if len(argv) >= 2 and argv[1]:
                ptr_size = emu.get_ptr_size()
                (getattr(emu, 'mem_write', None) or emu.emu.mem_write)(
                    argv[1], (0x6f6e3000).to_bytes(ptr_size, 'little'))
        except Exception:
            pass
        return 0

    @apihook('BCryptEncrypt', argc=10)
    def BCryptEncrypt(self, emu, argv, ctx={}): return 0

    @apihook('BCryptDecrypt', argc=10)
    def BCryptDecrypt(self, emu, argv, ctx={}): return 0

    @apihook('BCryptGetProperty', argc=6)
    def BCryptGetProperty(self, emu, argv, ctx={}):
        # Write a plausible size into ResultLength if requested.
        try:
            if len(argv) >= 6 and argv[5]:
                (getattr(emu, 'mem_write', None) or emu.emu.mem_write)(
                    argv[5], b'\x20\x00\x00\x00')  # 32 bytes
        except Exception:
            pass
        return 0

    @apihook('BCryptSetProperty', argc=5)
    def BCryptSetProperty(self, emu, argv, ctx={}): return 0


def _ensure_cng_registered():
    for nm, _ in _winapi.API_HANDLERS:
        if nm and nm.lower() == 'cng':
            return
    _winapi.API_HANDLERS = _winapi.API_HANDLERS + (('cng', _Cng),)


_ensure_cng_registered()


# ----------------------------------------------------------------------
# ksecdd.sys — kernel-mode security driver. Exports the BCrypt family
# (same as cng.sys via forwarding) plus Sec* identity helpers.
# Drivers (e.g. enSilo / FortiEDR) call ksecdd!BCryptHashData etc.
# rather than cng.sys.
# ----------------------------------------------------------------------
class _KsecDD(api_module.ApiHandler):
    name = 'ksecdd'
    apihook = api_module.ApiHandler.apihook

    def __init__(self, emu):
        super().__init__(emu)
        self.emu = emu

    # BCrypt family — mirror cng.sys stubs.
    @apihook('BCryptOpenAlgorithmProvider', argc=4)
    def BCryptOpenAlgorithmProvider(self, emu, argv, ctx={}):
        try:
            if argv and argv[0]:
                ptr_size = emu.get_ptr_size()
                (getattr(emu, 'mem_write', None) or emu.emu.mem_write)(
                    argv[0], (0x6f6e4000).to_bytes(ptr_size, 'little'))
        except Exception:
            pass
        return 0

    @apihook('BCryptCloseAlgorithmProvider', argc=2)
    def BCryptCloseAlgorithmProvider(self, emu, argv, ctx={}): return 0

    @apihook('BCryptCreateHash', argc=7)
    def BCryptCreateHash(self, emu, argv, ctx={}):
        try:
            if len(argv) >= 2 and argv[1]:
                ptr_size = emu.get_ptr_size()
                (getattr(emu, 'mem_write', None) or emu.emu.mem_write)(
                    argv[1], (0x6f6e5000).to_bytes(ptr_size, 'little'))
        except Exception:
            pass
        return 0

    @apihook('BCryptDestroyHash', argc=1)
    def BCryptDestroyHash(self, emu, argv, ctx={}): return 0

    @apihook('BCryptHashData', argc=4)
    def BCryptHashData(self, emu, argv, ctx={}): return 0

    @apihook('BCryptFinishHash', argc=4)
    def BCryptFinishHash(self, emu, argv, ctx={}):
        try:
            if len(argv) >= 3 and argv[1] and argv[2]:
                sz = int(argv[2])
                if 0 < sz <= 256:
                    (getattr(emu, 'mem_write', None) or emu.emu.mem_write)(
                        argv[1], b'\x00' * sz)
        except Exception:
            pass
        return 0

    @apihook('BCryptGetProperty', argc=6)
    def BCryptGetProperty(self, emu, argv, ctx={}):
        try:
            if len(argv) >= 6 and argv[5]:
                (getattr(emu, 'mem_write', None) or emu.emu.mem_write)(
                    argv[5], b'\x20\x00\x00\x00')  # 32 bytes
        except Exception:
            pass
        return 0

    @apihook('BCryptSetProperty', argc=5)
    def BCryptSetProperty(self, emu, argv, ctx={}): return 0

    @apihook('BCryptGenRandom', argc=4)
    def BCryptGenRandom(self, emu, argv, ctx={}):
        try:
            if len(argv) >= 3 and argv[1] and argv[2]:
                sz = int(argv[2])
                if 0 < sz <= 0x10000:
                    pattern = bytes((i & 0xff) for i in range(sz))
                    (getattr(emu, 'mem_write', None) or emu.emu.mem_write)(
                        argv[1], pattern)
        except Exception:
            pass
        return 0

    # Sec* identity helpers.
    @apihook('SecLookupAccountSid', argc=6)
    def SecLookupAccountSid(self, emu, argv, ctx={}): return 0

    @apihook('SecLookupAccountName', argc=6)
    def SecLookupAccountName(self, emu, argv, ctx={}): return 0

    @apihook('SecLookupWellKnownSid', argc=3)
    def SecLookupWellKnownSid(self, emu, argv, ctx={}): return 0

    @apihook('SecMakeSPN', argc=7)
    def SecMakeSPN(self, emu, argv, ctx={}): return 0


def _ensure_ksecdd_registered():
    for nm, _ in _winapi.API_HANDLERS:
        if nm and nm.lower() == 'ksecdd':
            return
    _winapi.API_HANDLERS = _winapi.API_HANDLERS + (('ksecdd', _KsecDD),)


_ensure_ksecdd_registered()


# ----------------------------------------------------------------------
# fwpkclnt.sys — Windows Filtering Platform kernel callouts. Drivers
# (legitimate firewalls AND anti-AV droppers that delete competing
# callouts) call into this. Each stub returns STATUS_SUCCESS so the
# driver proceeds; OUT handles get a fresh fake address.
# ----------------------------------------------------------------------
class _Fwpkclnt(api_module.ApiHandler):
    name = 'fwpkclnt'
    apihook = api_module.ApiHandler.apihook

    def __init__(self, emu):
        super().__init__(emu)
        self.emu = emu

    def _out_handle(self, emu, argv, idx, base=0x6f6f1000):
        try:
            if len(argv) > idx and argv[idx]:
                ptr_size = emu.get_ptr_size()
                (getattr(emu, 'mem_write', None) or emu.emu.mem_write)(
                    argv[idx], base.to_bytes(ptr_size, 'little'))
        except Exception:
            pass

    @apihook('FwpmEngineOpen0', argc=5)
    def FwpmEngineOpen0(self, emu, argv, ctx={}):
        self._out_handle(emu, argv, 4)
        return 0

    @apihook('FwpmEngineClose0', argc=1)
    def FwpmEngineClose0(self, emu, argv, ctx={}): return 0

    @apihook('FwpsCalloutRegister0', argc=3)
    def FwpsCalloutRegister0(self, emu, argv, ctx={}):
        self._out_handle(emu, argv, 2, base=0x6f6f2000)
        return 0

    @apihook('FwpsCalloutRegister1', argc=3)
    def FwpsCalloutRegister1(self, emu, argv, ctx={}):
        self._out_handle(emu, argv, 2, base=0x6f6f2100)
        return 0

    @apihook('FwpsCalloutRegister2', argc=3)
    def FwpsCalloutRegister2(self, emu, argv, ctx={}):
        self._out_handle(emu, argv, 2, base=0x6f6f2200)
        return 0

    @apihook('FwpsCalloutUnregisterById0', argc=1)
    def FwpsCalloutUnregisterById0(self, emu, argv, ctx={}): return 0

    @apihook('FwpsCalloutUnregisterByKey0', argc=1)
    def FwpsCalloutUnregisterByKey0(self, emu, argv, ctx={}): return 0

    @apihook('FwpmCalloutAdd0', argc=4)
    def FwpmCalloutAdd0(self, emu, argv, ctx={}):
        # Write out the assigned ID (DWORD) — argv[3]
        try:
            if len(argv) > 3 and argv[3]:
                (getattr(emu, 'mem_write', None) or emu.emu.mem_write)(
                    argv[3], b'\x42\x00\x00\x00')
        except Exception:
            pass
        return 0

    @apihook('FwpmCalloutDeleteById0', argc=2)
    def FwpmCalloutDeleteById0(self, emu, argv, ctx={}): return 0

    @apihook('FwpmFilterAdd0', argc=4)
    def FwpmFilterAdd0(self, emu, argv, ctx={}):
        try:
            if len(argv) > 3 and argv[3]:
                (getattr(emu, 'mem_write', None) or emu.emu.mem_write)(
                    argv[3], b'\x01\x00\x00\x00\x00\x00\x00\x00')
        except Exception:
            pass
        return 0

    @apihook('FwpmFilterDeleteById0', argc=2)
    def FwpmFilterDeleteById0(self, emu, argv, ctx={}): return 0

    @apihook('FwpmTransactionBegin0', argc=2)
    def FwpmTransactionBegin0(self, emu, argv, ctx={}): return 0

    @apihook('FwpmTransactionCommit0', argc=1)
    def FwpmTransactionCommit0(self, emu, argv, ctx={}): return 0

    @apihook('FwpmTransactionAbort0', argc=1)
    def FwpmTransactionAbort0(self, emu, argv, ctx={}): return 0

    @apihook('FwpmSubLayerAdd0', argc=3)
    def FwpmSubLayerAdd0(self, emu, argv, ctx={}): return 0

    @apihook('FwpmProviderAdd0', argc=3)
    def FwpmProviderAdd0(self, emu, argv, ctx={}): return 0

    @apihook('FwpsInjectionHandleCreate0', argc=3)
    def FwpsInjectionHandleCreate0(self, emu, argv, ctx={}):
        self._out_handle(emu, argv, 2, base=0x6f6f3000)
        return 0

    @apihook('FwpsInjectionHandleDestroy0', argc=1)
    def FwpsInjectionHandleDestroy0(self, emu, argv, ctx={}): return 0

    @apihook('FwpmBfeStateGet0', argc=0)
    def FwpmBfeStateGet0(self, emu, argv, ctx={}):
        # FWPM_SERVICE_STATE: STOPPED=0, START_PENDING=1, STOP_PENDING=2,
        # RUNNING=3. Return 3 (RUNNING) so drivers that wait for the
        # Base Filtering Engine before installing filters proceed
        # immediately.
        return 3

    @apihook('FwpmBfeStateSubscribeChanges0', argc=4)
    def FwpmBfeStateSubscribeChanges0(self, emu, argv, ctx={}):
        # NTSTATUS FwpmBfeStateSubscribeChanges0(
        #   HANDLE engine,
        #   FWPM_SERVICE_STATE_CHANGE_CALLBACK0 callback,
        #   PVOID context,
        #   HANDLE *changeHandle) ;   <-- argv[3] OUT
        try:
            if len(argv) > 3 and argv[3]:
                ptr_size = emu.get_ptr_size()
                (getattr(emu, 'mem_write', None) or emu.emu.mem_write)(
                    argv[3], (0x6f6f4000).to_bytes(ptr_size, 'little'))
        except Exception:
            pass
        return 0

    @apihook('FwpmBfeStateUnsubscribeChanges0', argc=1)
    def FwpmBfeStateUnsubscribeChanges0(self, emu, argv, ctx={}): return 0

    @apihook('FwpsFlowAssociateContext0', argc=4)
    def FwpsFlowAssociateContext0(self, emu, argv, ctx={}): return 0

    @apihook('FwpsFlowRemoveContext0', argc=2)
    def FwpsFlowRemoveContext0(self, emu, argv, ctx={}): return 0


def _ensure_fwpkclnt_registered():
    # Speakeasy ships its own fwpkclnt handler with ~12 stubs. If it's
    # already registered, additively monkey-patch its class with our
    # extra functions (FwpmBfeStateGet0, FwpmBfeStateSubscribeChanges0,
    # FwpsFlowAssociateContext0, etc.) that drivers reach but
    # Speakeasy never implemented.
    apihook = api_module.ApiHandler.apihook
    for nm, hdl_cls in _winapi.API_HANDLERS:
        if nm and nm.lower() == 'fwpkclnt':
            # Pull each method from our _Fwpkclnt class and attach to the
            # existing handler class via apihook, unless already present.
            for our_name in dir(_Fwpkclnt):
                our_fn = getattr(_Fwpkclnt, our_name, None)
                if not callable(our_fn):
                    continue
                hook = getattr(our_fn, '__apihook__', None)
                if not hook:
                    continue
                hk_name = hook[0]
                if hasattr(hdl_cls, hk_name):
                    continue
                # Apihook mutates __apihook__ in place — use a fresh
                # wrapper per name so each registers independently.
                def _make(target, name, argc):
                    def _t(self, emu, argv, ctx={}):
                        return target(self, emu, argv, ctx)
                    _t.__name__ = name
                    return apihook(name, argc=argc)(_t)
                setattr(hdl_cls, hk_name,
                        _make(our_fn, hk_name, hook[2]))
            return
    _winapi.API_HANDLERS = _winapi.API_HANDLERS + (('fwpkclnt', _Fwpkclnt),)


_ensure_fwpkclnt_registered()


def _ensure_netio_registered():
    # Speakeasy already ships a netio module — only register if it's
    # missing one of our stubs. Use additive registration.
    for nm, hdl in _winapi.API_HANDLERS:
        if nm and nm.lower() == 'netio':
            for fn_name in ('WskRegister', 'WskDeregister',
                            'WskCaptureProviderNPI',
                            'WskReleaseProviderNPI',
                            'WskQueryProviderCharacteristics',
                            'WskSocket_NPI', 'WskSocketConnect_NPI',
                            'WskControlClient_NPI',
                            'WskGetAddressInfo_NPI',
                            'WskFreeAddressInfo_NPI',
                            'WskGetNameInfo_NPI',
                            'WskDispatchUnknown_NPI'):
                if not hasattr(hdl, fn_name):
                    src = getattr(_NetIo, fn_name)
                    setattr(hdl, fn_name, src)
            return
    _winapi.API_HANDLERS = _winapi.API_HANDLERS + (('netio', _NetIo),)


_ensure_netio_registered()
