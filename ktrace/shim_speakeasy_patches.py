"""Patches over Speakeasy internals that need fixing for our workflow:
the create_device_object NextDevice typo + a few generate_export_table
overrides. Kept here so install_shim stays readable."""
import struct as _struct
from speakeasy.winenv.api import api as api_module
from speakeasy.windows.kernel import WinKernelEmulator
apihook = api_module.ApiHandler.apihook


def install_speakeasy_patches(arch_bits, ntos_mod, conv, state):
    is64 = (arch_bits == 64)
    # ---- Patch Speakeasy's `create_device_object` ------------------
    # kernel.py:418 has a typo: `drv.object.NextDevice` should be
    # `next_dev.object.NextDevice`. DRIVER_OBJECT has no NextDevice so
    # this AttributeError-crashes the second IoCreateDevice on any
    # driver that creates 3+ devices (e.g. TDI / NDIS filters).
    try:
        from speakeasy.windows import kernel as _spk_kernel
        from speakeasy.windows import objman as _spk_objman
        _orig_cdo = _spk_kernel.WinKernelEmulator.create_device_object

        def _patched_create_device_object(self, name='', drv=0, ext_size=0,
                                          devtype=0, chars=0, tag=''):
            dev = _spk_objman.Device(self)
            alloc_size = ext_size + dev.sizeof()
            if not name:
                devname = r'\Device\%x' % (dev.get_id())
                if not tag:
                    tag = 'emu.device.autogen'
                name = '%s.%s' % (tag, devname)
            else:
                devname = name
                if not tag:
                    tag = 'emu.object'
                name = '%s.%s' % (tag, devname)
            dev.address = self.mem_map(alloc_size, tag=name)
            dev.name = devname
            fobj = _spk_objman.FileObject(self)
            dev.object.DeviceObject = dev.address
            dev.file_object = fobj
            self.add_object(dev)
            if drv:
                drv.read_back()
                dev.object.DriverObject = drv.address
                dev.driver = drv
                if not drv.object.DeviceObject:
                    drv.object.DeviceObject = dev.address
                    drv.write_back()
                else:
                    next_dev = self.get_object_from_addr(
                        drv.object.DeviceObject)
                    # bounded walk in case of bad data
                    for _ in range(64):
                        if next_dev is None:
                            break
                        if next_dev.object.NextDevice:
                            nxt = self.get_object_from_addr(
                                next_dev.object.NextDevice)
                            if nxt is None or nxt is next_dev:
                                break
                            next_dev = nxt
                        else:
                            next_dev.object.NextDevice = dev.address
                            next_dev.write_back()
                            break
                drv.devices.append(dev)
            dev.object.Characteristics = chars
            dev.object.DeviceType = devtype
            if ext_size > 0:
                dev.object.DeviceExtension = dev.address + dev.sizeof()
            dev.write_back()
            return dev

        _spk_kernel.WinKernelEmulator.create_device_object = \
            _patched_create_device_object
    except Exception:
        pass

    # #2 KMDF support: WdfVersionBind populates `WDF_BIND_INFO.FuncTable`
    # with function pointers the driver subsequently calls through. If
    # we return 0 and don't fill the table, the next WDF call jumps to
    # NULL. Fill every slot with a shared "WdfFunctionStub" apihook
    # trigger so calls land on a benign 0-returning handler.

    # OUT-handle heuristic: most WDF "Create" functions take the
    # output handle pointer as the LAST argument. If that arg points
    # at a zero qword/dword (uninitialized OUT slot), populate it with
    # a fake non-NULL handle so subsequent driver code doesn't NULL-
    # deref. If the slot is already non-zero we don't touch it
    # (could be an input config struct pointer in some signatures).
    #
    # We hand out a fresh fake handle per call so the driver can
    # distinguish them. Speakeasy passes argv per the registered
    # argc; we set argc=10 here to cover the worst-case WDF signature
    # (WdfDeviceCreateDeviceInterface takes 4, WdfRequestSend takes 4,
    # WdfDeviceInitAssignSDDLString takes 2, etc. — 10 is plenty).
    state['wdf_next_handle'] = 0x6f6d0000

    def _wdf_function_stub(self, emu, argv, ctx={}):
        if not argv:
            return 0
        last = argv[-1]
        if not (isinstance(last, int) and 0x10000 <= last < 0xffff_ffff_ffff):
            return 0
        try:
            ps = emu.get_ptr_size() if hasattr(emu, 'get_ptr_size') \
                else (8 if arch_bits == 64 else 4)
            before = bytes((getattr(emu, 'mem_read', None) or
                            emu.emu.mem_read)(last, ps))
        except Exception:
            return 0
        if any(b != 0 for b in before):
            # Slot already populated — likely an input pointer, leave alone.
            return 0
        # Hand out a unique fake handle per call.
        h = state['wdf_next_handle']
        state['wdf_next_handle'] = h + 0x100
        try:
            (getattr(emu, 'mem_write', None) or emu.emu.mem_write)(
                last, h.to_bytes(ps, 'little'))
        except Exception:
            return 0
        return 0  # STATUS_SUCCESS

    setattr(ntos_mod.Ntoskrnl, 'WdfFunctionStub',
            apihook('WdfFunctionStub', argc=10, conv=conv)(_wdf_function_stub))

    # Save reference to Speakeasy's own WdfVersionBind if available.
    # Speakeasy's impl allocates its own FuncTable + populates known
    # slots (WdfDeviceCreate, WdfIoQueueCreate, WdfDriverCreate, …)
    # with apihook-trigger addresses to its real implementations. We
    # call that FIRST, then fill any *still-NULL* slots with the
    # generic WdfFunctionStub so calls to unimplemented WDF functions
    # land on a benign 0-returning handler instead of NULL-jumping.
    _orig_wvb = getattr(
        __import__('speakeasy.winenv.api.kernelmode.wdfldr',
                   fromlist=['Wdfldr']).Wdfldr,
        'WdfVersionBind', None)

    def _wdf_version_bind(self, emu, argv, ctx={}):
        if len(argv) < 3 or not argv[2]:
            return 0
        # Hand off to Speakeasy first so its WdfDeviceCreate /
        # WdfIoQueueCreate / WdfDriverCreate / … slots get the real
        # implementations rather than a generic 0-stub.
        try:
            if _orig_wvb is not None:
                _orig_wvb(self, emu, argv, ctx)
        except Exception:
            pass
        bind_info = argv[2]
        try:
            arch_now = emu.get_arch()
            is64 = (arch_now == 64 or arch_now == 2)  # speakeasy's ARCH_AMD64==2
        except Exception:
            is64 = (arch_bits == 64)
        # WDF_BIND_INFO offsets (x64). On x86, ULONGs are not 8-aligned
        # so FuncCount/FuncTable are at +0x10/+0x14.
        if is64:
            fc_off, ft_off, ptr_size, packfmt = 0x20, 0x28, 8, '<Q'
        else:
            fc_off, ft_off, ptr_size, packfmt = 0x10, 0x14, 4, '<I'
        try:
            func_count = _struct.unpack(
                '<I', emu.mem_read(bind_info + fc_off, 4))[0]
            func_table = _struct.unpack(
                packfmt, emu.mem_read(bind_info + ft_off, ptr_size))[0]
            if not func_table or func_count == 0 or func_count > 5000:
                return 0
            stub_addr = emu.emu.get_proc('ntoskrnl', 'WdfFunctionStub')
            # Backfill only the slots that Speakeasy didn't populate.
            # That way the working WdfDeviceCreate/WdfIoQueueCreate
            # impls stay reachable and only the unimplemented entries
            # land on the generic stub.
            try:
                existing = bytes(emu.mem_read(func_table,
                                              func_count * ptr_size))
            except Exception:
                existing = b'\x00' * (func_count * ptr_size)
            stub_bytes = _struct.pack(packfmt, stub_addr)
            new = bytearray()
            for i in range(func_count):
                slot = existing[i*ptr_size:(i+1)*ptr_size]
                if any(slot):
                    new += slot          # keep Speakeasy's real impl
                else:
                    new += stub_bytes    # backfill with generic stub
            emu.mem_write(func_table, bytes(new))
        except Exception:
            pass
        return 0  # STATUS_SUCCESS
    setattr(ntos_mod.Ntoskrnl, 'WdfVersionBind',
            apihook('WdfVersionBind', argc=4, conv=conv)(_wdf_version_bind))
    setattr(ntos_mod.Ntoskrnl, 'WdfVersionBindClass',
            apihook('WdfVersionBindClass', argc=4, conv=conv)(_wdf_version_bind))

    # ---- Patch Speakeasy's ZwOpenKey / NtOpenKey / *Ex / *Transacted
    # bug. The upstream handler calls reg_open_key(name, create=False);
    # when the key doesn't exist that returns None, then
    # `hnd.to_bytes(...)` crashes the whole emulation run.
    # We swap in our own handlers that:
    #   - if the key exists in Speakeasy's reg view, write that handle
    #   - otherwise hand out a fresh fake handle (so the driver proceeds
    #     past key-existence checks into the per-value queries we already
    #     stub via RtlQueryRegistryValues / ZwQueryValueKey).
    state['fake_reg_next_handle'] = 0xfa000000
    state['fake_reg_handles'] = {}  # name(str) -> handle

    def _zw_open_key_impl(self, emu, argv, ctx={}):
        if len(argv) < 3:
            return 0xC0000001  # STATUS_UNSUCCESSFUL
        phnd, _access, objattr = argv[0], argv[1], argv[2]
        name = ''
        try:
            oa = self.win.OBJECT_ATTRIBUTES(emu.get_ptr_size())
            oa = self.mem_cast(oa, objattr)
            name = self.read_unicode_string(oa.ObjectName) or ''
            argv[2] = name
        except Exception:
            pass
        hnd = None
        try:
            hnd = self.reg_open_key(name, create=False)
        except Exception:
            hnd = None
        if not hnd:
            cache = state['fake_reg_handles']
            hnd = cache.get(name)
            if not hnd:
                hnd = state['fake_reg_next_handle']
                state['fake_reg_next_handle'] = hnd + 4
                cache[name] = hnd
            try:
                import decode
                if name:
                    decode.remember_handle(hnd, name)
            except Exception:
                pass
        if phnd:
            try:
                self.mem_write(
                    phnd, int(hnd).to_bytes(
                        emu.get_ptr_size(), 'little'))
            except Exception:
                pass
        return 0  # STATUS_SUCCESS

    # Override both Zw* and Nt* (and their Ex / Transacted variants).
    # apihook() mutates `__apihook__` on the wrapped function object —
    # use a fresh wrapper per name so each registers under its own key.
    def _make_zwopen(name, argc):
        def _trampoline(self, emu, argv, ctx={}):
            return _zw_open_key_impl(self, emu, argv, ctx)
        _trampoline.__name__ = name
        return apihook(name, argc=argc, conv=conv)(_trampoline)

    for _nm, _argc in (('ZwOpenKey', 3), ('NtOpenKey', 3),
                       ('ZwOpenKeyEx', 4), ('NtOpenKeyEx', 4),
                       ('ZwOpenKeyTransacted', 4),
                       ('NtOpenKeyTransacted', 4),
                       ('ZwOpenKeyTransactedEx', 5),
                       ('NtOpenKeyTransactedEx', 5)):
        setattr(ntos_mod.Ntoskrnl, _nm, _make_zwopen(_nm, _argc))

    # OA-name snapshotting for ZwCreateFile / ZwOpenFile / NtCreateFile /
    # etc. lives inside shim_fake_io.py's _make_open_file handler — done
    # there because it owns the apihook registration for the file APIs
    # (installed last in shim.py's chain, so any wrapping here would be
    # overwritten anyway). Without that snapshot, by format_call time
    # the driver has often returned from the function that built the
    # OA on its stack frame and the bytes are stale.

    # ---- Patch Speakeasy's ZwQueryValueKey: upstream tries
    # `self.get_bytes(vi) + data` where get_bytes() returns a str
    # ("can't concat str to bytes"). Even when not crashing, it returns
    # nothing useful for drivers querying their own service-key values
    # (ImagePath / Start / Type / ErrorControl).
    #
    # Provide a synthetic responder that recognises common service-key
    # value names and returns a plausible KEY_VALUE_PARTIAL_INFORMATION
    # blob, so the driver's "find my install path" / "check Start type"
    # logic proceeds. Unknown values get STATUS_OBJECT_NAME_NOT_FOUND.
    import struct as _s2

    def _zw_query_value_key_impl(self, emu, argv, ctx={}):
        if len(argv) < 6:
            return 0xC0000001
        phnd, pval, info_class, val_info, length, ret_len = argv
        name = ''
        try:
            name = self.read_unicode_string(pval) or ''
            argv[1] = name
        except Exception:
            pass
        REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD = 1, 2, 3, 4
        v_type = REG_DWORD
        data = None

        # Priority 1: --prime-reg / --fake-io-data user-supplied values
        # take precedence over our hardcoded service-key synthesis.
        # Looks up by (key_path, value_name) case-insensitively. The
        # key_path comes from the symlink-handle map that ZwOpenKey
        # populated above.
        try:
            from shim_fake_io import FAKE_IO
            user_reg = FAKE_IO.get('registry_data') or {}
            if name and user_reg:
                key_path = state.get('fake_reg_handles', {})
                # state['fake_reg_handles'] is value-name -> handle. We
                # need handle -> key-path. Use the OpenKey-side cache.
                path = None
                # Reverse-lookup via decode.lookup_handle (handles are
                # auto-registered there by our ZwOpenKey).
                try:
                    import decode
                    path = decode.lookup_handle(phnd)
                except Exception:
                    pass
                if path:
                    bag = user_reg.get(path) or {}
                    if not bag:
                        low = path.lower()
                        for k, v in user_reg.items():
                            if k.lower() == low:
                                bag = v
                                break
                    val = bag.get(name) if bag else None
                    if val is None and bag:
                        low_n = name.lower()
                        for k, v in bag.items():
                            if k.lower() == low_n:
                                val = v
                                break
                    if val:
                        v_type = int(val.get('type', 4))
                        try:
                            data = bytes.fromhex(val.get('data_hex', ''))
                        except Exception:
                            data = b''
        except Exception:
            pass

        # Priority 2: hardcoded service-key synthesis for common names
        # (only when --prime-reg / --fake-io-data didn't provide a value).
        n_lo = (name or '').lower()
        if data is None:
            if n_lo == 'imagepath':
                v_type = REG_EXPAND_SZ
                data = ('\\SystemRoot\\System32\\drivers\\ktrace_synth.sys'
                        .encode('utf-16-le') + b'\x00\x00')
            elif n_lo == 'displayname':
                v_type = REG_SZ
                data = 'ktrace synthetic driver'.encode('utf-16-le') + b'\x00\x00'
            elif n_lo == 'start':
                v_type = REG_DWORD
                data = (3).to_bytes(4, 'little')  # SERVICE_DEMAND_START
            elif n_lo == 'type':
                v_type = REG_DWORD
                data = (1).to_bytes(4, 'little')  # SERVICE_KERNEL_DRIVER
            elif n_lo == 'errorcontrol':
                v_type = REG_DWORD
                data = (1).to_bytes(4, 'little')  # SERVICE_ERROR_NORMAL
            elif n_lo == 'group':
                v_type = REG_SZ
                data = 'FSFilter Anti-Virus'.encode('utf-16-le') + b'\x00\x00'
            elif n_lo == 'dependonservice':
                v_type = REG_SZ
                data = 'FltMgr\x00'.encode('utf-16-le') + b'\x00\x00'
            elif n_lo == 'altitude':
                v_type = REG_SZ
                data = '320900'.encode('utf-16-le') + b'\x00\x00'
            else:
                return 0xC0000034  # STATUS_OBJECT_NAME_NOT_FOUND

        # KEY_VALUE_PARTIAL_INFORMATION = 12-byte header + data:
        #   ULONG TitleIndex; ULONG Type; ULONG DataLength; UCHAR Data[1];
        # KEY_VALUE_FULL_INFORMATION = 16-byte header + name + data:
        #   ULONG TitleIndex; ULONG Type; ULONG DataOffset;
        #   ULONG DataLength; ULONG NameLength; WCHAR Name[1];
        KVPI_PARTIAL, KVPI_FULL = 2, 1
        if info_class == KVPI_PARTIAL:
            hdr = _s2.pack('<III', 0, v_type, len(data))
            output = hdr + data
        elif info_class == KVPI_FULL:
            name_w = (name.encode('utf-16-le') + b'\x00\x00')
            hdr_sz = 20  # 5 × ULONG including NameLength
            hdr = _s2.pack('<IIIII', 0, v_type, hdr_sz + len(name_w),
                           len(data), len(name_w))
            output = hdr + name_w + data
        else:
            output = data  # Best-effort for unknown classes.

        try:
            self.mem_write(
                ret_len, len(output).to_bytes(4, 'little'))
        except Exception:
            pass
        if length < len(output) or not val_info:
            return 0xC0000023  # STATUS_BUFFER_TOO_SMALL
        try:
            self.mem_write(val_info, output)
        except Exception:
            return 0xC0000001
        return 0  # STATUS_SUCCESS

    def _make_zwquery(name):
        def _t(self, emu, argv, ctx={}):
            return _zw_query_value_key_impl(self, emu, argv, ctx)
        _t.__name__ = name
        return apihook(name, argc=6, conv=conv)(_t)
    for _nm in ('ZwQueryValueKey', 'NtQueryValueKey'):
        setattr(ntos_mod.Ntoskrnl, _nm, _make_zwquery(_nm))

    # ---- Snapshot registry-value writes BEFORE the data buffer can be
    # freed. Speakeasy's report (and our format_call) only run after
    # `run_module` finishes a chunk, by which point an
    # ExFreePoolWithTag a few instructions later would have unmapped the
    # buffer. We render the value here, stash the decoded text back
    # into argv[4], and `decode.fmt_reg_data` recognises the string
    # form so the log line shows the snapshot.
    import decode as _dec
    state['reg_write_next_handle'] = 0xfa400000

    def _snapshot_reg_value(emu_obj, type_val, data_addr, length):
        """Return a string like REG_SZ('foo') / REG_DWORD(0x4) /
        REG_BINARY(b'...'). Always succeeds (caller already validated
        the args), but may return None if the read fails."""
        try:
            t = _dec.as_int(type_val) or 0
            addr = _dec.as_int(data_addr) or 0
            n = (_dec.as_int(length) or 0) & 0xFFFFFFFF
        except Exception:
            return None
        if n == 0 or not addr:
            return f"{_dec.fmt_reg_type(t)}(<empty>)"
        if t in (1, 2, 6):   # REG_SZ / REG_EXPAND_SZ / REG_LINK
            try:
                raw = bytes(emu_obj.mem_read(addr, min(n, 0x800)))
            except Exception:
                return None
            if raw.endswith(b'\x00\x00'):
                raw = raw[:-2]
            try:
                s = raw.decode('utf-16-le', errors='replace').rstrip('\x00')
            except Exception:
                return None
            return f"{_dec.fmt_reg_type(t)}({s!r})"
        if t == 7:           # REG_MULTI_SZ
            try:
                raw = bytes(emu_obj.mem_read(addr, min(n, 0x1000)))
            except Exception:
                return None
            text = raw.decode('utf-16-le', errors='replace')
            parts = [p for p in text.split('\x00') if p]
            return f"{_dec.fmt_reg_type(t)}({parts!r})"
        if t == 4:           # REG_DWORD
            try:
                raw = bytes(emu_obj.mem_read(addr, 4))
                return f"{_dec.fmt_reg_type(t)}(0x{int.from_bytes(raw,'little'):x})"
            except Exception:
                return None
        if t == 11:          # REG_QWORD
            try:
                raw = bytes(emu_obj.mem_read(addr, 8))
                return f"{_dec.fmt_reg_type(t)}(0x{int.from_bytes(raw,'little'):x})"
            except Exception:
                return None
        # Generic preview (REG_BINARY, REG_RESOURCE_LIST, ...).
        cap = max(0, getattr(_dec, '_DATA_PREVIEW_BYTES', 20))
        if cap == 0:
            return f"{_dec.fmt_reg_type(t)}({n} bytes @ 0x{addr:x})"
        try:
            raw = bytes(emu_obj.mem_read(addr, min(n, cap)))
        except Exception:
            return None
        return f"{_dec.fmt_reg_type(t)}({_dec._escape_preview(raw, n)})"

    def _rtl_write_registry_value_impl(self, emu, argv, ctx={}):
        # NTSTATUS RtlWriteRegistryValue(ULONG RelativeTo, PCWSTR Path,
        #                                PCWSTR Name, ULONG Type,
        #                                PVOID Data, ULONG Length);
        if len(argv) < 6:
            return 0xC0000001
        # Resolve Path / Name UNICODE_STRINGs / PWSTRs for readability.
        try:
            argv[1] = self.read_wide_string(argv[1]) or argv[1]
        except Exception:
            pass
        try:
            argv[2] = self.read_wide_string(argv[2]) or argv[2]
        except Exception:
            pass
        snap = _snapshot_reg_value(self, argv[3], argv[4], argv[5])
        if snap is not None:
            argv[4] = snap   # format_call sees the string and renders it inline
        return 0  # STATUS_SUCCESS

    def _zw_set_value_key_impl(self, emu, argv, ctx={}):
        # NTSTATUS ZwSetValueKey(HANDLE Key, PUNICODE_STRING ValueName,
        #                        ULONG Index, ULONG Type, PVOID Data,
        #                        ULONG Length);
        if len(argv) < 6:
            return 0xC0000001
        try:
            name = self.read_unicode_string(argv[1])
            if name:
                argv[1] = name
        except Exception:
            pass
        snap = _snapshot_reg_value(self, argv[3], argv[4], argv[5])
        if snap is not None:
            argv[4] = snap
        return 0  # STATUS_SUCCESS

    def _make_write_reg():
        def _t(self, emu, argv, ctx={}):
            return _rtl_write_registry_value_impl(self, emu, argv, ctx)
        _t.__name__ = 'RtlWriteRegistryValue'
        return apihook('RtlWriteRegistryValue', argc=6, conv=conv)(_t)
    setattr(ntos_mod.Ntoskrnl, 'RtlWriteRegistryValue', _make_write_reg())

    def _make_setval(name):
        def _t(self, emu, argv, ctx={}):
            return _zw_set_value_key_impl(self, emu, argv, ctx)
        _t.__name__ = name
        return apihook(name, argc=6, conv=conv)(_t)
    for _nm in ('ZwSetValueKey', 'NtSetValueKey'):
        setattr(ntos_mod.Ntoskrnl, _nm, _make_setval(_nm))

    # ---- Symbolic-link object stubs: track handle->link-name so a later
    # ZwQuerySymbolicLinkObject can return the (synthesised) target.
    # Drive-letter enumeration ('\??\A:' .. '\??\Z:' → '\Device\HarddiskVolumeN')
    # is the canonical use; without it, drivers that build a dosname→devname
    # mapping table during init bail out with empty targets.
    state['symlink_target_by_handle'] = {}

    def _zw_open_symlink_impl(self, emu, argv, ctx={}):
        if len(argv) < 3:
            return 0xC0000001
        phnd, _access, objattr = argv[0], argv[1], argv[2]
        link_name = ''
        try:
            oa = self.win.OBJECT_ATTRIBUTES(emu.get_ptr_size())
            oa = self.mem_cast(oa, objattr)
            link_name = self.read_unicode_string(oa.ObjectName) or ''
            argv[2] = link_name
        except Exception:
            pass
        # Compute the target. For '\??\X:' (drive letter) return
        # \Device\HarddiskVolume<idx>; for other links use a generic
        # placeholder so drivers that hash/compare the target still
        # see *something*.
        target = ''
        if link_name:
            ln = link_name.lower()
            if ln.startswith('\\??\\') and len(link_name) == 6 \
                    and link_name[5] == ':':
                letter = link_name[4].lower()
                # Map A=0, B=1, C=2, ..., but C: is by far the most
                # important; everything below C gets a high-volume slot.
                idx = max(2, ord(letter) - ord('a'))
                target = f'\\Device\\HarddiskVolume{idx}'
            elif ln.startswith('\\dosdevices\\') or ln.startswith('\\??\\'):
                target = f'\\Device\\{link_name.split(chr(92))[-1] or "obj"}'
        # Mint a synthetic handle and remember it.
        h = 0xfa800000 + (len(state['symlink_target_by_handle']) << 4)
        state['symlink_target_by_handle'][h] = (link_name, target)
        try:
            import decode
            if link_name:
                decode.remember_handle(h, link_name)
        except Exception:
            pass
        if phnd:
            try:
                self.mem_write(
                    phnd, int(h).to_bytes(
                        emu.get_ptr_size(), 'little'))
            except Exception:
                pass
        return 0  # STATUS_SUCCESS

    def _zw_query_symlink_impl(self, emu, argv, ctx={}):
        # NTSTATUS ZwQuerySymbolicLinkObject(HANDLE, PUNICODE_STRING out,
        #                                    PULONG ret_len)
        if len(argv) < 2 or not argv[1]:
            return 0xC0000001
        h = argv[0]
        # Look up the remembered target (set by our ZwOpenSymbolicLinkObject).
        _link, target = state['symlink_target_by_handle'].get(h, ('', ''))
        if not target:
            # Last-ditch: pretend everything points to HarddiskVolume2.
            target = '\\Device\\HarddiskVolume2'
        target_wb = target.encode('utf-16-le')
        ptr_size = emu.get_ptr_size()
        # UNICODE_STRING: USHORT Length, USHORT Max, [pad,] PWSTR Buffer
        import struct as _ss
        try:
            if ptr_size == 8:
                hdr = bytes(self.mem_read(argv[1], 16))
                max_len = _ss.unpack('<H', hdr[2:4])[0]
                buf = _ss.unpack('<Q', hdr[8:16])[0]
            else:
                hdr = bytes(self.mem_read(argv[1], 8))
                max_len = _ss.unpack('<H', hdr[2:4])[0]
                buf = _ss.unpack('<I', hdr[4:8])[0]
        except Exception:
            return 0xC0000001
        if not buf or max_len < len(target_wb):
            return 0xC0000023  # STATUS_BUFFER_TOO_SMALL
        try:
            self.mem_write(buf, target_wb)
            # Update Length in the UNICODE_STRING header.
            self.mem_write(argv[1], _ss.pack('<H', len(target_wb)))
            if len(argv) > 2 and argv[2]:
                self.mem_write(argv[2],
                               len(target_wb).to_bytes(4, 'little'))
        except Exception:
            return 0xC0000001
        return 0

    def _make_sym_open(name):
        def _t(self, emu, argv, ctx={}):
            return _zw_open_symlink_impl(self, emu, argv, ctx)
        _t.__name__ = name
        return apihook(name, argc=3, conv=conv)(_t)

    def _make_sym_query(name):
        def _t(self, emu, argv, ctx={}):
            return _zw_query_symlink_impl(self, emu, argv, ctx)
        _t.__name__ = name
        return apihook(name, argc=3, conv=conv)(_t)

    for _nm in ('ZwOpenSymbolicLinkObject', 'NtOpenSymbolicLinkObject'):
        setattr(ntos_mod.Ntoskrnl, _nm, _make_sym_open(_nm))
    for _nm in ('ZwQuerySymbolicLinkObject', 'NtQuerySymbolicLinkObject'):
        setattr(ntos_mod.Ntoskrnl, _nm, _make_sym_query(_nm))

    # ---- Real impl: IoQueryFileDosDeviceName + IoVolumeDeviceToDosName
    # Drivers that need to convert a FILE_OBJECT or DEVICE_OBJECT back to
    # a DOS-style path call these. Signature (both):
    #   NTSTATUS Io...(P{FILE,DEVICE}_OBJECT, POBJECT_NAME_INFORMATION *)
    # The pointed-to POBJECT_NAME_INFORMATION* must be filled with a
    # pool-allocated OBJECT_NAME_INFORMATION blob the caller will later
    # ExFreePool. A stub returning STATUS_SUCCESS with the OUT-pointer
    # untouched causes a NULL-deref in the caller's next `wcsncpy(...,
    # info->Name.Buffer, info->Name.Length)`. So write a populated blob.
    #
    # OBJECT_NAME_INFORMATION layout (x64):
    #   +0x00 UNICODE_STRING Name  (Length=2, MaxLen=2, pad=4, Buffer=8 -> 0x10 bytes)
    #   +0x10 WCHAR backing buffer
    def _io_query_dos_name_impl(self, emu, argv, ctx={}):
        if len(argv) < 2 or not argv[1]:
            return 0xC0000001  # STATUS_UNSUCCESSFUL
        try:
            from speakeasy.common import PERM_MEM_RWX
            mm = getattr(emu, 'mem_map', None) or emu.emu.mem_map
            mw = getattr(emu, 'mem_write', None) or emu.emu.mem_write
            ps = emu.get_ptr_size()
            ufmt = '<Q' if ps == 8 else '<I'
            name = r'\??\C:'
            wname = name.encode('utf-16-le')
            # UNICODE_STRING (16B on x64, 8B on x86) + null-terminated wide-buffer
            ustr_sz = 0x10 if ps == 8 else 0x08
            buf_sz = len(wname) + 2
            blob = ustr_sz + buf_sz
            addr = mm(blob, base=None, tag='ktrace.io_dos_name',
                      perms=PERM_MEM_RWX)
            data = bytearray(blob)
            _struct.pack_into('<H', data, 0, len(wname))             # Length
            _struct.pack_into('<H', data, 2, len(wname) + 2)         # MaxLen
            _struct.pack_into(ufmt, data,
                              8 if ps == 8 else 4,
                              addr + ustr_sz)                         # Buffer
            data[ustr_sz:ustr_sz + len(wname)] = wname
            mw(addr, bytes(data))
            mw(argv[1], addr.to_bytes(ps, 'little'))
        except Exception:
            return 0xC0000001
        return 0  # STATUS_SUCCESS

    def _make_dos_name(nm):
        def _t(self, emu, argv, ctx={}):
            return _io_query_dos_name_impl(self, emu, argv, ctx)
        _t.__name__ = nm
        return apihook(nm, argc=2, conv=conv)(_t)

    for _nm in ('IoQueryFileDosDeviceName', 'IoVolumeDeviceToDosName'):
        setattr(ntos_mod.Ntoskrnl, _nm, _make_dos_name(_nm))

    # ---- Fake-ntoskrnl synthesis for byte-pattern-resolution tricks.
    #
    # Sophisticated drivers (e.g. Chinese surveillance/EDR kernels) don't
    # just MmGetSystemRoutineAddress a name and call the result. They
    # also:
    #   - byte-scan the resolved routine for an opcode pattern (e.g. the
    #     first CALL E8 in the first 100 bytes) and dereference its
    #     target, to extract a *private*, non-exported kernel routine
    #   - walk back from MmGetSystemRoutineAddress's return value to find
    #     the ntoskrnl PE base
    #   - resolve undocumented routines like PsSuspendProcess /
    #     SeRegisterImageVerificationCallback
    # Speakeasy's stock MmGetSystemRoutineAddress returns either a real
    # apihook trigger (0xfeee00xx) or 0 — neither pattern-scan-able.
    #
    # Plant a synthetic ntoskrnl image page that *looks like* a tiny PE
    # with a few "exported" function bodies, each containing planted CALL
    # E8 sequences pointing to non-zero target addresses. Hook
    # MmGetSystemRoutineAddress to hand out the planted body addresses
    # for the names sophisticated drivers ask for, and hook
    # MmIsAddressValid to return TRUE for any address in our synth
    # region.
    #
    # This is enough to fool byte-pattern scans that just need
    #   (a) a CALL opcode at offset N
    #   (b) MmIsAddressValid(call_target) == TRUE
    # It is NOT enough to fool drivers that walk back from the routine
    # address to the PE base and parse section headers — that takes a
    # full fake PE which is a separate (larger) effort.
    state['fake_ntos_base'] = 0x6f700000
    state['fake_ntos_funcs'] = {}  # name -> address within synth region

    def _install_fake_kernel_routines(emu_obj):
        try:
            from speakeasy.common import PERM_MEM_RWX
        except Exception:
            return
        if state.get('fake_ntos_mapped'):
            return
        # `emu_obj` may be either the WinKernelEmulator (passed by apihook)
        # or an ApiHandler — pick the one with mem_map.
        mm = (getattr(emu_obj, 'mem_map', None) or
              getattr(getattr(emu_obj, 'emu', None), 'mem_map', None))
        mw = (getattr(emu_obj, 'mem_write', None) or
              getattr(getattr(emu_obj, 'emu', None), 'mem_write', None))
        if not mm or not mw:
            return
        try:
            mm(0x10000, base=state['fake_ntos_base'],
               tag='ktrace.fake_ntos', perms=PERM_MEM_RWX)
        except Exception:
            # If the base is taken, try a different one.
            try:
                state['fake_ntos_base'] = 0x6fa00000
                mm(0x10000, base=state['fake_ntos_base'],
                   tag='ktrace.fake_ntos', perms=PERM_MEM_RWX)
            except Exception:
                return
        import struct as _ss
        # Plant a minimal PE32+ image at the start of the synth region so
        # drivers that walk back from MmGetSystemRoutineAddress's return
        # value to find ntoskrnl base (via RtlImageNtHeader) can parse a
        # valid header. Two sections, both writable so byte-pattern
        # function bodies live in .text and ZwQuerySystemInformation's
        # SystemModuleInformation entry can claim the whole 0x10000
        # range.
        #   +0x000 IMAGE_DOS_HEADER (e_magic 'MZ', e_lfanew=0x80)
        #   +0x080 NT signature + IMAGE_FILE_HEADER + IMAGE_OPTIONAL_HEADER64
        #   +0x1F8 IMAGE_SECTION_HEADER × 2  (".text" + ".data")
        #   +0x1000 .text — function bodies
        nt_base = state['fake_ntos_base']
        # DOS header: 64 bytes
        dos = bytearray(0x80)
        dos[0:2] = b'MZ'
        dos[0x3C:0x40] = _ss.pack('<I', 0x80)  # e_lfanew
        # NT signature
        nt_hdr = bytearray()
        nt_hdr += b'PE\x00\x00'
        # IMAGE_FILE_HEADER (20 bytes): Machine, NumberOfSections,
        # TimeDateStamp, PointerToSymbolTable, NumberOfSymbols,
        # SizeOfOptionalHeader, Characteristics
        nt_hdr += _ss.pack('<HHIIIHH',
                           0x8664,    # Machine = AMD64
                           2,         # NumberOfSections
                           0x60000000, 0, 0,    # TimeDate / symtab
                           0xF0,      # SizeOfOptionalHeader (PE32+)
                           0x2022)    # Char: EXECUTABLE_IMAGE + LARGE_ADDR + DRIVER (DLL bit)
        # IMAGE_OPTIONAL_HEADER64 (240 / 0xF0 bytes)
        opt = bytearray()
        opt += _ss.pack('<H', 0x20b)              # Magic (PE32+)
        opt += b'\x0e\x00'                         # MajorLinker / MinorLinker
        opt += _ss.pack('<I', 0x8000)              # SizeOfCode
        opt += _ss.pack('<I', 0x1000)              # SizeOfInitializedData
        opt += _ss.pack('<I', 0)                   # SizeOfUninitializedData
        opt += _ss.pack('<I', 0x1000)              # AddressOfEntryPoint
        opt += _ss.pack('<I', 0x1000)              # BaseOfCode
        opt += _ss.pack('<Q', nt_base)             # ImageBase
        opt += _ss.pack('<I', 0x1000)              # SectionAlignment
        opt += _ss.pack('<I', 0x200)               # FileAlignment
        opt += _ss.pack('<HH', 10, 0)              # OS major/minor
        opt += _ss.pack('<HH', 0, 0)               # Image major/minor
        opt += _ss.pack('<HH', 10, 0)              # SubSys major/minor
        opt += _ss.pack('<I', 0)                   # Win32VersionValue
        opt += _ss.pack('<I', 0x10000)             # SizeOfImage
        opt += _ss.pack('<I', 0x1000)              # SizeOfHeaders
        opt += _ss.pack('<I', 0)                   # CheckSum
        opt += _ss.pack('<H', 1)                   # Subsystem (NATIVE)
        opt += _ss.pack('<H', 0)                   # DllCharacteristics
        opt += _ss.pack('<QQQQ', 0x100000, 0x1000,  # Stack reserve / commit
                        0x100000, 0x1000)           # Heap  reserve / commit
        opt += _ss.pack('<I', 0)                   # LoaderFlags
        opt += _ss.pack('<I', 16)                  # NumberOfRvaAndSizes
        opt += b'\x00' * (16 * 8)                  # Data directories — all 0
        # Section headers (40 bytes each, 2 sections)
        # .text  RVA=0x1000  VirtualSize=0x8000  Char=CODE|EXEC|READ
        # .data  RVA=0xA000  VirtualSize=0x1000  Char=DATA|READ|WRITE
        sec_text = (b'.text\x00\x00\x00' +
                    _ss.pack('<IIIIIIHHI',
                             0x8000,    # VirtualSize
                             0x1000,    # VirtualAddress
                             0x8000,    # SizeOfRawData
                             0x1000,    # PointerToRawData
                             0, 0,      # Relocs / linenums
                             0, 0,      # numreloc / numlinenum
                             0x60000020))  # CODE | EXEC | READ
        sec_data = (b'.data\x00\x00\x00' +
                    _ss.pack('<IIIIIIHHI',
                             0x1000,    # VirtualSize
                             0xA000,    # VirtualAddress
                             0x1000,    # SizeOfRawData
                             0xA000,    # PointerToRawData
                             0, 0,
                             0, 0,
                             0xC0000040))  # INITIALIZED_DATA | READ | WRITE
        try:
            mw(nt_base, bytes(dos))
            mw(nt_base + 0x80, bytes(nt_hdr) + bytes(opt))
            mw(nt_base + 0x80 + 4 + 20 + 0xF0, sec_text + sec_data)
        except Exception:
            pass

        # Plant function bodies inside the .text section (at +0x1000).
        # Each gets a 0x80-byte slot with the byte-pattern from before:
        #   55 48 89 E5 48 83 EC 20   ; 8-byte prologue (no E8/84)
        #   4× { E8 <rel32> ; 7 NOPs }  ; 4 CALL E8 reachable for scans
        #   C3                         ; ret
        #   <NOP pad to 0x80>
        body_size = 0x80
        text_base = nt_base + 0x1000
        for fn_idx, name in enumerate((
                'PsTerminateSystemThread',
                'PsSuspendProcess',
                'SeRegisterImageVerificationCallback',
                'NtOpenFile',
                'NtQuerySystemInformation',
                'KeStackAttachProcess',
                'PspTerminateThreadByPointer',
                'PspTerminateProcess')):
            base = text_base + fn_idx * body_size
            state['fake_ntos_funcs'][name] = base
            blob = bytearray()
            blob += b'\x55\x48\x89\xE5\x48\x83\xEC\x20'  # 8-byte prologue
            for ci in range(4):
                rel = 0x100 * (ci + 1)
                blob += b'\xE8' + _ss.pack('<i', rel)
                blob += b'\x90' * 7
            blob += b'\xC3'
            blob += b'\x90' * (body_size - len(blob))
            try:
                mw(base, bytes(blob))
            except Exception:
                pass
        state['fake_ntos_mapped'] = True

    # Override MmGetSystemRoutineAddress: try Speakeasy's get_proc first
    # (real apihook trigger), then fall back to a synth body in our fake
    # ntoskrnl region for names we have planted bodies for.
    _orig_mga = ntos_mod.Ntoskrnl.__dict__.get('MmGetSystemRoutineAddress')

    def _mm_get_routine_faked(self, emu, argv, ctx={}):
        if not argv:
            return 0
        name_ptr = argv[0]
        try:
            ptr_size = emu.get_ptr_size()
            if ptr_size == 8:
                hdr = bytes(self.mem_read(name_ptr, 16))
                length = _struct.unpack('<H', hdr[0:2])[0]
                buf = _struct.unpack('<Q', hdr[8:16])[0]
            else:
                hdr = bytes(self.mem_read(name_ptr, 8))
                length = _struct.unpack('<H', hdr[0:2])[0]
                buf = _struct.unpack('<I', hdr[4:8])[0]
            if not buf or not length or length > 0x200:
                return 0
            name = bytes(self.mem_read(buf, length)).decode(
                'utf-16-le', errors='replace').rstrip('\x00')
        except Exception:
            return 0
        argv[0] = name  # so the trace shows the routine name
        # Names whose *bytes* the caller will byte-pattern scan must be
        # served from our planted synth body (Speakeasy's get_proc returns
        # a one-byte apihook trigger that has no CALL opcode embedded).
        BYTE_SCAN_TARGETS = {
            'PsTerminateSystemThread', 'PsSuspendProcess', 'NtOpenFile',
            'NtQuerySystemInformation', 'KeStackAttachProcess',
            'PspTerminateThreadByPointer', 'PspTerminateProcess',
            'SeRegisterImageVerificationCallback',
        }
        if name in BYTE_SCAN_TARGETS:
            _install_fake_kernel_routines(emu)
            return state['fake_ntos_funcs'].get(name, state['fake_ntos_base'])
        # For other names, try Speakeasy's real export table first.
        try:
            ea = emu.get_proc('ntoskrnl', name)
            if ea:
                return ea
        except Exception:
            pass
        # Fall back to a planted synth body. Lazily map on first call.
        _install_fake_kernel_routines(self)
        if name not in state['fake_ntos_funcs']:
            # Generic slot — reuse PsTerminateSystemThread's body.
            base = state['fake_ntos_base']
            state['fake_ntos_funcs'][name] = base
            return base
        return state['fake_ntos_funcs'][name]

    def _make_mga(name):
        def _t(self, emu, argv, ctx={}):
            return _mm_get_routine_faked(self, emu, argv, ctx)
        _t.__name__ = name
        return apihook(name, argc=1, conv=conv)(_t)

    setattr(ntos_mod.Ntoskrnl, 'MmGetSystemRoutineAddress',
            _make_mga('MmGetSystemRoutineAddress'))

    # Override MmIsAddressValid to return TRUE for any address in our
    # fake-ntoskrnl synth region (drivers that byte-pattern-resolve a
    # private routine then call MmIsAddressValid on the extracted CALL
    # target — we want that check to pass).
    _orig_mmiav = ntos_mod.Ntoskrnl.__dict__.get('MmIsAddressValid')

    def _mm_is_address_valid_faked(self, emu, argv, ctx={}):
        if not argv:
            return 0
        addr = argv[0]
        base = state.get('fake_ntos_base', 0)
        if base and base <= addr < base + 0x10000:
            return 1
        # Speakeasy's fake region for apihook triggers (0xfeed* / 0xfeee*)
        if 0xfeedf000 <= addr <= 0xfeee3000:
            return 1
        if _orig_mmiav is not None:
            try:
                return _orig_mmiav(self, emu, argv, ctx)
            except Exception:
                pass
        # Default: be permissive — drivers often query it after a
        # pointer-from-byte-scan, and a non-zero check is usually safer
        # than zero for trace progression.
        return 1

    def _make_mmiav(name):
        def _t(self, emu, argv, ctx={}):
            return _mm_is_address_valid_faked(self, emu, argv, ctx)
        _t.__name__ = name
        return apihook(name, argc=1, conv=conv)(_t)

    setattr(ntos_mod.Ntoskrnl, 'MmIsAddressValid',
            _make_mmiav('MmIsAddressValid'))

    # ---- Time helpers. Speakeasy ships these but the impls are broken:
    # ExSystemTimeToLocalTime doesn't adjust for the local timezone
    # offset (just copies bytes), and RtlTimeToTimeFields reads the
    # source pointer but NEVER WRITES the TIME_FIELDS output — so any
    # driver that builds a `%04d-%02d-%02d %02d:%02d:%02d` timestamp
    # ends up logging `0000-00-00 00:00:00` (d3 FileProtect.log, d14
    # event reporter, etc.). Replace both with real impls.
    import time as _t, struct as _struct_t

    def _ex_system_time_to_local_time(self, emu, argv, ctx={}):
        if len(argv) < 2 or not argv[0] or not argv[1]:
            return 0
        try:
            sys_b = bytes(self.mem_read(argv[0], 8))
            sys_ft = int.from_bytes(sys_b, 'little')
        except Exception:
            return 0
        # Bias = local-tz offset in 100-ns intervals. Python's
        # time.timezone is seconds west of UTC; negate so EST → +5h
        # becomes a positive add to UTC FILETIME for local-east, etc.
        try:
            bias_secs = -_t.timezone
            if _t.daylight and _t.localtime().tm_isdst:
                bias_secs = -_t.altzone
            local_ft = (sys_ft + bias_secs * 10_000_000) & ((1 << 64) - 1)
        except Exception:
            local_ft = sys_ft
        try:
            self.mem_write(argv[1], local_ft.to_bytes(8, 'little'))
        except Exception:
            pass
        return 0

    def _rtl_time_to_time_fields(self, emu, argv, ctx={}):
        # TIME_FIELDS = { CSHORT Year, Month, Day, Hour, Minute, Second,
        #                 Milliseconds, Weekday; }  (16 bytes)
        if len(argv) < 2 or not argv[0] or not argv[1]:
            return 0
        try:
            ft = int.from_bytes(bytes(self.mem_read(argv[0], 8)), 'little')
        except Exception:
            return 0
        # FILETIME → unix seconds.
        try:
            unix_s = ft / 10_000_000 - 11644473600
            ms = int((ft // 10_000) % 1000)
            tm = _t.gmtime(unix_s) if unix_s > 0 else _t.gmtime(0)
            tf = _struct_t.pack(
                '<hhhhhhhh',
                tm.tm_year, tm.tm_mon, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec,
                ms, tm.tm_wday)
            self.mem_write(argv[1], tf)
        except Exception:
            pass
        return 0

    setattr(ntos_mod.Ntoskrnl, 'ExSystemTimeToLocalTime',
            apihook('ExSystemTimeToLocalTime', argc=2,
                    conv=conv)(_ex_system_time_to_local_time))
    setattr(ntos_mod.Ntoskrnl, 'RtlTimeToTimeFields',
            apihook('RtlTimeToTimeFields', argc=2,
                    conv=conv)(_rtl_time_to_time_fields))

    # ---- Inject fake-ntoskrnl as a module entry in
    # ZwQuerySystemInformation(SystemModuleInformation). Drivers that
    # resolve a routine via MmGetSystemRoutineAddress then walk the
    # SystemModuleInformation list to find which module contains the
    # address (= ntoskrnl base) — d14's FUN_140001090 is the canonical
    # case. Without our region in the list the walk returns 0 and
    # downstream PE-section-walk byte-pattern scanning never runs.
    # We append a synthetic SYSTEM_MODULE entry with base=fake_ntos_base
    # size=0x10000 after Speakeasy's stock list.
    _orig_zqsi = ntos_mod.Ntoskrnl.__dict__.get('ZwQuerySystemInformation')

    def _zw_query_systeminfo_wrapped(self, emu, argv, ctx={}):
        # Class 11 = SystemModuleInformation. Other classes pass through.
        SystemModuleInformation = 11
        if len(argv) < 4 or argv[0] != SystemModuleInformation:
            if _orig_zqsi is not None:
                return _orig_zqsi(self, emu, argv, ctx)
            return 0xC0000004  # STATUS_INFO_LENGTH_MISMATCH
        # Synth SYSTEM_MODULE for x64 (struct size = 0x128 / 296 bytes):
        #   PVOID Reserved[2]                  16
        #   PVOID Base                          8
        #   ULONG Size                          4
        #   ULONG Flags                         4
        #   USHORT Index, Unknown, LoadCount, ModuleNameOffset   8
        #   CHAR ImageName[256]               256
        # Total 296.
        # x86 size is smaller (216) but d14 + most modern rogue drivers
        # are x64; fall back to original on x86.
        import struct as _ss
        ptr_size = emu.get_ptr_size()
        if ptr_size != 8:
            if _orig_zqsi is not None:
                return _orig_zqsi(self, emu, argv, ctx)
            return 0xC0000004
        if _orig_zqsi is None:
            return 0xC0000002  # STATUS_NOT_IMPLEMENTED
        # Delegate to original to fill in real modules + size.
        rv = _orig_zqsi(self, emu, argv, ctx)
        if rv != 0:
            # Original couldn't fit, or there was an error. Read back
            # the returned-length to adjust.
            return rv
        sysinfo, syslen, retlen = argv[1], argv[2], argv[3]
        if not sysinfo or not retlen:
            return rv
        try:
            # Read the existing count + adjust to count+1.
            cur_total = int.from_bytes(
                bytes(self.mem_read(retlen, 4)), 'little')
            mod_count = int.from_bytes(
                bytes(self.mem_read(sysinfo, 8)), 'little')
            new_total = cur_total + 296
            if new_total > syslen:
                # No room — return STATUS_INFO_LENGTH_MISMATCH and set
                # retlen to the bigger size so the caller retries.
                self.mem_write(retlen, new_total.to_bytes(4, 'little'))
                return 0xC0000004
            # Bump mod_count and write.
            self.mem_write(
                sysinfo, (mod_count + 1).to_bytes(8, 'little'))
            # Append our synth entry right after the existing list.
            entry_off = sysinfo + cur_total
            entry = bytearray(296)
            entry[0x10:0x18] = _ss.pack(
                '<Q', state['fake_ntos_base'])  # Base
            entry[0x18:0x1C] = _ss.pack('<I', 0x10000)  # Size
            entry[0x1C:0x20] = _ss.pack('<I', 0)        # Flags
            entry[0x20:0x22] = _ss.pack('<H', mod_count)   # Index
            entry[0x22:0x24] = _ss.pack('<H', 0)           # Unknown
            entry[0x24:0x26] = _ss.pack('<H', 1)           # LoadCount
            name = b'\\SystemRoot\\system32\\ntoskrnl.exe'
            entry[0x26:0x28] = _ss.pack(
                '<H', name.rfind(b'\\') + 1)  # ModuleNameOffset
            entry[0x28:0x28 + len(name)] = name
            self.mem_write(entry_off, bytes(entry))
            self.mem_write(
                retlen, new_total.to_bytes(4, 'little'))
        except Exception:
            pass
        return rv

    def _make_zqsi(name):
        def _t(self, emu, argv, ctx={}):
            return _zw_query_systeminfo_wrapped(self, emu, argv, ctx)
        _t.__name__ = name
        return apihook(name, argc=4, conv=conv)(_t)
    for _nm in ('ZwQuerySystemInformation', 'NtQuerySystemInformation'):
        setattr(ntos_mod.Ntoskrnl, _nm, _make_zqsi(_nm))

    # ---- RTL_GENERIC_TABLE / RTL_AVL_TABLE proper-init stubs.
    # File-protection / DRM / anti-cheat drivers use these to hold
    # per-PID or per-filename ACL trees. A zero-init stub causes the
    # next Insert call to dereference a NULL comparator -> infinite
    # hang (JKDriver / PDFProtect is the canonical example).
    #
    # Proper layout (x64 RTL_GENERIC_TABLE = 0x48 bytes):
    #   +0x00 TableRoot           +0x28 CompareRoutine
    #   +0x08 InsertOrderList     +0x30 AllocateRoutine
    #   +0x18 OrderedPointer      +0x38 FreeRoutine
    #   +0x20 WhichOrderedElement +0x40 TableContext
    #   +0x24 NumberOfElements
    import struct as _s_gt

    def _rtl_init_table(self, emu, argv, ctx={}):
        if len(argv) < 5 or not argv[0]:
            return 0
        blob = bytearray(0x48)
        _s_gt.pack_into('<Q', blob, 0x28, argv[1] or 0)  # Compare
        _s_gt.pack_into('<Q', blob, 0x30, argv[2] or 0)  # Allocate
        _s_gt.pack_into('<Q', blob, 0x38, argv[3] or 0)  # Free
        _s_gt.pack_into('<Q', blob, 0x40, argv[4] or 0)  # Context
        try:
            self.mem_write(argv[0], bytes(blob))
        except Exception:
            pass
        return 0

    def _rtl_insert_table(self, emu, argv, ctx={}):
        # Return NULL (insert failed / already exists). Set NewElement
        # = FALSE if the caller passed an OUT pointer.
        if len(argv) > 3 and argv[3]:
            try:
                self.mem_write(argv[3], b'\x00')
            except Exception:
                pass
        return 0

    def _rtl_lookup_table(self, emu, argv, ctx={}):
        return 0

    def _rtl_enumerate_table(self, emu, argv, ctx={}):
        return 0

    def _rtl_count_table(self, emu, argv, ctx={}):
        return 0

    def _rtl_is_empty(self, emu, argv, ctx={}):
        return 1  # TRUE

    def _rtl_delete_table(self, emu, argv, ctx={}):
        return 1  # success

    _gt_specs = (
        ('RtlInitializeGenericTable', _rtl_init_table, 5),
        ('RtlInitializeGenericTableAvl', _rtl_init_table, 5),
        ('RtlInsertElementGenericTable', _rtl_insert_table, 4),
        ('RtlInsertElementGenericTableAvl', _rtl_insert_table, 4),
        ('RtlLookupElementGenericTable', _rtl_lookup_table, 2),
        ('RtlLookupElementGenericTableAvl', _rtl_lookup_table, 2),
        ('RtlEnumerateGenericTable', _rtl_enumerate_table, 2),
        ('RtlEnumerateGenericTableAvl', _rtl_enumerate_table, 2),
        ('RtlEnumerateGenericTableWithoutSplaying', _rtl_enumerate_table, 2),
        ('RtlNumberGenericTableElements', _rtl_count_table, 1),
        ('RtlNumberGenericTableElementsAvl', _rtl_count_table, 1),
        ('RtlIsGenericTableEmpty', _rtl_is_empty, 1),
        ('RtlIsGenericTableEmptyAvl', _rtl_is_empty, 1),
        ('RtlDeleteElementGenericTable', _rtl_delete_table, 2),
        ('RtlDeleteElementGenericTableAvl', _rtl_delete_table, 2),
    )

    def _make_gt(impl, name, argc):
        def _t(self, emu, argv, ctx={}):
            return impl(self, emu, argv, ctx)
        _t.__name__ = name
        return apihook(name, argc=argc, conv=conv)(_t)

    for _nm, _impl, _ac in _gt_specs:
        if not hasattr(ntos_mod.Ntoskrnl, _nm):
            setattr(ntos_mod.Ntoskrnl, _nm, _make_gt(_impl, _nm, _ac))

    # Export sort patch
    def patched_generate_export_table(self, modname):
        if not modname: return
        modname = modname.lower()
        mod_handler = self.api.load_api_handler(modname)
        if not mod_handler: return None
        from speakeasy.windows.common import JitPeFile, DecoyModule
        jit = JitPeFile(self.get_arch())
        funcs = [(f[4], f[0]) for k, f in mod_handler.funcs.items() if isinstance(k, str)]
        data_exports = [k for k, d in mod_handler.data.items() if isinstance(k, str)]
        new = funcs.copy()
        if modname == 'ntdll':
            nt = self.api.load_api_handler('ntoskrnl')
            funcs = [(f[4], f[0]) for k, f in nt.funcs.items() if isinstance(k, str)]
            funcs = new + funcs; new = funcs.copy()
        if modname in ('ntdll', 'ntoskrnl'):
            for o, fn in funcs:
                if fn.startswith('Nt'): new.append((None, 'Zw'+fn[2:]))
                elif fn.startswith('Zw'): new.append((None, 'Nt'+fn[2:]))
        else:
            for o, fn in funcs:
                new.append((None, fn+'A')); new.append((None, fn+'W'))
        func_names = [fn for _, fn in new]
        all_names = sorted(set(func_names + data_exports))
        img = jit.get_decoy_pe_image(modname, all_names)
        return DecoyModule(data=img, is_jitted=True)
    for cls in WinKernelEmulator.__mro__:
        if 'generate_export_table' in vars(cls):
            cls.generate_export_table = patched_generate_export_table; break

