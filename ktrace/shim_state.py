"""Run-scoped behaviour toggles + preset module/process lists, plus the
stack-shadow utility. Imported by shim.py; the EMU_OPTS dict is module-
level so closures capturing it see the live mutations from ktrace.py."""
EMU_OPTS = {
    'force_strstr_match': False,
    'fake_modules': [],  # list of driver path strings to inject into
                         # NtQuerySystemInformation(SystemModuleInformation)
    'fake_processes': [],  # list of (pid, image_name) for ZwQueryInformationProcess /
                           # PsGetProcessImageFileName / NtQuerySystemInformation(SystemProcessInformation)
    'fake_drivers': [],  # list of NT names ('\\driver\\nsiproxy') for which
                         # ObReferenceObjectByName returns a synthetic
                         # DRIVER_OBJECT. Implementation lives in
                         # shim_fake_driver.py.
    'current_pid_override': None,  # set by invoke_callbacks to make
                                   # PsGetCurrentProcessId return this PID
    'previous_mode_override': None,  # set by invoke_callbacks to make
                                     # ExGetPreviousMode return UserMode (1)
                                     # while we simulate a user-mode-triggered
                                     # callback; many drivers' callback bodies
                                     # short-circuit unless PreviousMode != 0.
    'pid_lookup_ceiling': 0x2000,    # cap for PsLookupProcessByProcessId
                                     # synthetic-eproc fallback. Drivers
                                     # that walk PID space without a
                                     # termination condition (Chinese AV
                                     # killers, PDF-DRM minifilters, etc.)
                                     # otherwise spin until the watchdog
                                     # fires. Set to 0 to disable cap.
                                     # User-supplied --fake-processes
                                     # entries above the ceiling still
                                     # succeed (matched before the cap).
    'canned_tdi_response': None,     # bytes served to TDI reads (ZwReadFile
                                     # on \Device\Tcp/Udp/RawIp handles, and
                                     # TDI_RECEIVE IRPs). Set by
                                     # --fake-tdi-response. None = use the
                                     # built-in stub HTTP / DNS responses.
}


def set_current_pid_override(pid):
    EMU_OPTS['current_pid_override'] = pid


def set_previous_mode_override(mode):
    """1 = UserMode, 0 = KernelMode, None = pass through to default (0)."""
    EMU_OPTS['previous_mode_override'] = mode


# Curated lists keyed by preset name. ktrace.py expands a `--fake-modules
# av,defender,custom.sys` arg into the union of presets + raw names.
FAKE_MODULE_PRESETS = {
    'av': [
        # Kaspersky
        r'\SystemRoot\system32\drivers\klif.sys',
        r'\SystemRoot\system32\drivers\klhk.sys',
        r'\SystemRoot\system32\drivers\kltdi.sys',
        # Symantec / Norton
        r'\SystemRoot\system32\drivers\SymEFA.sys',
        r'\SystemRoot\system32\drivers\SRTSP.sys',
        # McAfee
        r'\SystemRoot\system32\drivers\mfehidk.sys',
        r'\SystemRoot\system32\drivers\mfemms.sys',
        # Trend Micro
        r'\SystemRoot\system32\drivers\tmcomm.sys',
        r'\SystemRoot\system32\drivers\tmebc64.sys',
        # ESET
        r'\SystemRoot\system32\drivers\eamonm.sys',
        r'\SystemRoot\system32\drivers\edevmon.sys',
        r'\SystemRoot\system32\drivers\ehdrv.sys',
        # Avast / AVG
        r'\SystemRoot\system32\drivers\aswSP.sys',
        r'\SystemRoot\system32\drivers\aswSnx.sys',
        r'\SystemRoot\system32\drivers\aswMonFlt.sys',
        # Bitdefender
        r'\SystemRoot\system32\drivers\bdfwfpf.sys',
        r'\SystemRoot\system32\drivers\bdsandbox.sys',
        # Sophos
        r'\SystemRoot\system32\drivers\sophosfilter.sys',
        # F-Secure
        r'\SystemRoot\system32\drivers\fsdfw.sys',
        # CrowdStrike
        r'\SystemRoot\system32\drivers\CSAgent.sys',
        r'\SystemRoot\system32\drivers\csboot.sys',
        # SentinelOne
        r'\SystemRoot\system32\drivers\SentinelMonitor.sys',
        # Carbon Black
        r'\SystemRoot\system32\drivers\carbonblackk.sys',
    ],
    'defender': [
        r'\SystemRoot\system32\drivers\wd\WdFilter.sys',
        r'\SystemRoot\system32\drivers\wd\WdNisDrv.sys',
        r'\SystemRoot\system32\drivers\wd\WdBoot.sys',
        r'\SystemRoot\system32\drivers\mssecflt.sys',
        r'\SystemRoot\system32\drivers\SgrmAgent.sys',
    ],
    'sysmon': [
        r'\SystemRoot\system32\drivers\Sysmon64.sys',
        r'\SystemRoot\system32\drivers\SysmonDrv.sys',
    ],
    'common': [
        r'\SystemRoot\system32\ntoskrnl.exe',
        r'\SystemRoot\system32\hal.dll',
        r'\SystemRoot\system32\drivers\tcpip.sys',
        r'\SystemRoot\system32\drivers\ndis.sys',
        r'\SystemRoot\system32\drivers\fltmgr.sys',
        r'\SystemRoot\system32\drivers\Wdf01000.sys',
        r'\SystemRoot\system32\drivers\Ntfs.sys',
        r'\SystemRoot\system32\drivers\afd.sys',
        r'\SystemRoot\system32\drivers\netio.sys',
        r'\SystemRoot\system32\drivers\fwpkclnt.sys',
    ],
}


# Parallel presets for --fake-processes. Each entry maps preset name
# to a list of (pid, image-name) tuples. PIDs start at 0x1000+ so they
# don't collide with Speakeasy's tracked processes.
FAKE_PROCESS_PRESETS = {
    'av': [
        (0x1004, 'MsMpEng.exe'),       (0x1008, 'mssecess.exe'),
        (0x100c, 'avp.exe'),           (0x1010, 'Mcshield.exe'),
        (0x1014, '360sd.exe'),         (0x1018, '360tray.exe'),
        (0x101c, '360rp.exe'),         (0x1020, 'zhudongfangyu.exe'),
        (0x1024, 'hipsmain.exe'),      (0x1028, 'hipstray.exe'),
        (0x102c, 'kxetray.exe'),       (0x1030, 'ksafe.exe'),
        (0x1034, 'RavMonD.exe'),       (0x1038, 'KvMonXP.exe'),
        (0x103c, 'QQPCTray.exe'),      (0x1040, 'QQPCRTP.exe'),
        (0x1044, 'NisSrv.exe'),        (0x1048, 'MSASCui.exe'),
        (0x104c, 'ekrn.exe'),          (0x1050, 'SAVAdminService.exe'),
        (0x1054, 'CSFalconService.exe'),  (0x1058, 'CSAgent.exe'),
        (0x105c, 'SentinelAgent.exe'), (0x1060, 'cbservice.exe'),
        (0x1064, 'bdservicehost.exe'), (0x1068, 'avastsvc.exe'),
    ],
    'common': [
        (0x100, 'System'),     (0x200, 'csrss.exe'),
        (0x300, 'wininit.exe'), (0x400, 'services.exe'),
        (0x500, 'lsass.exe'),  (0x600, 'svchost.exe'),
        (0x700, 'explorer.exe'),(0x800, 'winlogon.exe'),
    ],
}


def set_force_strstr_match(v: bool):
    EMU_OPTS['force_strstr_match'] = bool(v)


def map_stack_shadow(emu, extra_above=0x1000, extra_below=0x10000):
    """Extend Speakeasy's stack region so deep call chains don't fault.

    Two issues addressed:
    (1) Spill-to-caller-home writes (`mov [rsp+0x30], rcx`) at function
        entry land just *above* stack_base — Speakeasy reserves but
        doesn't map there.
    (2) Deeper drivers (e.g. system-thread routines with large local
        frames + nested calls) consume more than the default 1-page
        commit, growing the stack *below* the mapped region.

    Speakeasy's mem_map silently relocates when the requested base
    overlaps a reserved range, so we drop to the underlying engine.
    """
    try:
        sb = getattr(emu.emu, 'stack_base', 0)
    except Exception:
        sb = 0
    if not sb:
        return False
    ok_above = ok_below = False
    try:
        # One page directly above stack_base for register spills.
        emu.emu.emu_eng.mem_map(sb, extra_above)
        ok_above = True
    except Exception:
        pass
    try:
        # Pre-commit additional pages below the existing stack mapping
        # (Speakeasy reserved 0x40000 by default, only committed 1 page).
        # Map page by page to avoid hitting already-mapped pages.
        page = 0x1000
        # The original stack page is at sb - page .. sb. We want to
        # extend below that, so start at sb - 2*page and go down.
        for off in range(2, 2 + extra_below // page):
            addr = sb - off * page
            if addr <= 0x1000:
                break
            try:
                emu.emu.emu_eng.mem_map(addr, page)
                ok_below = True
            except Exception:
                # Already mapped or other error — keep going.
                pass
    except Exception:
        pass
    return ok_above or ok_below


def set_fake_processes(presets_or_names):
    """Expand preset names + raw `pid:name` pairs into the EMU_OPTS list.

    Accepts comma-separated string OR list of strings. Forms:
      - 'av'           → expand FAKE_PROCESS_PRESETS['av']
      - 'all'          → union of all presets
      - 'pid:name'     → raw tuple
      - 'name'         → auto-assign next pid
    """
    if isinstance(presets_or_names, str):
        items = [s.strip() for s in presets_or_names.split(',') if s.strip()]
    else:
        items = list(presets_or_names or [])
    out = []
    next_pid = 0x2000
    for it in items:
        if it in FAKE_PROCESS_PRESETS:
            out.extend(FAKE_PROCESS_PRESETS[it])
        elif it == 'all':
            for v in FAKE_PROCESS_PRESETS.values():
                out.extend(v)
        elif ':' in it:
            pid_s, name = it.split(':', 1)
            try:
                out.append((int(pid_s, 0), name))
            except ValueError:
                out.append((next_pid, it))
                next_pid += 4
        else:
            out.append((next_pid, it))
            next_pid += 4
    # De-dup by pid (keep first)
    seen = set()
    uniq = []
    for pid, name in out:
        if pid in seen:
            continue
        seen.add(pid)
        uniq.append((pid, name))
    EMU_OPTS['fake_processes'] = uniq


def set_fake_modules(presets_or_names):
    """Expand preset names + raw driver paths into the EMU_OPTS list.
    Accepts a comma-separated string OR a list."""
    if isinstance(presets_or_names, str):
        items = [s.strip() for s in presets_or_names.split(',') if s.strip()]
    else:
        items = list(presets_or_names or [])
    out = []
    for it in items:
        if it in FAKE_MODULE_PRESETS:
            out.extend(FAKE_MODULE_PRESETS[it])
        elif it == 'all':
            for v in FAKE_MODULE_PRESETS.values():
                out.extend(v)
        else:
            # Treat as a driver name/path. Prepend driver dir if it
            # looks like a bare filename.
            if '\\' not in it and '/' not in it:
                it = r'\SystemRoot\system32\drivers\\' + it
            out.append(it)
    # De-duplicate, preserve order.
    seen = set()
    uniq = []
    for s in out:
        if s in seen:
            continue
        seen.add(s)
        uniq.append(s)
    EMU_OPTS['fake_modules'] = uniq

