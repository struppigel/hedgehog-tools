"""Per-driver profiles, keyed by SHA-256.

A profile encodes sample-specific quirks the generic tracer cannot
auto-detect: VMProtect chain target redirects, IAT-slot trampolines,
MDL self-alias mirrors, known function symbols, default IOCTLs.

Profiles may also declare fake-driver hooks for samples that hook
foreign DRIVER_OBJECTs via ObReferenceObjectByName. Two fields:

  'fake_drivers':      list of NT object names to pre-allocate
                       (e.g. ['\\Driver\\nsiproxy']). At runtime
                       ObReferenceObjectByName returns the synthetic
                       DRIVER_OBJECT for these names and ktrace logs
                       any hook the sample installs at +0xE0.

  'fake_driver_irps':  list of dicts describing IRPs to fire through
                       the hooked dispatcher after the IOCTL phase.
                       Each entry:
                          {'name': '\\Driver\\nsiproxy',
                           'ioctl': 0x12001B,
                           'outlen': 0x70,
                           'input_builder': 'nsi_tcp_keys',  ← key in INPUT_BUILDERS
                           'input_args': {...}}

Adding a new profile is pure data — no code changes needed (assuming
the buffer shape it needs already has a builder in INPUT_BUILDERS).
Adding a new buffer shape = one new function in this file.
"""
from __future__ import annotations
import hashlib
import struct
from pathlib import Path

PROFILES = {
    # ---- PoisonX (x64, nsiproxy MajorFunction[] hook → TCP-conn hider) ----
    'db5d284b9a9c02f76030ba89fd85c7c8f830f8fe4195cdc1f9cddf15f127125d': {
        'name': 'poisonx',
        'description': 'PoisonX rootkit (\\Driver\\nsiproxy hook hiding '
                       'TCP connections by port)',
        # Trigger install_irp_hook() by adding port 4444 to the
        # blocklist. atoi() reads ASCII; the value compared against is
        # network-byte-order, so we feed htons(4444) = 0x5C11 = 23569
        # as the decimal string the malware will atoi.
        'default_ioctls': [0x22E008, 0x22E010],
        # Both IOCTLs atoi() their input; we feed htons(4444) = 0x5C11
        # = 23569 so the blocklist matches the entry the fake-driver
        # IRP below installs. IOCTL 0x22E010 will treat the same
        # value as a target PID and ZwOpenProcess against a fake
        # process — that path gets traced as a bonus.
        'default_ioctl_input': b'23569\x00',
        # The sample hooks \Driver\nsiproxy's MajorFunction[+0xE0].
        # ktrace pre-allocates a synthetic DRIVER_OBJECT under this name.
        'fake_drivers': ['\\Driver\\nsiproxy'],
        # After IOCTL phase fires, drive a synthetic IOCTL_NSI_GETALLPARAM
        # through the hooked dispatcher to exercise the PID-scrub branch.
        'fake_driver_irps': [
            {
                'name': '\\Driver\\nsiproxy',
                'ioctl': 0x12001B,        # IOCTL_NSI_GETALLPARAM
                'outlen': 0x70,           # PoisonX's length gate
                'input_builder': 'nsi_tcp_keys',
                'input_args': {
                    'entries': [
                        (4444, 0),         # local 4444 → should be SCRUBBED
                        (80, 0),           # local 80   → should be preserved
                    ],
                },
            },
        ],
        'symbols': {
            0x140001000: 'completion_routine_hide_pid',
            0x140001170: 'hooked_device_control',
            0x14000121c: 'install_irp_hook',
            0x14000132c: 'ioctl_add_pid_to_blocklist',
            0x1400013f8: 'xor_decrypt_string',
            0x140001430: 'DriverEntry',
            0x140001620: 'driver_unload',
            0x140001750: 'dispatch_not_supported',
            0x140001760: 'dispatch_device_control',
            0x1400017d4: 'kill_process_by_pid',
            0x140001860: 'ioctl_kill_process',
        },
    },

    # ---- r2 / bat_driver.sys (x86, WHCP-signed Chinese rogue driver) ----
    '5643e118fcc224894dbd68c8a6984548cd38f620c84458cacab92d1d3f2a1dd0': {
        'name': 'r2',
        'description': 'r2 / bat_driver.sys (VMProtect, WHCP-signed)',
        'chain_targets': {
            0x64ae89d4: ('ntoskrnl', 'ExAllocatePoolWithTag'),
            0x497073f4: ('ntoskrnl', 'ExFreePoolWithTag'),
            0x5511e75d: ('ntoskrnl', 'IofCompleteRequest'),
            0x640965d6: ('ntoskrnl', 'ExAllocatePool'),
            0x731a8081: ('ntoskrnl', 'IoCreateDevice'),
            0x1634978e: ('ntoskrnl', 'memset'),
            0x7f233428: ('ntoskrnl', 'ExAllocatePoolWithTag'),
            0x7b49484d: ('ntoskrnl', 'ExAllocatePoolWithTag'),
            0x353b379f: ('ntoskrnl', 'ExAllocatePoolWithTag'),
            0x62322c23: ('ntoskrnl', 'ExAllocatePoolWithTag'),
            0x3ed64679: ('ntoskrnl', 'ExAllocatePoolWithTag'),
            0x19151cbb: ('ntoskrnl', 'ExAllocatePoolWithTag'),
            0x321855fe: ('ntoskrnl', 'ExAllocatePoolWithTag'),
            0x566d4f18: ('ntoskrnl', 'ExAllocatePoolWithTag'),
            0x760f1c0d: ('ntoskrnl', 'ExAllocatePoolWithTag'),
            0x2fe14da7: ('ntoskrnl', 'ExAllocatePoolWithTag'),
            0x32ff2cae: ('ntoskrnl', 'ExAllocatePoolWithTag'),
            0x4fd553d3: ('ntoskrnl', 'ExAllocatePoolWithTag'),
            0x2584271f: ('ntoskrnl', 'ExAllocatePoolWithTag'),
            0x50d97414: ('ntoskrnl', 'ExAllocatePoolWithTag'),
            0x2c457c21: ('ntoskrnl', 'ExAllocatePoolWithTag'),
            0x4cca6cde: ('ntoskrnl', 'memcpy'),
        },
        'slot_base': 0x558000,
        # The trampoline JMP destinations (0xfeedf00c..0x48) are stale apihook
        # trigger addresses from an older Speakeasy build. Even so, planting
        # them is necessary because the synthetic ntoskrnl-grow region they
        # live in is what the driver's resolver uses as scratch space. The
        # driver overwrites the slot table at runtime with real triggers
        # before issuing the calls, so the stale targets don't actually fire.
        'slot_trampolines': {
            0:  (0xfeedf00c, 'nt'),  2:  (0xfeedf010, 'hal'),
            4:  (0xfeedf014, 'nt'),  5:  (0xfeedf018, 'nt'),
            6:  (0xfeedf01c, 'nt'),  7:  (0xfeedf020, 'nt'),
            8:  (0xfeedf024, 'nt'),  9:  (0xfeedf028, 'nt'),
            10: (0xfeedf02c, 'nt'),  11: (0xfeedf030, 'nt'),
            12: (0xfeedf034, 'nt'),  13: (0xfeedf038, 'nt'),
            14: (0xfeedf03c, 'nt'),  15: (0xfeedf040, 'nt'),
            16: (0xfeedf044, 'nt'),  18: (0xfeedf048, 'hal'),
        },
        'mdl_alias': {
            'alias_lo': 0xcc000,
            'alias_hi': 0xcc000 + 0xd0000,
            'orig_lo':  0x400000,
        },
        'dump_sections': [('DRIVER0', 0x407000, 0x5b4000)],
        'default_ioctls': [0x224C00, 0x224C04],
        'symbols': {
            0x00401000: 'FUN_00401000_scxa_alloc',
            0x00401042: 'FUN_00401042_scxa_free',
            0x0040105c: 'FUN_0040105c_irp_done',
            0x00401078: 'FUN_00401078_version_ioctl',
            0x004010d4: 'FUN_004010d4_des_key_schedule',
            0x0040131c: 'FUN_0040131c_des_round',
            0x00401706: 'FUN_00401706_md5_init',
            0x00401734: 'FUN_00401734_md5_final',
            0x004017c6: 'FUN_004017c6_md5_transform',
            0x0040221a: 'FUN_0040221a_des_decrypt',
            0x00402338: 'FUN_00402338_des_setup',
            0x00402656: 'FUN_00402656_devname',
            0x00402760: 'FUN_00402760_iocreate',
            0x00402c52: 'FUN_00402c52_plugin_seed',
            0x00402e5e: 'FUN_00402e5e_rng',
            0x00402eb0: 'FUN_00402eb0_random_digits',
            0x00402f16: 'FUN_00402f16_rktn_alloc',
            0x004030cc: 'FUN_004030cc_rng_step',
            0x004030f0: 'FUN_004030f0_alldvrm_wrapper',
            0x004032b9: 'FUN_004032b9_memcpy_wrap',
            0x004032e2: 'FUN_004032e2_memset_wrap',
            0x00403474: 'FUN_00403474_ProcessPlugin',
        },
    },
}


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 16), b''):
            h.update(chunk)
    return h.hexdigest()


def resolve(sample_path, explicit_name=None):
    """Return (name, profile_dict) or (None, {})."""
    if explicit_name:
        for sha, p in PROFILES.items():
            if p.get('name') == explicit_name:
                return explicit_name, p
        return None, {}
    sha = sha256_of(sample_path)
    if sha in PROFILES:
        p = PROFILES[sha]
        return p.get('name', sha[:12]), p
    return None, {}


# ---------------------------------------------------------------------------
# Input builders for profile-driven fake-driver IRPs.
#
# Each builder takes (emu, arch_bits, args) where args is the profile's
# 'input_args' dict, and returns:
#
#     (input_bytes, dump_regions)
#
# where input_bytes goes into the IRP's InputBufferLength + SystemBuffer
# (via ktrace's existing synth_irp path), and dump_regions is a list of
# (label, addr, length) tuples that ktrace will read + log AFTER the
# captured completion routine runs. Used to show out-of-band buffers
# (e.g. an entries array that the response header pointed at).
# ---------------------------------------------------------------------------


def build_nsi_tcp_keys(emu, arch_bits, args):
    """Build the response shape PoisonX-class nsiproxy rootkits expect
    for IOCTL_NSI_GETALLPARAM on the TCP connection table.

    Layout:
      Response header (0x70 bytes):
        +0x28  PVOID    entries pointer
        +0x30  SIZE_T   stride = 0x38
        +0x68  ULONG    entry count

      Each entry (0x38 bytes) = two SOCKADDR_INET halves:
        Local  at +0x00:  family @ +0x00, sin_port @ +0x02 (network order)
        Remote at +0x1C:  family @ +0x1C, sin_port @ +0x1E (network order)

    args:
      entries: list of (local_port, remote_port) tuples in host byte
               order. Builder htons them into the network-order port
               slots the sample compares against.
    """
    AF_INET6 = 0x17
    entries = args.get('entries') or []

    ent_bytes = bytearray()
    for lport, rport in entries:
        e = bytearray(0x38)
        struct.pack_into('<H', e, 0x00, AF_INET6)
        struct.pack_into('>H', e, 0x02, lport & 0xFFFF)
        struct.pack_into('<H', e, 0x1C, AF_INET6)
        struct.pack_into('>H', e, 0x1E, rport & 0xFFFF)
        ent_bytes += e

    entries_addr = 0
    if ent_bytes:
        entries_addr = emu.emu.mem_map(
            max(0x100, len(ent_bytes) + 0x10),
            base=None,
            tag='ktrace.profile.nsi_entries',
            perms=7)
        emu.mem_write(entries_addr, bytes(ent_bytes))

    hdr = bytearray(0x70)
    struct.pack_into('<Q', hdr, 0x28, entries_addr)
    struct.pack_into('<Q', hdr, 0x30, 0x38)
    struct.pack_into('<I', hdr, 0x68, len(entries))

    dump_regions = []
    if entries_addr and ent_bytes:
        dump_regions.append((
            'NSI TCP-key entries',
            entries_addr,
            len(ent_bytes),
            # Optional formatter that ktrace will call with the
            # post-completion bytes; we render each entry as
            # local/remote ports + a SCRUBBED/preserved tag so the
            # per-entry effect of completion_routine_hide_pid is
            # readable at a glance.
            format_nsi_tcp_keys_dump,
        ))

    return bytes(hdr), dump_regions


def format_nsi_tcp_keys_dump(log_fn, label, addr, post_bytes):
    """Pretty-print the entries buffer after the completion routine
    has run. Each 0x38-byte entry: extract ports, flag SCRUBBED if
    fully zeroed."""
    log_fn(f"  Post-CompletionRoutine {label} ({len(post_bytes)}B):")
    for i in range(0, len(post_bytes), 0x38):
        e = post_bytes[i:i+0x38]
        if len(e) < 0x38:
            break
        scrubbed = (e == b'\x00' * 0x38)
        lp = int.from_bytes(e[2:4], 'big')
        rp = int.from_bytes(e[0x1e:0x20], 'big')
        tag = 'SCRUBBED' if scrubbed else 'preserved'
        log_fn(f"    entry[{i // 0x38}] {tag}: lport={lp} "
               f"rport={rp} bytes={e.hex()}")


INPUT_BUILDERS = {
    'nsi_tcp_keys': build_nsi_tcp_keys,
}
