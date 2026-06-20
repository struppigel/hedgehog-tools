"""Static-disassembly helpers for ktrace.

`discover_ioctls` scans an IRP_MJ_DEVICE_CONTROL dispatcher for IOCTL
constants. It handles three common compiler patterns:

  1. Direct compare:           cmp eax, 0x12c800
  2. SUB cascade (jumptable):  sub eax, 0x12c800 ; je hit_a
                               sub eax, 0xf3994  ; je hit_b   (running base)
  3. Per-device demultiplex:   if (devobj == X) goto handler_X
                               where the IOCTL switch lives inside
                               handler_X. We recurse through direct
                               JMP/CALL targets one or two levels deep.
"""
from __future__ import annotations


def discover_ioctls(emu, dispatcher_va, arch_bits,
                    max_scan_bytes=0x3000, max_recurse=6,
                    expand_neighbors=False):
    """Return a sorted list of IOCTL candidates found in the dispatcher
    plus any direct callees within `max_recurse` hops.

    With `expand_neighbors=True`, every found IOCTL also yields a small
    set of adjacent values (±4, ±8, ±0xC, ±0x10, +0x14, +0x18, +0x1C,
    +0x20) — this catches dense IOCTL families where adjacent codes
    appear only as `cmp <reg>, smalldelta` in the disassembly because
    the compiler emitted `sub <reg>, base ; cmp <reg>, delta`.
    """
    try:
        from capstone import (
            Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32, CS_OP_IMM, CS_OP_REG)
        from capstone.x86 import (
            X86_REG_EAX, X86_REG_RAX, X86_REG_ECX, X86_REG_RCX,
            X86_REG_EDX, X86_REG_RDX)
        IOCTL_REGS = {X86_REG_EAX, X86_REG_RAX,
                      X86_REG_ECX, X86_REG_RCX,
                      X86_REG_EDX, X86_REG_RDX}
    except ImportError:
        return []
    if not dispatcher_va:
        return []

    md = Cs(CS_ARCH_X86, CS_MODE_64 if arch_bits == 64 else CS_MODE_32)
    md.detail = True

    found = set()
    visited = set()

    def looks_like_ioctl(v):
        v &= 0xFFFFFFFF
        device = (v >> 16) & 0xFFFF
        function = (v >> 2) & 0xFFF
        access = (v >> 14) & 0x3
        method = v & 0x3
        if device == 0 or device > 0xFFFF:
            return False
        if function == 0:
            return False
        if v >= 0x80000000:
            return False
        # Reject values whose bytes look like an ASCII string literal —
        # compilers embed 4-byte string slices as imm32 (e.g. 'FnF\0' =
        # 0x00466e46, 'Name' = 0x656d614e). >= 3 printable ASCII bytes
        # is a strong signal it's a string, not an IOCTL.
        b = v.to_bytes(4, 'little')
        printable = sum(1 for c in b if 0x20 <= c < 0x7f)
        if printable >= 3:
            return False
        # Reject round decimal constants in the 1k..10M range — these are
        # buffer sizes / array-bounds / retry counters compiled as
        # `cmp <reg>, IMM`, not IOCTLs. Real IOCTLs almost never align to
        # a 1000-boundary because their constituent fields (DeviceType,
        # Function) are picked independently. Example: Guru8906 BYOVD
        # driver's `cmp rdx, 0x186A0` (100000) max-array-index check.
        if 1000 <= v < 10_000_000 and v % 1000 == 0:
            return False
        return True

    def scan(va, depth):
        if depth > max_recurse or va in visited:
            return
        visited.add(va)
        try:
            code = bytes(emu.mem_read(va, max_scan_bytes))
        except Exception:
            return
        # SUB cascade state (compiler emits `sub eax, K ; je hit`
        # chains to encode dense switch tables). On each `sub eax, K`
        # we accumulate `cumulative += K`; the *original* value of eax
        # at that je is `cumulative` — emit as IOCTL candidate.
        # A subsequent `cmp eax, small` reuses the same cumulative
        # offset: original = cumulative + small.
        # Track per-register so unrelated `sub rsp, 0x30` etc. don't
        # poison the eax/ecx/edx cascade. Reset on rets / unconditional
        # jumps / non-IOCTL-reg modifying ops.
        cumulative = {r: 0 for r in IOCTL_REGS}

        for insn in md.disasm(code, va):
            mn = insn.mnemonic
            if mn == 'ret':
                for r in IOCTL_REGS:
                    cumulative[r] = 0
                continue
            if mn == 'cmp':
                ops = insn.operands
                imm_op = next((o for o in ops if o.type == CS_OP_IMM), None)
                reg_op = next((o for o in ops if o.type == CS_OP_REG), None)
                if imm_op is not None:
                    v = imm_op.imm & 0xFFFFFFFF
                    if looks_like_ioctl(v):
                        found.add(v)
                    if reg_op is not None and reg_op.reg in IOCTL_REGS:
                        c = cumulative.get(reg_op.reg, 0)
                        if c and v < 0x10000:
                            cand = (c + v) & 0xFFFFFFFF
                            if looks_like_ioctl(cand):
                                found.add(cand)
            elif mn == 'sub' and len(insn.operands) == 2:
                ops = insn.operands
                if (ops[0].type == CS_OP_REG and
                        ops[1].type == CS_OP_IMM and
                        ops[0].reg in IOCTL_REGS):
                    v = ops[1].imm & 0xFFFFFFFF
                    reg = ops[0].reg
                    cumulative[reg] = (cumulative[reg] + v) & 0xFFFFFFFF
                    if looks_like_ioctl(cumulative[reg]):
                        found.add(cumulative[reg])
            elif mn == 'add' and len(insn.operands) == 2:
                # `ADD reg, imm32` with top bit set is equivalent to
                # `SUB reg, -imm32` (compiler uses ADD with negative
                # constant to encode the dispatcher's switch base).
                ops = insn.operands
                if (ops[0].type == CS_OP_REG and
                        ops[1].type == CS_OP_IMM and
                        ops[0].reg in IOCTL_REGS):
                    v = ops[1].imm & 0xFFFFFFFF
                    if v & 0x80000000:
                        # Treat as a SUB cascade with K = -v
                        sub_eq = (-ops[1].imm) & 0xFFFFFFFF
                        reg = ops[0].reg
                        cumulative[reg] = (cumulative[reg] + sub_eq) & 0xFFFFFFFF
                        if looks_like_ioctl(cumulative[reg]):
                            found.add(cumulative[reg])
            elif mn == 'mov' and len(insn.operands) == 2:
                ops = insn.operands
                if (ops[0].type == CS_OP_REG and
                        ops[1].type == CS_OP_IMM):
                    v = ops[1].imm & 0xFFFFFFFF
                    if looks_like_ioctl(v):
                        found.add(v)
                    # A `mov eax, X` resets that register's cascade.
                    if ops[0].reg in IOCTL_REGS:
                        cumulative[ops[0].reg] = 0
                elif (ops[0].type == CS_OP_REG and
                        ops[0].reg in IOCTL_REGS):
                    # `mov eax, [mem]` or `mov eax, reg` resets too.
                    cumulative[ops[0].reg] = 0
            elif mn == 'mov' and len(insn.operands) == 2:
                # `mov eax, imm32` may be a switch-table base or an
                # IOCTL constant being written to a buffer.
                ops = insn.operands
                if (ops[0].type == CS_OP_REG and
                        ops[1].type == CS_OP_IMM):
                    v = ops[1].imm & 0xFFFFFFFF
                    if looks_like_ioctl(v):
                        found.add(v)
            elif mn in ('call', 'jmp'):
                if len(insn.operands) == 1 and insn.operands[0].type == CS_OP_IMM:
                    target = insn.operands[0].imm
                    if (0x140000000 <= target < 0x180000000
                            or 0x10000 <= target < 0x80000000):
                        scan(target, depth + 1)
                for r in IOCTL_REGS:
                    cumulative[r] = 0
                if mn == 'jmp':
                    # Linear sweep across a jmp at top-level of a basic
                    # block is unreliable; recursing already covered
                    # the target. Continue scanning the fallthrough
                    # since some compilers put jmp inside dispatcher
                    # before subsequent code.

                    continue

    scan(dispatcher_va, 0)

    if expand_neighbors:
        # Most dense-IOCTL switches use closely-spaced codes. Add a
        # small fan-out around each found candidate so we probe
        # adjacent dense codes whose constants are hidden by SUB+CMP
        # tricks. Bounded to ±0x40 to avoid false positives.
        neighbors = set()
        for v in list(found):
            for d in (4, 8, 0xC, 0x10, 0x14, 0x18, 0x1C, 0x20,
                      0x24, 0x28, 0x2C, 0x30, 0x34, 0x38, 0x3C, 0x40):
                for sign in (-1, 1):
                    cand = (v + sign * d) & 0xFFFFFFFF
                    if looks_like_ioctl(cand):
                        neighbors.add(cand)
        found |= neighbors

    return sorted(found)
