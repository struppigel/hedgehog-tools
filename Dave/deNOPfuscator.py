import idautils
import ida_bytes
import idc
import ida_ua
from idautils import DecodeInstruction
import ida_ua

# deNOPfuscator PoC, IDA 9
# removes superfluous NOP instructions; place the cursor on the start of the function that has NOPs
#
# testfile d982401b64ae312363fafadcfdedabdd7c13ad89651767c5c6bc0fef03f63fb4
# only used this for one file so far, some cases are missing when adjusting the addresses

def instruction_has_relative_address(ea):
    insn = DecodeInstruction(ea)
    if not insn:
        return False

    for op in insn.ops:
        # Check if the operand is of type 'o_near' or 'o_far'
        if op.type in [ida_ua.o_near, ida_ua.o_far]:
            return True
    return False

def deobfuscate(func_ea):
    func_end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
    non_nop_instructions = []
    address_mapping = {}  # Original -> New Address mapping

    # Save all non-NOP instructions and calculate new addresses
    current_offset = 0
    for ea in idautils.Heads(func_ea, func_end):
        if idc.print_insn_mnem(ea).lower() != "nop":
            insn_size = ida_bytes.get_item_size(ea)
            insn_bytes = ida_bytes.get_bytes(ea, insn_size)
            non_nop_instructions.append((ea, insn_bytes))
            address_mapping[ea] = func_ea + current_offset
            current_offset += insn_size
            
    # Adjust relative addresses
    adjusted_instructions = []
    for orig_ea, insn_bytes in non_nop_instructions:
        insn = DecodeInstruction(orig_ea)
        
        if not insn:
            continue
        print(f"{orig_ea:08X}: {idc.generate_disasm_line(orig_ea, 0)}")
        # Check for instructions that need address adjustment
        if instruction_has_relative_address(orig_ea):
            # Get the operand (target address)
            op = insn.ops[0]
            
            # Adjust the target address
            target_ea = op.addr
            print("old call/jmp target", hex(target_ea))
            new_target_ea = address_mapping.get(target_ea, target_ea)
            print("fixup", hex(new_target_ea))
            # Calculate the new relative offset
            new_offset = new_target_ea - address_mapping[orig_ea] - insn.size
			
            # Patch the bytes for the adjusted instruction
            patched_bytes = list(insn_bytes)
            if len(patched_bytes) >= 5:  # Most relative jumps and calls have 4-byte offsets
                patched_bytes[-4:] = new_offset.to_bytes(4, byteorder='little', signed=True)
                patched_bytes = bytes(patched_bytes)
            adjusted_instructions.append((address_mapping[orig_ea], patched_bytes))
            
        else:
            adjusted_instructions.append((address_mapping[orig_ea], insn_bytes))
    return adjusted_instructions

def change_function_size(func_ea, new_end_ea):
    if idc.set_func_end(func_ea, new_end_ea):
        print(f"Function size updated. New end address: {new_end_ea:#X}")
    else:
        print("Failed to update function size.")

def patch_database(func_ea, instructions):
    func_end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)

    # Clear function area with NOPs
    for ea in range(func_ea, func_end):
        ida_bytes.patch_byte(ea, 0x90)

    # Patch the function with the adjusted instructions
    current_ea = func_ea
    for new_ea, insn_bytes in instructions:
        ida_bytes.patch_bytes(current_ea, insn_bytes)
        current_ea += len(insn_bytes)

    change_function_size(func_ea, current_ea)


func_start = here() 
deobfus_instr = deobfuscate(func_start)
patch_database(func_start, deobfus_instr)
print("Function patched with adjusted non-NOP instructions.")
