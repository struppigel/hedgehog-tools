# This script determins the decrypt functions, renames them accordingly, decrypts the strings of BadSpace and 
# applies comments with the decrypted strings to decompilation.
# Requirements: hexrays decompiler available, encrypted strings are in ".data" or ".rdata" section
#
# sample: 6a195e6111c9a4b8c874d51937b53cd5b4b78efc32f7bb255012d05087586d8f
# author: Karsten Hahn @ GDATA CyberDefense AG

import idautils
import ida_hexrays
import sys    

# function from  https://gist.github.com/OALabs/04ef6b2d6203d162c5b3b0eefd49530c
def rc4crypt(key, data):
    x = 0
    box = list(range(256))
    for i in list(range(256)):
        x = (x + box[i] + key[i % len(key)]) % 256
        box[i], box[x] = box[x], box[i]
    x = 0
    y = 0
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(char ^ box[(box[x] + box[y]) % 256]))
    return ''.join(out)
    
def decrypt_string(string_blob):
    MAX_LEN = 300
    key_start = 4
    key_size = 4
    str_start = 8
    str_len = int.from_bytes(idc.get_bytes(string_blob, 4), byteorder='little')
    if str_len >= MAX_LEN: return None
    key_data = idc.get_bytes(string_blob + key_start, key_size)
    str_data = idc.get_bytes(string_blob + str_start, str_len)
    if key_data == None or str_data == None: return None
    plaintxt_str =  rc4crypt(key_data, str_data)
    out_str = plaintxt_str.replace('\x00','')
    return out_str

# function from https://github.com/X-Junior/Malware-IDAPython-Scripts/blob/main/Badspace/badspace.py
def set_comment(address, comment):
    cfunc = idaapi.decompile(address)
    eamap = cfunc.get_eamap()
    decompObjAddr = eamap[address][0].ea

    tl = idaapi.treeloc_t()
    tl.ea = decompObjAddr
    commentSet = False

    for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
        tl.itp = itp
        cfunc.set_user_cmt(tl, comment)
        cfunc.save_user_cmts()
        unused = cfunc.__str__()
        if not cfunc.has_orphan_cmts():
            commentSet = True
            cfunc.save_user_cmts()
            break
        cfunc.del_orphan_cmts()

# finds potential decrypt calls and decrypt
def find_call_and_decrypt(cfunc):
    decrypt_functions = set()
    
    class my_call_visitor(ida_hexrays.ctree_visitor_t):
        
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST) # CV_FAST does not keep parents nodes in CTREE
        
        def visit_expr(self, e):
	        # only interested in calls
            if e.op != ida_hexrays.cot_call:
                return 0
                
            called = e.x 
            if ( called.op != ida_hexrays.cot_obj # called function has right node type
                or e.a.size() != 1 ): # number of arguments is 1
                return 0
            
            arg1 = e.a.at(0) # obtain first argument
            # a is the argument vector for the function call
            if arg1 and arg1.op == ida_hexrays.cot_ref: # make sure it is a reference
                encrypted_data_addr = arg1.x.obj_ea
                segment = get_segm_name(encrypted_data_addr)
                # make sure target is in correct segment
                if segment != ".data" and segment != ".rdata": return 0 
                decrypted = decrypt_string(encrypted_data_addr)
                if decrypted:
                    print("call arg found at 0x%x with data addr 0x%x" % (arg1.ea, encrypted_data_addr))
                    print("decrypted", decrypted)
                    set_comment(arg1.ea, decrypted)
                    decrypt_functions.add(called.obj_ea)
                    idc.set_name(encrypted_data_addr, decrypted, idaapi.SN_FORCE)
            return 0 # continue traversal
    v = my_call_visitor()
    v.apply_to(cfunc.body, None)
    return decrypt_functions

def rename_and_print_functions(funs, basename):
    for ea in funs:
        idaapi.set_name(ea, basename, idaapi.SN_FORCE)
        print("%s: %s" % (hex(ea), get_name(ea)))

if __name__ == "__main__":
    if not idaapi.init_hexrays_plugin():   
        sys.exit()     
        
    decrypt_functions = set()
    # iterate all functions in all segments
    for segea in idautils.Segments():
        for func_ea in idautils.Functions(segea, get_segm_end(segea)):
            cfunc = idaapi.decompile(func_ea)
            decrypt_functions.update(find_call_and_decrypt(cfunc))
            
    print("decrypt functions found and renamed")
    rename_and_print_functions(decrypt_functions, "mlw_string_decrypt")
        
    print("done")
