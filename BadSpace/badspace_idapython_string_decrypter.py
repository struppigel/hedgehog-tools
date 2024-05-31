import idaapi, idc, idautils

# This script is a modified version of Revil String decrypter by OALabs: https://gist.github.com/OALabs/04ef6b2d6203d162c5b3b0eefd49530c
#
# It decrypts the strings of BadSpace, renames the labels and applies comments with the decrypted strings to both, disassembly and decompilation.
# Currently it works only for one sample because it needs the decrypt function address.
#
# sample: 6a195e6111c9a4b8c874d51937b53cd5b4b78efc32f7bb255012d05087586d8f
# author: Karsten Hahn @ GDATA CyberDefense AG

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

# from https://github.com/X-Junior/Malware-IDAPython-Scripts/blob/main/Badspace/badspace.py
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

def find_string_ref(ptr_addr):
	# looking for instructions of the form: lea rcx, <imm-value>
    reg_name = 'rcx'
	regsize = 8
    inst_name = 'lea'
    e_count = 0
    ## count back 500 heads
    while e_count < 500:
        e_count += 1
        ptr_addr = idc.prev_head(ptr_addr)
        if idc.print_insn_mnem(ptr_addr) == inst_name:
            tmp_reg_name = idaapi.get_reg_name(idc.get_operand_value(ptr_addr, 0), regsize)
            if reg_name.lower() == tmp_reg_name.lower():
                if idc.get_operand_type(ptr_addr, 1) == 2:
                    return idc.get_operand_value(ptr_addr, 1)
    return None

def get_xref_list(fn_addr):
    return [addr.frm for addr in idautils.XrefsTo(fn_addr)]
    
def decrypt_string(fn_address):
    key_start = 4
    key_size = 4
    str_start = 8
    string_blob = find_string_ref(fn_address)
    if string_blob == None: return
    str_len = int.from_bytes(idc.get_bytes(string_blob, 4), byteorder='little')
    key_data = idc.get_bytes(string_blob + key_start, key_size)
    str_data = idc.get_bytes(string_blob + str_start, str_len)
    plaintxt_str =  rc4crypt(key_data, str_data)
    out_str = plaintxt_str.replace('\x00','')
    print("0x%x: %s" % (fn_address, out_str))
    set_comment(fn_address, out_str)
    # set label for data address
    idc.set_name(string_blob, out_str, idaapi.SN_FORCE)

def decrypt_all_strings(fn_address):
    for ptr in get_xref_list(fn_address):
        decrypt_string(ptr)

# TODO automate function search
decrypt_all_strings(0x2EDA35E40)
decrypt_all_strings(0x2EDA35DC0)