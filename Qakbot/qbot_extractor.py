import pefile
import os
import sys
import hashlib
import re
import functools
import struct
import argparse
from collections import namedtuple

# samples used: 
# 76d9e9e59d2a939f773e953a843906284bb52a14eb573c42c0b09402b65fa430
# 670e990631c0b98ccdd7701c2136f0cb8863a308b07abd0d64480c8a2412bde4
# 84669a2a67b9dda566a1d8667b1d40f1ea2e65f06aa80afb6581ca86d56981e7

# global settings
print_only_c2s = False
quiet = False

#  verify if the hash of the data is the same as the expected hash
def verify_hash(data: bytes, expected_hash: bytes):
   return sha1sum(data) == expected_hash

# returns the sha1 hash of a byte list
def sha1sum(data):
    h  = hashlib.sha1()
    h.update(data)
    return h.digest()

# returns the file's sha256 hash
def sha256sum(filename):
    h  = hashlib.sha256()
    b  = bytearray(128*1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        while n := f.readinto(mv):
            h.update(mv[:n])
    return h.hexdigest()

# decrypt qbot strings
def decipher_strings(data: bytes, key: bytes):
   result = []
   if len(key) == 0 or len(data) == 0: return []
   current_string = list()
   for i in range(len(data)):
       current_string.append(data[i] ^ key[i % len(key)])
       if data[i] == key[i % len(key)]:
              result.append(bytes(current_string))
              current_string = list()
   return result

# code by https://github.com/OALabs/Lab-Notes/blob/main/Qakbot/qakbot.ipynb
def tohex(data):
    import binascii
    if type(data) == str:
        return binascii.hexlify(data.encode('utf-8'))
    else:
        return binascii.hexlify(data)

# append config to the config output file
def write_config_to_file(config, out_file):
    with open(out_file, 'a', encoding='utf-8') as f:
        f.write("------------------------------------------\n\n" + config + "\n")

# extract info that is necessary for decryption, namely: key VA, data VA and data size
def extract_decryption_data(afile):
    DecryptInfo = namedtuple("DecryptInfo", "key data size")
    decrypt_info_list = []
    with open(afile, 'rb') as f:
        data = f.read()
        # 51              push    ecx
        # 68 ([4])        push    offset key
        # BA ([4])        mov     edx, 0E4Ch --> size
        # B9 ([4])        mov     ecx, offset str_table
        # E8 [4]          call    string_main_decrypt_function
        # 83 C4 0C        add     esp, 0Ch
        # C3              retn
        pattern = re.compile(b'\x51\x68(.{4})\xBA(.{4})\xB9(.{4})\xE8.{4}\x83\xC4\x0C\xC3')
        for matched in pattern.finditer(data):
            key_addr = struct.unpack("<L",matched.group(1))[0]
            data_addr = struct.unpack("<L",matched.group(3))[0]
            data_size =  struct.unpack("<L", matched.group(2))[0]

            decrypt_info_list.append(DecryptInfo(key_addr, data_addr, data_size))
    return decrypt_info_list

# read the data based on VA for the data_addr
def read_data(afile, data_addr, data_size):
    data = []
    with open(afile, 'rb') as f:
        pe = pefile.PE(data=f.read())
        # it is a VA, so we need to substract image base
        start = data_addr-pe.OPTIONAL_HEADER.ImageBase 
        data = pe.get_data(start, data_size)
    return data

# heuristically determines the key size and returns the key as byte list
def extract_str_table_key(afile, key_addr):
    maxsize = 0x1000
    data = read_data(afile, key_addr, maxsize)
    prev_was_zero = False
    curr_off = 0
    end_offset = 0
    for b in data:
        if b == 0 and not prev_was_zero:
            prev_was_zero = True       
        elif b == 0 and prev_was_zero:
            end_offset = curr_off-1
            break
        else: prev_was_zero = False
        curr_off += 1
    write("key length found " + str(end_offset))
    return data[:end_offset]

# returns the table data as byte list
def extract_str_table_data(afile, data_addr, data_size):
    return read_data(afile, data_addr, data_size)

# returns all the resources in a list containing the data of the resources
# code partially by https://github.com/OALabs/Lab-Notes/blob/main/Qakbot/qakbot.ipynb
def get_resources(afile):
    resource_data = []
    try:
        with open(afile, 'rb') as f:
            data = f.read()
            pe = pefile.PE(data=data)

            rt_string_idx = [
                    entry.id for entry in 
                    pe.DIRECTORY_ENTRY_RESOURCE.entries
                ].index(pefile.RESOURCE_TYPE['RT_RCDATA'])
            rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]
            
            for entry in rt_string_directory.directory.entries:
                data_rva = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                resource_data.append(pe.get_memory_mapped_image()[data_rva:data_rva+size])
    except:
        write("an error with resource extraction occured!")
        return []
    return resource_data

# code by https://github.com/OALabs/Lab-Notes/blob/main/Qakbot/qakbot.ipynb
def rc4crypt(data, key):
    #If the input is a string convert to byte arrays
    if type(data) == str:
        data = data.encode('utf-8')
    if type(key) == str:
        key = key.encode('utf-8')
    x = 0
    box = list(range(256))
    for i in range(256):
        x = (x + box[i] + key[i % len(key)]) % 256
        box[i], box[x] = box[x], box[i]
    x = 0
    y = 0
    out = []
    for c in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(c ^ box[(box[x] + box[y]) % 256])
    return bytes(out)

# prints one decrypted string table alongside the offsets
# the output format can be used as Python dict
# result looks like this:
# 348 : '\\\\.\\pipe\\\x00',
# 2148 : 'fshoster32.exe\x00',
# 2978 : 'wmic process call create \'expand "%S" "%S"\'\n\x00
# ...
def print_string_lookup(str_list):
    # this is used to count the offsets properly, using the escaped version would result in wrong offsets
    strings = [b.decode('latin1') for b in str_list]
    # looks weird but will put the output string into a format that can be used as string in Python code
    # even if there are multiline strings or quotes in the decrypted strings
    strings_escaped = [b.decode('latin1').encode('unicode_escape').decode('latin1').replace("'","\\'") for b in str_list]
    curr_idx = 0
    write("\n--------String Table Start --------")
    for idx, s in enumerate(strings):
        print(curr_idx, ":", "'"+strings_escaped[idx]+"',")
        curr_idx += len(s)
    write("--------String Table End --------\n")

# extracts and decrypts QBots string tables and prints it
# the output is useful for deobfuscation, it can be put into IDAPython or Binary Ninja API scripts
# to add comments with the translated strings
def main_string_lookup(afile):
    decrypt_info = extract_decryption_data(afile)
    print()
    for table_num, info in enumerate(decrypt_info):
        write("===========Table " + str(table_num + 1) + " ===========\n")
        write("string key va: " + hex(info.key))
        write("string table va: " + hex(info.data))
        write("table size: " + hex(info.size))
        
        str_key = extract_str_table_key(afile, info.key)
        if str_key == []: continue
        strtable = extract_str_table_data(afile, info.data, info.size)
        strings_decrypted = decipher_strings(strtable, str_key)
        print_string_lookup(strings_decrypted)

# extracts and decrypts QBots string tables and returns a list of dictionaries, one dict for each string table in the sample
# the key is the string translation and the value is the decrypted string
def get_string_lookup_dicts(afile):
    decrypt_info = extract_decryption_data(afile)
    result_dicts = []
    for info in decrypt_info:
        str_key = extract_str_table_key(afile, info.key)
        if str_key == []: continue
        strtable = extract_str_table_data(afile, info.data, info.size)
        str_list = decipher_strings(strtable, str_key)
        # this is used to count the offsets properly, using the escaped version would result in wrong offsets
        strings = [b.decode('latin1') for b in str_list]
        # looks weird but will put the output string into a format that can be used as string in Python code
        # even if there are multiline strings or quotes in the decrypted strings
        strings_escaped = [b.decode('latin1').encode('unicode_escape').decode('latin1').replace("'","\\'") for b in str_list]
        curr_idx = 0
        table_dict = dict()
        for idx, s in enumerate(strings):
            table_dict[curr_idx] = strings_escaped[idx]
            curr_idx += len(s)
        if len(table_dict) > 0: result_dicts.append(table_dict)
    return result_dicts
        

# returns potential keys for configuration decryption
# the potential keys are determined by decrypting strings in the string table
def collect_config_keys(afile):
    decrypt_info = extract_decryption_data(afile)
    strings_bytes = set()
    for table_num, info in enumerate(decrypt_info):
        write("===========Table " + str(table_num + 1) + " ===========\n")
        write("string key va: " + hex(info.key))
        write("string table va: " + hex(info.data))
        write("table size: " + hex(info.size))
        
        str_key = extract_str_table_key(afile, info.key)
        if str_key == []: continue
        strtable = extract_str_table_data(afile, info.data, info.size)
        strings_decrypted = decipher_strings(strtable, str_key)
        write("decrypted strings from table " + str(len(strings_decrypted)) + "\n")
        strings_bytes.update(strings_decrypted)
    write("unique decrypted strings " + str(len(strings_bytes)))
    strings_list = [r.decode('latin1') for r in strings_bytes]
    #print("\n".join(strings_list))
    return list(strings_bytes)

# code by https://github.com/OALabs/Lab-Notes/blob/main/Qakbot/qakbot.ipynb
# converts the ip table of QBot to a list with IP addresses as strings
def extract_ips(data):
    ips = []
    ip_table = data[1:]
    for ptr in range(0,len(ip_table),7):
        if len(ip_table) - ptr < 7: break
        ip_string = "%d.%d.%d.%d" % (ord(ip_table[ptr:ptr+1]),
            ord(ip_table[ptr+1:ptr+2]),
            ord(ip_table[ptr+2:ptr+3]),
            ord(ip_table[ptr+3:ptr+4]))
        port_string = struct.unpack('>H', ip_table[ptr+4:ptr+6])[0]
        ips.append("%s:%s" % (ip_string,port_string))
    return ips

# see https://n1ght-w0lf.github.io/malware%20analysis/qbot-banking-trojan/
# translates QBot configuration keys to their meaning
def get_config_key_description(key):
    keys = {
        "10" : "campaign",
        "11" : "c2 number",
        "1"  : "date of installation",
        "2"  : "victim qbot install",
        "5"  : "victim network shares",
        "38" : "last victim call to c2",
        "45" : "c2 ip",
        "46" : "c2 port",
        "39" : "victim external ip",
        "43" : "time of record",
        "3"  : "timestamp"
    }
    if key in keys: return keys[key]
    else: return key

# converts a dictionary to a string
def dict_to_string(dictionary):
    return "\n".join([k + ": " + v for k, v in dictionary.items()])

# puts the plaintext configuration into a dictionary, keys are translated by their meaning
def decode_config(data):
    delim = "="
    try:
        config = data.decode('latin1')
        config_dict = dict()
        if not '10=' in config:
            return None
        for line in config.splitlines():
            if delim in line:
                splitted = line.split(delim)
                key = splitted[0]
                value = delim.join(splitted[1:])
                key = get_config_key_description(key)
                config_dict[key] = value
        return config_dict
    except: 
        return None
    return None

# extracts and returns the configuration of QBot as a string
# to do so it will bruteforce the key, using all decrypted strings from QBots encrypted string table
def extract_config(afile):
    resources = get_resources(afile)
    decrypted_blobs = []
    config_key_candidates = collect_config_keys(afile)
    for key_string in config_key_candidates:
        #print(key_string.decode('latin1'))
        if len(key_string) <= 1: continue
        m = hashlib.sha1()
        m.update(key_string[:-1]) # remove zero byte
        rsrc_key = m.digest()
        for rsrc in resources:
            result = rc4crypt(rsrc, rsrc_key)
            data = result[20:]
            expected_hash = result[:20]
            if verify_hash(data, expected_hash):
                write("")
                write("config hash " + str(tohex(expected_hash)))
                write("config key " + key_string.decode('latin1') + "\n")
                decrypted_blobs.append(data)
    write("successfully decrypted data blobs " + str(len(decrypted_blobs)))
    if decrypted_blobs == []: return ""
    smallest_blob = functools.reduce(lambda a, b: a if len(a) < len(b) else b, decrypted_blobs)
    biggest_blob = functools.reduce(lambda a, b: a if len(a) > len(b) else b, decrypted_blobs)
    ips = extract_ips(biggest_blob)
    write("obtained C2s " + str(len(ips)))
    config_data = smallest_blob
    config = decode_config(config_data)
    config_str = ""
    if config:
        config_str += dict_to_string(config) + "\n"
    else: write("given data blob was not a config")
    config_str += "ips:" + ", ".join(ips) + "\n"
    return config_str

# -f option
def main_file(afile):
    write('checking ' + afile)
    config = extract_config(afile)
    config_str = sha256sum(afile) + "\n\n" + config + "\n\n"
    if not quiet: print("\n" + config)
    if write_c2s_to_file:
        write_config_to_file(config_str, c2_output_file)
    return config_str

# -d option
def main_folder(folder):
    if folder.endswith('\\'): 
        folder = folder[:-1]

    configs = []
    for directory, subdirs, files in os.walk(folder):
        for pfile in files:
            afile = os.path.join(directory, pfile)
            config_str = main_file(afile)
            configs.append(config_str)
    write('\nconfigs extracted: ' + str(len(configs)))

# print only if no --quiet or --c2 settings were used
def write(string):
    if not quiet and not print_only_c2s: print(string)

def main():
    global print_only_c2s
    global quiet 
    global write_c2s_to_file
    global c2_output_file

    parser = argparse.ArgumentParser(description='QBot config extractor and string decrypter')
    parser.add_argument('-f', '--file', help='path is a single qbot sample', action='store_true')
    parser.add_argument('-d', '--directory', help='given path is a directory with samples', action='store_true')
    parser.add_argument('-o', '--output', help='write C2s to file', action='store', type=str)
    parser.add_argument('-c2', '--c2', help='print only C2 data, nothing more', action='store_true', default=print_only_c2s)
    parser.add_argument('-q', '--quiet', help='do not print anything', action='store_true', default=quiet)
    parser.add_argument('-s', '--strings', help='print decoded strings and their offsets (can be used as dict to deobfuscate with IDAPython or Binary Ninja API)', action='store_true')
    parser.add_argument('path', help='file or folder to decode')

    args = parser.parse_args()
    
    print_only_c2s = args.c2
    quiet = args.quiet
    write_c2s_to_file = False
    
    if args.output: 
        write_c2s_to_file = True
        c2_output_file = args.output

    if args.strings:
        if args.directory:
            print("--directory not supported for strings", file=sys.stderr)
        elif os.path.isfile(args.path):
            main_string_lookup(args.path)
        else:
            print("not a file", file=sys.stderr)
    elif args.directory:
        if os.path.isdir(args.path):
            main_folder(args.path)
        else:
            print("not a directory", file=sys.stderr)
    elif args.file:
        if os.path.isfile(args.path):
            main_file(args.path)
        else:
            print("not a file", file=sys.stderr)

if __name__ == '__main__':
    main()