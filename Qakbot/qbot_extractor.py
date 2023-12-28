import pefile
import os
import hashlib
import re
import functools
import struct
from collections import namedtuple

# samples used: 
# 76d9e9e59d2a939f773e953a843906284bb52a14eb573c42c0b09402b65fa430
# 670e990631c0b98ccdd7701c2136f0cb8863a308b07abd0d64480c8a2412bde4
# 84669a2a67b9dda566a1d8667b1d40f1ea2e65f06aa80afb6581ca86d56981e7

def verify_hash(data: bytes, expected_hash: bytes):
   return sha1sum(data) == expected_hash

def sha1sum(data):
    h  = hashlib.sha1()
    h.update(data)
    return h.digest()

def sha256sum(filename):
    h  = hashlib.sha256()
    b  = bytearray(128*1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        while n := f.readinto(mv):
            h.update(mv[:n])
    return h.hexdigest()

def decipher_strings(data: bytes, key: bytes):
   result = []
   current_string = list()
   for i in range(len(data)):
       current_string.append(data[i] ^ key[i % len(key)])
       if data[i] == key[i % len(key)]:
              result.append(bytes(current_string))
              current_string = list()
   return result

def tohex(data):
    import binascii
    if type(data) == str:
        return binascii.hexlify(data.encode('utf-8'))
    else:
        return binascii.hexlify(data)

def write_config_to_file(config, out_file):
    with open(out_file, 'a', encoding='utf-8') as f:
        f.write("------------------------------------------\n\n" + config + "\n")

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

# read the data based on VA(!) for the data_addr
def read_data(afile, data_addr, data_size):
    data = []
    with open(afile, 'rb') as f:
        pe = pefile.PE(data=f.read())
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
    print("key length found", end_offset)
    return data[:end_offset]

# returns the table data as byte list
def extract_str_table_data(afile, data_addr, data_size):
    return read_data(afile, data_addr, data_size)

# returns all the resources in a list containing the data of the resources
# code partially by https://github.com/OALabs/Lab-Notes/blob/main/Qakbot/qakbot.ipynb
def get_resources(afile):
    resource_data = []
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
    return resource_data

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

# return potential keys for configuration decryption
def collect_config_keys(afile):
    decrypt_info = extract_decryption_data(afile)
    strings_bytes = set()
    for i in decrypt_info:
        print("======================")
        print("string key va:", hex(i.key))
        print("string table va:", hex(i.data))
        print("table size:", hex(i.size))
        
        str_key = extract_str_table_key(afile, i.key)
        strtable = extract_str_table_data(afile, i.data, i.size)
        strings_decrypted = decipher_strings(strtable, str_key)
        print("decrypted strings from table", len(strings_decrypted), "\n")
        strings_bytes.update(strings_decrypted)
    print("unique decrypted strings", len(strings_bytes))
    strings_list = [r.decode('latin1') for r in strings_bytes]
    #print("\n".join(strings_list))
    return list(strings_bytes)

# code partially by https://github.com/OALabs/Lab-Notes/blob/main/Qakbot/qakbot.ipynb
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

def dict_to_string(dictionary):
    return "\n".join([k + ": " + v for k, v in dictionary.items()])

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

def extract_config(afile):
    resources = get_resources(afile)
    decrypted_blobs = []

    for key_string in collect_config_keys(afile):
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
                print()
                print("config hash", tohex(expected_hash))
                print("config key", key_string.decode('latin1'),"\n")
                decrypted_blobs.append(data)
    print("successfully decrypted data blobs", len(decrypted_blobs))
    smallest_blob = functools.reduce(lambda a, b: a if len(a) < len(b) else b, decrypted_blobs)
    biggest_blob = functools.reduce(lambda a, b: a if len(a) > len(b) else b, decrypted_blobs)
    ips = extract_ips(biggest_blob)
    print("obtained C2s", len(ips))
    config_data = smallest_blob
    config = decode_config(config_data)
    config_str = ""
    if config:
        config_str += dict_to_string(config) + "\n"
    else: print("given data blob was not a config")
    config_str += "ips:" + ", ".join(ips)
    return config_str

def main(folder):
    if folder.endswith('\\'): 
        folder = folder[:-1]

    configs = []
    for directory, subdirs, files in os.walk(folder):
        for pfile in files:
            print('checking', pfile)
            afile = os.path.join(directory, pfile)
            config = extract_config(afile)
            config_str = sha256sum(afile) + "\n\n" + config + "\n\n"
            configs.append(config_str)
            write_config_to_file(config_str, 'qbot_configs.txt')
    print('\nconfigs extracted: ' + str(len(configs)))

if __name__ == '__main__':
    import sys
    if len(sys.argv) == 0:
        print("please provide a folder name")
    else:
        main(sys.argv[1])

