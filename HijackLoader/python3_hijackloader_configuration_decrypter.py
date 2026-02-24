# Decrypts the configuration of HijackLoader
# 
# this tool was made for the sample 418A1A6B08456C06F2F4CC9AD49EE7C63E642CCE1FA7984AD70FC214602B3B1 
# it decrypts the config file Zootkumbak.uhp, parses it and extracts modules and payload 
# the config is inside of the original file archive and has the following hash 
# af2ade19542dde58b424618b928e715ebf61dffb6d8ca9d4b299e532dfa3b763
# it was not tested on other samples may need adjustments for them
#
# author: Karsten Hahn @ GDATA CyberDefense
#
# The MIT License (MIT)
# 
# Copyright Karsten Hahn © 2026 
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the “Software”), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import struct
import sys
import lznt1
import os
from dataclasses import dataclass

MODULE_HEADER_SIZE = 0x8a

@dataclass
class Module:
    name: str
    header_offset: int
    data_size: int
    data_offset: int
    str_list: list[str]

# Decrypts Zootkumbak.uhp malware configuration data

def find_pattern(data, pattern):
    """Find all occurrences of pattern in data"""
    matches = []
    start = 0
    while True:
        pos = data.find(pattern, start)
        if pos == -1:
            break
        matches.append(pos)
        start = pos + 1
    return matches

def decompress_data(data, file_path):
    try:
        decompressed = lznt1.decompress(data)
        if decompressed:
            decompressed_output_path = file_path + ".decompressed"
            with open(decompressed_output_path, 'wb') as f:
                f.write(decompressed)
            print(f"Saved decompressed data to: {decompressed_output_path}")
            return decompressed
        print("LZNT1 decompression failed")
    except Exception as e:
        print(f"LZNT1 decompression error: {e}")
    return None

def concat_data(fragments, file_path, max_size):
    concatenated_data = bytearray()
    for _, fragment_data in fragments:
        concatenated_data.extend(fragment_data)

    if len(concatenated_data) > max_size:
        concatenated_data = concatenated_data[:max_size]
   
    # Save concatenated raw data before decompression
    raw_output_path = file_path + ".raw_concatenated"
    with open(raw_output_path, 'wb') as f:
        f.write(concatenated_data)
    print(f"Saved raw concatenated data to: {raw_output_path}")
    return concatenated_data

def xor_decrypt(data, key, size):
    result = bytearray()
    key_bytes = struct.pack('<I', key)
    for i in range(size):
        result.append(data[i] ^ key_bytes[i % 4])
    return bytes(result)

def decrypt_config(file_path, pattern="IDAT"):
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    # Build search pattern from IDAT string
    if isinstance(pattern, str):
        search_pattern = pattern.encode('ascii')[:4].ljust(4, b'\x00')
    else:
        search_pattern = struct.pack('<I', pattern)
    
    # Find all fragment positions
    positions = find_pattern(file_data, search_pattern)
    print(f"Found {len(positions)} pattern matches")
    print("")
    if not positions: return None
    
    fragments = []
    xor_key = None

    for i, pos in enumerate(positions):
        if pos < 4 or pos + 16 > len(file_data):
            print(f"Fragment {i+1}: Not enough data for size+IDAT+magic+xorkey header, skipping")
            continue

        size_bytes = file_data[pos-4:pos]  # Get all 4 bytes
        blob_size = struct.unpack('>I', size_bytes)[0]  # Read as big endian
        data_size = blob_size
        
        if blob_size <= 0 or blob_size > len(file_data):
            print(f"Invalid blob size {blob_size}, skipping")
            continue

        header_start = pos + 4
        if i == 0: 
            if header_start + 16 > len(file_data): 
                print(f"fragment {i+1}: Not enough data for extended header, skipping")
                continue
            magic_bytes = file_data[header_start:header_start+4]
            xor_key_bytes = file_data[header_start+4:header_start+8]
            compressed_size_bytes = file_data[header_start+8:header_start+12]
            uncompressed_size_bytes = file_data[header_start+12:header_start+16]
            
            xor_key = struct.unpack('<I', xor_key_bytes)[0]
            compressed_payload_size = struct.unpack('<I', compressed_size_bytes)[0]
            uncompressed_payload_size = struct.unpack('<I', uncompressed_size_bytes)[0]
            
            print("IDAT config header")
            print("-------------")
            print(f"magic bytes: {magic_bytes.hex()}")
            print(f"XOR key: 0x{xor_key:08x}")
            print(f"compressed payload size: {compressed_payload_size} (0x{compressed_payload_size:x})")
            print(f"uncompressed payload size: {uncompressed_payload_size} (0x{uncompressed_payload_size:x})")
            
            data_start = pos + 4 + 16  
            data_size = blob_size - 16  
        else:
            data_start = pos + 4 
            data_size = blob_size 
            
        data_end = data_start + data_size
        
        # Extract and decrypt the data
        encrypted_data = file_data[data_start:data_end]
        decrypted_data = xor_decrypt(encrypted_data, xor_key, len(encrypted_data))
        fragments.append((pos, decrypted_data))
    if not fragments:
        print("ERROR: No fragments found")
        return None
    
    concatenated_data = concat_data(fragments, file_path, max_size=compressed_payload_size)
    return decompress_data(concatenated_data, file_path)

def dump_config(file_path, config):
    output_path = file_path + ".config"
    with open(output_path, 'wb') as f:
        f.write(config)
    print(f"Saved decompressed config to: {output_path}")

def extract_string(config_data, offset):
    """Extract null-terminated string from config at offset"""
    if offset >= len(config_data):
        return ""
    
    end = config_data.find(b'\x00', offset)
    if end == -1:
        return None
    return config_data[offset:end].decode('utf-8', errors='ignore')

def extract_strings(config_data, offset, max_size):
    if offset >= len(config_data):
        return []
    
    end = config_data.find(b'\x00\x00', offset)
    if end == -1:
        return []
    end = min(end, offset + max_size)
    byte_strings = config_data[offset:end].split(b'\x00')
    return [s.decode('utf-8', errors='ignore') for s in byte_strings if s and s.isascii() and len(s) > 1]

def extract_header_strings(config, header_start):
    end = header_start + config[header_start:].find(b'\xFF\xFF\xFF\xFF') - 4
    max_size = min(end - header_start, MODULE_HEADER_SIZE)
    return extract_strings(config, header_start, max_size)

def extract_wstring(config_data, offset):
    """Extract null-terminated UTF-16LE string from config at offset"""
    if offset >= len(config_data):
        return ""

    end = config_data.find(b'\x00\x00', offset)
    if end == -1:
        end = len(config_data)

    raw = config_data[offset:end+1]
    return raw.decode("utf-16le", errors="ignore")


def parse_full_config(config_data):
    # buildup
    # 0x8  moduletable v3, partial offset: should be 8F F9 00 00 == 0xf98f
    # 0x13 COPYLIST directory, should be "d0eccdb9"
    # 0x45 directory %APPDATA%   in wide
    # 0x90 directory %windir%\SysWOW64\ in ascii
    # 0xf4 library path %windir%\SysWOW64\rasapi32.dll in ascii
    # 0x160 moduletable v1 -- some offset into shcode  
    # 0x3dd moduletable v2 -- some offset into shcode, should be FC918B084D
    # 0x3dd + 0 (base of config) + F98F == FD6C
    # moduletable ==  0x3dd + 0 (base of config) + 0xF98F (partial offset) == 0xFD6C
    # moduletable.count == 35
    # data_offset in file =  modulebase + offset_in_header + 0xee4

    if not config_data or len(config_data) < 0x200:
        return None

    moduletable_v3 = struct.unpack('<I', config_data[0x8:0xC])[0]
    copylist_subdirectory = extract_wstring(config_data, 0x13)
    directory1 = extract_wstring(config_data, 0x45)
    directory2 = extract_string(config_data, 0x90)
    library_path = extract_string(config_data, 0xf4)
    moduletable_v1 = struct.unpack('<I', config_data[0x160:0x164])[0] & 0xFFFF
    moduletable_v2 = struct.unpack('<I', config_data[0x3dd:0x3e1])[0] 
    module = moduletable_v3 + 0x3dd
    # TODO which one of these two is it? Probably the flags2!
    flags2 = struct.unpack('<I', config_data[module+0x18:module+0x18+0x4])[0]
    flags = struct.unpack('<I', config_data[0x18:0x18+0x4])[0]
    inject_flags = struct.unpack('<I', config_data[0xc:0xc+0x4])[0]
    module_count_offset = module + 0xee4
    module_count = struct.unpack('<I', config_data[module_count_offset:module_count_offset+0x4])[0]
    payload_data_roffset_ptr = module + 0xeec
    payload_key_size = struct.unpack('<I', config_data[module+0xca4:module+0xca4+0x4])[0]
    # size of encrypted data + key
    payload_data_size = struct.unpack('<I', config_data[module+0xca8:module+0xca8+0x4])[0]
    payload_data_offset = module_count_offset + struct.unpack('<I', config_data[payload_data_roffset_ptr:payload_data_roffset_ptr+0x4])[0]
    modules_start = module + 0x10de
    modules_size_offset = module + 0x1164
    modules_offset = module + 0x1160
    fixed_mod_filename = extract_string(config_data, module + 0x82f)
    
    module_list = []
    for i in range(0,module_count):
        header_offset = modules_start + i * MODULE_HEADER_SIZE
        module_size_offset = modules_size_offset + i * MODULE_HEADER_SIZE
        module_name = extract_string(config_data, header_offset)
        module_size = struct.unpack('<I', config_data[module_size_offset:module_size_offset + 0x4])[0]
        data_offset = module + (i * MODULE_HEADER_SIZE) + 0x1160
        offset_in_header = struct.unpack('<I', config_data[data_offset:data_offset + 0x4])[0]
        module_data_offset =  module + offset_in_header + 0xee4
        str_list = extract_header_strings(config,header_offset)
        if module_name:
            module_list.append(Module(module_name, header_offset, module_size, module_data_offset, str_list))

    return {
        'moduletable_v3': moduletable_v3,
        'copylist_subdirectory': copylist_subdirectory,
        'directory1': directory1,
        'directory2': directory2,
        'library_path': library_path,
        'moduletable_v1': moduletable_v1,
        'moduletable_v2': moduletable_v2,
        'module_table': module, 
        'module_count': module_count,
        'module_list': module_list,
        'flags': flags2,
        'inject_flags' : inject_flags,
        'payload_data_offset' : payload_data_offset,
        'payload_data_size' : payload_data_size,
        'payload_key_size' : payload_key_size,
        'fixed_mod_filename' : fixed_mod_filename
    }

def dump_payload(dump_path, config, config_info):
    output_path = os.path.join(dump_path, "PAYLOAD")
    DWORD_SIZE = 4  
    key_size = DWORD_SIZE * config_info['payload_key_size'] 
    payload_data_offset = config_info['payload_data_offset']
    payload_data_size = config_info['payload_data_size']
    
    key = config[payload_data_offset:payload_data_offset+key_size]
    payload = config[payload_data_offset + key_size: payload_data_offset + payload_data_size]
    
    result = bytearray()
    for i in range(payload_data_size - key_size):
        result.append(payload[i] ^ key[i % key_size])
    
    with open(output_path, 'wb') as f:
        f.write(result)
    return output_path

def dump_modules(dump_path, config, config_info):
    if not os.path.exists(dump_path):
        os.mkdir(dump_path)
    for module in config_info['module_list']:
        offset = module.data_offset
        size = module.data_size
        output_path = os.path.join(dump_path, module.name)
        with open(output_path, 'wb') as f:
            f.write(config[offset:offset+size])
        
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: parse_malware_config.py <file>")
        print("Example: parse_malware_config.py Zootkumbak.uhp")
        sys.exit(1)
    
    file_path = sys.argv[1]
    pattern = sys.argv[2] if len(sys.argv) > 2 else "IDAT"
    
    if pattern.startswith('0x'):
        try:
            pattern = int(pattern, 16)
        except:
            pass
    
    print(f"Parsing file: {file_path}")
    print(f"Searching for pattern: {pattern}")
    
    config = decrypt_config(file_path, pattern)
    if not config: 
        print("[ERROR] No configuration found")
        sys.exit(1)
    
    print(f"\nSuccess decrypting! Config size: {len(config)} bytes")
    dump_config(file_path, config)
    config_info = parse_full_config(config)
    if config_info:
        print(f"\nConfig")
        print("----------")
        print(f"Module offset part 1 @ 0x8: 0x{config_info['moduletable_v3']:x}")
        print(f"COPYLIST subdirectory: {config_info['copylist_subdirectory']}")
        print(f"Directory1: {config_info['directory1']}")
        print(f"Directory2: {config_info['directory2']}")
        print(f"Library path: {config_info['library_path']}")
        print(f"Module table offset: 0x{config_info['module_table']:x}")
        print(f"Module count: {config_info['module_count']}")
        print(f"Flags: 0x{config_info['flags']:x}")
        print(f"Inject flags: 0x{config_info['inject_flags']:x}")
        print(f"Payload data offset: 0x{config_info['payload_data_offset']:x}")
        print(f"Payload data size (including key): 0x{config_info['payload_data_size']:x}")
        print(f"Payload key size (in dwords): 0x{config_info['payload_key_size']:x}")
        print(f"FIXED module filename: {config_info['fixed_mod_filename']}")
        print("Modules:")
        for module in config_info['module_list']:
            print(f" - {module.name}")
            #print(f" - {module.name} (Header Offset: 0x{module.header_offset:x}, Size: {module.data_size} bytes, Data Offset in apitable struct: 0x{module.data_offset:x})")
            str_list = extract_strings(config, module.data_offset, module.data_size)
            for str in str_list:
               print("\t--> " + str)
    dump_path = os.path.join(os.path.dirname(file_path), "extracted_modules")
    dump_modules(dump_path, config, config_info)
    dump_payload(dump_path, config, config_info)
    print("Modules and payload dumped to", dump_path)
