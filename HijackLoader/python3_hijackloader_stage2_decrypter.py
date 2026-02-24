# Decrypts the 2nd stage shellcode of HijackLoader
# 
# this tool was made for the sample 418A1A6B08456C06F2F4CC9AD49EE7C63E642CCE1FA7984AD70FC214602B3B1 
# it decrypts the file Groumcumgag.ic inside of that archive fed719608185e516c70a1e801b5c568406ef6e1c292e381ba32825c6add93995 
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

import sys
import struct

# Known constant from malware: DAT_18007490f = 0x4A19
# This might change in other versions!
HEADER_OFFSET = 0x4A19

def extract_strings(config_data, offset=0xf4):
    if offset >= len(config_data):
        return ""
    
    end = config_data.find(b'\x00', offset)
    if end == -1:
        end = len(config_data)
    
    return config_data[offset:end].decode('utf-8', errors='ignore')

def decrypt_groumcumgag(file_path, output_path=None):
    with open(file_path, 'rb') as f:
        data = bytearray(f.read())
    
    if len(data) < HEADER_OFFSET + 8:
        print(f"Error: File too small")
        return False
    
    header_pos = HEADER_OFFSET
    data_size = struct.unpack('<I', data[header_pos:header_pos+4])[0]
    decrypt_key = struct.unpack('<I', data[header_pos+4:header_pos+8])[0]
    
    print(f"Encrypted data size: 0x{data_size:X}, Key: 0x{decrypt_key:08X}, Encrypted data offset: 0x{header_pos + 8:08X}")
    
    if data_size != 0:
        num_dwords = ((data_size - 1) >> 2) + 1
        encrypted_start = header_pos + 8
        
        for i in range(num_dwords):
            pos = encrypted_start + (i * 4)
            if pos + 4 <= len(data):
                dword = struct.unpack('<I', data[pos:pos+4])[0]
                dword = (dword + decrypt_key) & 0xFFFFFFFF
                data[pos:pos+4] = struct.pack('<I', dword)

        decrypted = data[encrypted_start:encrypted_start+data_size]
        
        target_dll = extract_strings(decrypted, 0x1)
        print("Injection DLL stage 2:", target_dll)
        if output_path is None:
            output_path = file_path + ".decrypted"
        
        with open(output_path, 'wb') as f:
            f.write(decrypted)
        
        print(f"Decrypted {data_size} bytes for shellcode layer 2 to {output_path}")
        return True
    
    return False

if __name__ == '__main__':
    print("IDAT Loader decrypter")
    print("---------------------\n")
    if len(sys.argv) != 2:
        print("Usage: python decrypt_simple.py <groumcumgag.ic>")
        sys.exit(1)
    
    decrypt_groumcumgag(sys.argv[1])