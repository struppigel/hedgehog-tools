# HijackLoader AVDATA decoder
# decodes the AVDATA module
# this tool was made for the sample 418A1A6B08456C06F2F4CC9AD49EE7C63E642CCE1FA7984AD70FC214602B3B1 
# decode the configuration first and extract the modules
# supply AVDATA module to this file
#
# author: Karsten Hahn @ GDATA CyberDefense
 
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
from dataclasses import dataclass
from typing import List

STRUCT_FORMAT = "<IBBBBiiiii"
STRUCT_SIZE = struct.calcsize(STRUCT_FORMAT)

processes = ['a2service', 'a2service.exe', 'wrsa', 'wrsa.exe', 'msmpeng', 'msmpeng.exe', 'avastsvc.exe','ekrn.exe','avp.exe','ccsvchst.exe','n360.exe','avguard.exe','avgsvc.exe','avgui.exe','vsserv.exe','epsecurityservice.exe','coreserviceshell.exe','mcshield.exe','mctray.exe','nis.exe','ns.exe','bdagent.exe','uiseagnt.exe','bytefence.exe','mcuicnt.exe','vkise.exe','cis.exe','mbam.exe','zhudongfangyu.exe','360tray.exe']

def reverse_bits32(x):
    x = ((x & 0x55555555) << 1) | ((x >> 1) & 0x55555555)
    x = ((x & 0x33333333) << 2) | ((x >> 2) & 0x33333333)
    x = ((x & 0x0F0F0F0F) << 4) | ((x >> 4) & 0x0F0F0F0F)
    x = ((x & 0x00FF00FF) << 8) | ((x >> 8) & 0x00FF00FF)
    return ((x << 16) | (x >> 16)) & 0xffffffff

def calc_hash(apiname):
    apiname = apiname.encode("ascii")
    x = 0x171
    y = 0x1e2
    z = 499
    
    while (y < 0xa6 and (x == 0x58)) and (z == 0x4d):
        x = 0x59
        y = y + 1
        z = 0xed
    
    hash = 0xFFFFFFFF
    for c in apiname:
        reversed = reverse_bits32(c)
        for j in range(8):
            if ((hash ^ reversed) & 0x80000000) != 0:
                hash = ((hash << 1) ^ 0x4c11db7) & 0xFFFFFFFF
            else:
                hash = (hash << 1) & 0xFFFFFFFF
            reversed = (reversed << 1) & 0xFFFFFFFF
    
    return reverse_bits32((~hash) & 0xFFFFFFFF)


def find_api_for_hash(req_hash):
    api_lists = {'processes' : processes}
    for dllname, api_list in api_lists.items():
        for apiname in api_list:
            if calc_hash(apiname) == req_hash:
                return apiname
    return None


@dataclass
class AvDataProcessBlock:
    crc32: int
    execution_type: int
    persistence_flag: int
    unknown: int
    unknown_2: int
    bits_persistence_flag: int
    unknown_3: int
    unknown_4: int
    injection_type: int
    overwrite_pe_headers_with_junk_flag: int
    
    def persistence_flag_str(self) -> str:
        PERSISTENCE = {
            1: "LNK",
            3: "SCHEDULED_TASK",
        }
        return PERSISTENCE.get(self.persistence_flag, hex8(self.persistence_flag))
    


def parse_avdata_process_blocks(data: bytes) -> List[AvDataProcessBlock]:
    if len(data) % STRUCT_SIZE != 0:
        raise ValueError(
            f"Data size ({len(data)}) is not a multiple of struct size ({STRUCT_SIZE})"
        )

    blocks = []

    for offset in range(0, len(data), STRUCT_SIZE):
        fields = struct.unpack_from(STRUCT_FORMAT, data, offset)
        blocks.append(AvDataProcessBlock(*fields))

    return blocks


def parse_from_file(path: str) -> List[AvDataProcessBlock]:
    with open(path, "rb") as f:
        data = f.read()
    return parse_avdata_process_blocks(data)


def hex32(x):
    return f"0x{x & 0xFFFFFFFF:08X}"

def hex8(x):
    return f"0x{x & 0xFF:02X}"

if __name__ == "__main__":
    blocks = parse_from_file(sys.argv[1])
for i, b in enumerate(blocks):
    print(f"[{i}]")
    process_name =  find_api_for_hash(b.crc32)
    if process_name:
        print(f"  Processname                         : {process_name}")
    print(f"  CRC32                               : {hex32(b.crc32)}")
    print(f"  Execution_Type                      : {hex8(b.execution_type)}")
    print(f"  Persistence_Flag                    : {b.persistence_flag_str()}")
    print(f"  unknown                             : {hex8(b.unknown)}")
    print(f"  unknown_2                           : {hex8(b.unknown_2)}")
    print(f"  BITS_Persistence_Flag               : {hex32(b.bits_persistence_flag)}")
    print(f"  unknown_3                           : {hex32(b.unknown_3)}")
    print(f"  unknown_4                           : {hex32(b.unknown_4)}")
    print(f"  Injection_Type                      : {hex32(b.injection_type)}")
    print(f"  overwrite_pe_headers_with_junk_Flag : {hex32(b.overwrite_pe_headers_with_junk_flag)}")
