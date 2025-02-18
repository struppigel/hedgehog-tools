# Nuitka file extractor
# author: Karsten Hahn

import pefile
import os
import struct
import pyzstd
import struct
import sys

def extract_files_from_rcdata(rcdata, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    offset = 0
    total_size = len(rcdata)

    while offset < total_size:
        file_name, offset = read_le_utf16_zeroterm_string(rcdata, offset, total_size)
        if not file_name:
            # probably EOF
            break
        file_size, offset = read_le_unsigned_64bit(rcdata, offset, total_size)
        if file_size is None:
            print(f"Error: Could not extract file size for {file_name}. Stopping extraction.")
            break
        file_data, offset = read_data(rcdata, offset, file_size, total_size)
        if file_data is None:
            print(f"Error: Could not extract file data for {file_name}. Stopping extraction.")
            break

        save_file(file_name, file_data, output_dir)

def read_le_utf16_zeroterm_string(rcdata, offset, total_size):
    if offset >= total_size:
        return None, offset  # Out of bounds
    name_end = offset
    while name_end + 1 < total_size:
        if rcdata[name_end:name_end+2] == b'\x00\x00':
            break
        name_end += 2  
    if name_end + 1 >= total_size:
        return None, offset
    try:
        file_name = rcdata[offset:name_end].decode("utf-16-le")
        return file_name, name_end + 2 
    except UnicodeDecodeError:
        print(f"Error: Invalid UTF-16 filename at offset {offset}.")
        return None, offset

def read_le_unsigned_64bit(rcdata, offset, total_size):
    if offset + 8 > total_size:
        return None, offset  # Out of bounds
    file_size = struct.unpack_from("<Q", rcdata, offset)[0]  # Little-endian unsigned 64-bit integer
    return file_size, offset + 8 

def read_data(rcdata, offset, file_size, total_size):
    if offset + file_size > total_size:
        return None, offset
    file_data = rcdata[offset:offset + file_size]
    return file_data, offset + file_size

def save_file(file_name, file_data, output_dir):
    file_path = os.path.join(output_dir, file_name + ".vir")
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "wb") as f:
        f.write(file_data)
    print(f"Extracted: {file_path} ({len(file_data)} bytes)")

def get_rcdata_resources(pe):
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        print("No resource section found in the PE file.")
        return []
    rcdata_entries = []
    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if resource_type.id == pefile.RESOURCE_TYPE["RT_RCDATA"]:
            for resource_id in resource_type.directory.entries:
                for resource_lang in resource_id.directory.entries:
                    rcdata_entries.append((resource_id.id, resource_lang))
    
    return rcdata_entries

def extract_resource_data(pe, resource_lang):
    data_rva = resource_lang.data.struct.OffsetToData
    size = resource_lang.data.struct.Size
    return pe.get_memory_mapped_image()[data_rva:data_rva+size]

def validate_nuitka_header(data):
    if len(data) < 3:
        return False
    if data[:2] != b'KA':
        return False
    return True

def is_compressed(data):
    compression_flag = chr(data[2])
    if compression_flag == 'Y':
        return True
    elif compression_flag == 'X':
        return False
    return None

def unpack_item(rcdata, compressed, output_dir):
    if compressed:
        print("decompressing")
        rcdata = pyzstd.ZstdDecompressor().decompress(rcdata)
    extract_files_from_rcdata(rcdata, output_dir)

def unpack_nuitka(path):
    output_dir = path + "_extracted"
    pe = pefile.PE(path)
    if not pe:
        return
    rcdata_entries = get_rcdata_resources(pe)
    if not rcdata_entries:
        return
    for resource_id, resource_lang in rcdata_entries:
        data = extract_resource_data(pe, resource_lang)
        valid_header = validate_nuitka_header(data)
        if not valid_header:
            print(f"skipping RCDATA {resource_id}: invalid header")
            continue
        compression_status = is_compressed(data)
        if compression_status == None:
            print(f"skipping RCDATA {resource_id}: Unknown compression flag '{chr(data[2])}' (expected 'Y' or 'X').")
            continue
        else:
            print(f"unpacking RCDATA {resource_id}")
            unpack_item(data[3:], compression_status, output_dir)

def main(afile):
    unpack_nuitka(afile)
    print("done")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("please provide a file name")
    else:
        main(sys.argv[1])