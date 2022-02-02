import argparse
import pefile
import struct

def extract_resource(raw_data):
	pe = pefile.PE(data=raw_data)
	data_list = []
	try:
		rt_string_idx = [
			entry.id for entry in 
			pe.DIRECTORY_ENTRY_RESOURCE.entries
		].index(pefile.RESOURCE_TYPE['RT_STRING'])
	except:
		print("resource not found")
		return None

	rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]

	for entry in rt_string_directory.directory.entries:
		data_rva = entry.directory.entries[0].data.struct.OffsetToData
		size = entry.directory.entries[0].data.struct.Size
		data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
		data_list.append(data)
	return data_list 
	
def extract_strings(resource_data):
	str_list = []
	for raw_config in extract_resource(resource_data):
		idx = 0
		while(idx < len(raw_config)):
			str_size = struct.unpack('<H', bytearray(raw_config[idx:idx+2]))[0]
			idx += 2
			str_size *= 2
			str = raw_config[idx : idx + str_size].decode('utf-16')
			str_list.append(str)
			idx += str_size
	return str_list

def allcome_decrypt(str):
	return ''.join([chr(ord(c)-2) for c in str])

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='AllComeClipper Config Extractor')
	parser.add_argument('-f', '--file', help='file', action='store_true')
	parser.add_argument('file', help='file to decode')
	args = parser.parse_args()
	try:
		with open(args.file,"rb") as f:
			data = f.read()
			str_list = extract_strings(data)
			print(str_list)
			for ctr, str in enumerate(str_list):
				if len(str) > 0:
					print(ctr, allcome_decrypt(str))
	except:
		print("unable to extract config")
		