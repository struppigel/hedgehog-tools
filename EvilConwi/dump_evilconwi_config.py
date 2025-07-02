# EvilConwi configuration extractor
# EvilConwi puts their config into unauthenticated attributes of the certificate table
# that is a form of authenticode stuffing that allows to keep a validly signed file but still using different settings
# these settings are necessary to determine if a CW installer is clean or malicious because it is the only difference between the files.

# tested on, e.g., 277ef6c0dcaf0e76291fbde0199dda1ca521c03e77dc56c54f5b9af8508e6029
# Usage: python dump_evilconwi_config.py <sample> <output-folder>
# Author: Karsten Hahn @ GDATA CyberDefense

import sys
import struct
import os
import pefile
import re
from asn1crypto import cms
from dataclasses import dataclass
from typing import List, Tuple

DEBUG_MODE = False
RES_OVERRIDE_ONLY_MODE = False

@dataclass
class ClientData:
	is_silent: bool
	instance_identifier_blob: bytes
	client_launch_parameters_string: str
	client_launch_parameters_constraint_string: str
	components_to_exclude: int
	additional_files: List[Tuple[str, bytes]]
	png_icons_by_size: List[Tuple[int, bytes]]
	encoded_certificate_chain: bytes
	digest: bytes
	signature: bytes

class Reader:
	def __init__(self, data: bytes, offset: int = 0):
		self.data = data
		self.offset = offset

	def read(self, size: int) -> bytes:
		if self.offset + size > len(self.data):
			raise EOFError(f"Attempt to read {size} bytes past end of data.")
		result = self.data[self.offset:self.offset + size]
		self.offset += size
		return result

	def read_boolean(self) -> bool:
		value = struct.unpack('<?', self.read(1))[0]
		if DEBUG_MODE:
			print(f"Read Boolean: {value}")
		return value

	def read_int32(self) -> int:
		value = struct.unpack('<i', self.read(4))[0]
		if DEBUG_MODE:
			print(f"Read Int32: {hex(value)}")
		return value

	def read_7bit_encoded_int(self) -> int:
		result = 0
		shift = 0
		while True:
			byte = self.read(1)[0]
			result |= (byte & 0x7F) << shift
			if not (byte & 0x80):
				break
			shift += 7
		return result

	def read_string(self) -> str:
		length = self.read_7bit_encoded_int()
		if length < 0:
			raise ValueError("Negative length for string.")
		value = self.read(length).decode('utf-8')
		if DEBUG_MODE:
			print(f"Read String of length {hex(length)}: {value}")
		return value

	def read_size_prefixed_bytes(self) -> bytes:
		length = self.read_int32()
		if length < 0:
			raise ValueError("Negative length for bytes.")
		value = self.read(length)
		if DEBUG_MODE:
			print(f"Read Size-Prefixed Bytes of length {hex(length)}")
		return value

def extract_strings_from_bytes(data: bytes, min_length: int = 6):
    ascii_re = re.compile(
        rb'([\x20-\x7E]{' + str(min_length).encode() + rb',})'
    )
    ascii_matches = [
        (m.start(), m.group(1).decode('ascii')) for m in ascii_re.finditer(data)
    ]

    utf16_re = re.compile(
        rb'((?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',})'
    )
    utf16_matches = []
    for m in utf16_re.finditer(data):
        try:
            s = m.group(1).decode('utf-16le')
            utf16_matches.append((m.start(), s))
        except UnicodeDecodeError:
            continue

    # Combine and sort by offset
    all_strings = ascii_matches + utf16_matches
    all_strings.sort(key=lambda x: x[0])  # sort by byte offset

    return [s for _, s in all_strings]

def parse_client_data(reader: Reader) -> ClientData:
	is_silent = reader.read_boolean()
	instance_identifier_blob = reader.read_size_prefixed_bytes()
	client_launch_parameters_string = reader.read_string()
	client_launch_parameters_constraint_string = reader.read_string()
	components_to_exclude = reader.read_int32()
	additional_files_count = reader.read_int32()
	additional_files = [(reader.read_string(), reader.read_size_prefixed_bytes()) for _ in range(additional_files_count)]
	png_icons_count = reader.read_int32()
	png_icons_by_size = [(reader.read_int32(), reader.read_size_prefixed_bytes()) for _ in range(png_icons_count)]
	encoded_certificate_chain = reader.read_size_prefixed_bytes()
	digest = reader.read_size_prefixed_bytes()
	signature = reader.read_size_prefixed_bytes()
	return ClientData(
		is_silent,
		instance_identifier_blob,
		client_launch_parameters_string,
		client_launch_parameters_constraint_string,
		components_to_exclude,
		additional_files,
		png_icons_by_size,
		encoded_certificate_chain,
		digest,
		signature
	)

def format_client_data_string(parsed: ClientData) -> str:
	
	lines = []
	
	if RES_OVERRIDE_ONLY_MODE:
		resource_override_list = [x[1] for x in parsed.additional_files if "Client.Override.en-US.resources" in x[0]]
		if len(resource_override_list) > 0:
			lines.append("\n--- Resource Override Strings ---\n")
			for s in extract_strings_from_bytes(resource_override_list[0]):
				lines.append(s)
		return '\n'.join(lines)
	
	lines.append("\n========= Parsed Client Data =========")
	lines.append(f"Is Silent: {parsed.is_silent}")
	lines.append(f"Components to Excludet: {hex(parsed.components_to_exclude)}")
	lines.append("\n--- Instance Identifier Blob ---")
	lines.append(parsed.instance_identifier_blob.hex())
	lines.append("\n--- Launch Parameters ---")
	lines.append(f"Launch Parameters: {parsed.client_launch_parameters_string}")
	lines.append(f"Launch Constraints: {parsed.client_launch_parameters_constraint_string}")
	lines.append("\n--- Additional Files ---")
	for filename, data in parsed.additional_files:
		lines.append(f"  {filename:<30} {hex(len(data))} bytes")
		
	resource_override_list = [x[1] for x in parsed.additional_files if "Client.Override.en-US.resources" in x[0]]
	if len(resource_override_list) > 0:
		lines.append("\n--- Resource Override Strings ---\n")
		for s in extract_strings_from_bytes(resource_override_list[0]):
			lines.append(s)
	
	appconfig_list = [x[1].decode('utf-8') for x in parsed.additional_files if "app.config" in x[0]]
	if len(appconfig_list) > 0:
		lines.append("\n--- Application Settings ---\n")
		lines.append(appconfig_list[0])
	
	systemconfig_list = [x[1].decode('utf-8') for x in parsed.additional_files if "system.config" in x[0]]
	if len(systemconfig_list) > 0:
		lines.append("\n--- System Settings ---\n")
		lines.append(systemconfig_list[0])
		
	lines.append("\n--- PNG Icons by Size ---")
	for size, data in parsed.png_icons_by_size:
		lines.append(f"  {size:>3}px : {hex(len(data))} bytes")
	lines.append("\n--- Certificates and Digests ---")
	lines.append(f"Encoded Certificate Chain: {hex(len(parsed.encoded_certificate_chain))} bytes")
	lines.append(f"Digest: {hex(len(parsed.digest))} bytes")
	lines.append(f"Signature: {hex(len(parsed.signature))} bytes")
	return '\n'.join(lines)

def write_client_data(parsed: ClientData, output_dir: str):
	icons_dir = os.path.join(output_dir, "icons")
	files_dir = os.path.join(output_dir, "files")
	os.makedirs(icons_dir, exist_ok=True)
	os.makedirs(files_dir, exist_ok=True)
	for filename, data in parsed.additional_files:
		with open(os.path.join(files_dir, filename), 'wb') as f:
			f.write(data)
	for size, data in parsed.png_icons_by_size:
		with open(os.path.join(icons_dir, f"icon_{size}px.png"), 'wb') as f:
			f.write(data)
	with open(os.path.join(output_dir, "extracted_configuration.txt"), "w", encoding="utf-8") as f:
		f.write(format_client_data_string(parsed))

def try_parse(data: bytes, output_dir: str) -> bool:
	for offset in range(10):
		if data[offset:offset+8] == b'h\x00t\x00t\x00p\x00':
			print("offset", hex(offset))
			end = data.find(b'\x00\x00\x00', offset)
			print("end", hex(end))
			if end != -1:
				try:
					url = data[offset:end+1].decode('utf16')
					display = f"========= Extracted URL =========\n\n{url}"
					print(display)
					with open(os.path.join(output_dir, "extracted_configuration.txt"), "w", encoding="utf-8") as f:
						f.write(display)
					return True
				except UnicodeDecodeError:
					print('UnicodeError')
					pass
	for offset in range(100):
		reader = Reader(data, offset)
		try:
			is_silent = reader.read_boolean()
			length = reader.read_int32()
			if DEBUG_MODE:
				print(f"Offset {offset}: Boolean={is_silent}, Next Int32={hex(length)}")
			if 0 <= length < 10000:
				reader = Reader(data, offset)
				parsed = parse_client_data(reader)
				print(f"Successfully parsed at offset {offset}")
				print(format_client_data_string(parsed))
				write_client_data(parsed, output_dir)
				return True
		except (EOFError, ValueError, struct.error):
			continue
	return False


def dump_certificate_table(file_path, output_dir, summary):
	pe = pefile.PE(file_path, fast_load=True)
	certs_dumped = False
	config_extracted = False

	security_dir_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
		pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
	]
	if security_dir_entry.VirtualAddress == 0:
		print("No certificate table found.")
		return certs_dumped, config_extracted

	cert_table_offset = security_dir_entry.VirtualAddress
	cert_table_size = security_dir_entry.Size
	cert_data = pe.__data__[cert_table_offset: cert_table_offset + cert_table_size]
	os.makedirs(output_dir, exist_ok=True)

	attr_index = 0
	offset = 0
	while offset < len(cert_data):
		length = int.from_bytes(cert_data[offset:offset+4], 'little')
		cert_blob = cert_data[offset+8: offset+length]
		try:
			content_info = cms.ContentInfo.load(cert_blob)
			if content_info['content_type'].native != 'signed_data':
				offset += ((length + 7) & ~7)
				continue
			signed_data = content_info['content']
			for signer_info in signed_data['signer_infos']:
				unsigned_attrs = signer_info['unsigned_attrs']
				if unsigned_attrs:
					certs_dumped = True
					for attr in unsigned_attrs:
						for value in attr['values']:
							data = value.dump()
							attr_path = os.path.join(output_dir, f"attribute_{attr_index}.bin")
							with open(attr_path, "wb") as f:
								f.write(data)
							if try_parse(data, output_dir):
								config_extracted = True
							attr_index += 1
		except Exception as e:
			print(e)
			pass
		offset += ((length + 7) & ~7)
	return certs_dumped, config_extracted

def process_folder(folder_path, output_base):
	summary = []
	for filename in os.listdir(folder_path):
		file_path = os.path.join(folder_path, filename)
		if not os.path.isfile(file_path):
			continue
		output_dir = os.path.join(output_base, os.path.splitext(filename)[0])
		print(f"\nProcessing: {file_path}")
		try:
			certs, config = dump_certificate_table(file_path, output_dir, summary)
			summary.append((filename, certs, config))
		except Exception as e:
			print(f"Error processing {filename}: {e}")

	print("\n========== Summary ==========")
	for fname, certs, config in summary:
		print(f"{fname}: Attributes dumped: {certs}, Config extracted: {config}")

if __name__ == "__main__":
	if len(sys.argv) < 3:
		print("Usage: python dump_evilconwi_config.py <file_or_folder> [<output_dir>] [debug|res_override]")
		sys.exit(1)
	input_path = sys.argv[1]
	output_dir = input_path + "_extracted"
	if len(sys.argv) > 2 and sys.argv[2].lower() != "debug" and sys.argv[2].lower() != "res_override" :
		output_dir = sys.argv[2]

	if len(sys.argv) > 2 and sys.argv[2].lower() == "debug":
		DEBUG_MODE = True
	if len(sys.argv) > 2 and sys.argv[2].lower() == "res_override":
		RES_OVERRIDE_ONLY_MODE = True
	
	if len(sys.argv) > 3 and sys.argv[3].lower() == "debug":
		DEBUG_MODE = True
	if len(sys.argv) > 3 and sys.argv[3].lower() == "res_override":
		RES_OVERRIDE_ONLY_MODE = True

	os.makedirs(output_dir, exist_ok=True)

	if os.path.isdir(input_path):
		process_folder(input_path, output_dir)
	else:
		try:
			dump_certificate_table(input_path, output_dir, [])
		except pefile.PEFormatError:
			with open(input_path, 'rb') as f:
				data = f.read()
			if not try_parse(data, output_dir):
				print("Failed to parse data within first 100 bytes.")
				sys.exit(1)