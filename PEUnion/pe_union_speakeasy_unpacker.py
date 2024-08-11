# Unpacks sample packed with PEUnion https://github.com/bytecode77/pe-union/ 
# Supported options: Native 32-Bit stub with RunPE shellcode 
# This is a PoC for a course. Compression option is not handled nor did I test different paddings.
#
# Requirement: Mandiants speakeasy https://github.com/mandiant/speakeasy
# Author: Karsten Hahn @ GDATA CyberDefense

import argparse
from speakeasy import *
import json


class PEUnionUnpacker(Speakeasy):
	
	def __init__(self, output_path, debug=False):
		super(PEUnionUnpacker, self).__init__(debug=debug)
		self.output_path = output_path
		self.error_mode = 0
		
	def dump_unpacked_data(self, start, size):
		print('dumping', hex(start) + '-' + hex(start+size))
		with open(self.output_path, "wb") as f:
			b = self.mem_read(start, size)
			f.write(b)

	def virtual_protect_hook(self, emu, api_name, func, params):
		addr, size, new_prot, old_prot = params
		if new_prot == 0x20:
			print('hooked VirtualProtect', params)
			pe_offset = 0x700
			start = addr + pe_offset
			size = size - pe_offset
			self.dump_unpacked_data(start, size)
			self.stop()
		return 0x0

	def set_error_mode_hook(self, emu, api_name, func, params):
		prev_error = self.error_mode
		self.error_mode = params[0]
		print('hooked SetErrorMode', params)
		return prev_error

def main(args):
	out_path = args.file + '.dmp'
	in_path = args.file
	pu = PEUnionUnpacker(out_path)
	module = pu.load_module(in_path)
	
	pu.add_api_hook(pu.set_error_mode_hook, 'kernel32' ,'SetErrorMode')
	pu.add_api_hook(pu.virtual_protect_hook, 'kernel32', 'VirtualProtect')
	
	pu.run_module(module)
	print('done :)')
	
if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="PEUnion unpacker")
	parser.add_argument('-f', '--file', action='store', dest='file', required=True, help='Path of sample')
	args = parser.parse_args()
	main(args)
