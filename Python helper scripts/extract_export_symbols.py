# This script is a helper for writing api resolvers. 
# It will print the export symbols as a Python list, which can be copied into the api resolver.
# author: Karsten Hahn

import pefile
import sys

def extract_export_symbols(pe_file_path):
	try:
		# Load the PE file
		pe = pefile.PE(pe_file_path)
	
		# Check if the PE file has an export directory
		if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
			print("Exported symbols:")
			res_str = "[ "
			for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
				# Get the symbol name or ordinal if the name is missing
				if export.name:
					symbol_name = export.name.decode('utf-8')
					res_str += "'" + symbol_name + "', "
			res_str = res_str[:-2] + " ]"
			print(res_str)
		else:
			print("No export symbols found.")
	except pefile.PEFormatError as e:
		print(f"Error loading PE file: {e}")
	except Exception as e:
		print(f"An error occurred: {e}")

if __name__ == "__main__":
	# Usage example
	if len(sys.argv) != 2:
		print("Usage: python extract_exports.py <path>")
		sys.exit(1)

	pe_file_path = sys.argv[1]
	extract_export_symbols(pe_file_path)