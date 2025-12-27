# Python helper scripts
 
Small Python scripts for generic tasks.

## extract_export_symbols

This script is a helper for writing api resolvers. 

It will print the export symbols as a Python list, which can be copied into the api resolver.


## monitor_and_dump_changed_files

Use this script during dynamic analysis to monitor a specific folder and dump any file changes.

It will save every change in with `<filename>_<timestamp>.<extension>` into the given dump folder.

This is useful if you have, e.g., an installer, dropper or wrapped file and want to extract the files that are unpacked and possibly deleted during execution.