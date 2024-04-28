# CobaltStrike
 
Resolves API hashes of CobaltStrike shellcode with default ROR 0xD hashing

**ghidra_cobaltstrike_resolve_api_hashes_by_comments.py** is a Jython script to automatically find hashes and add resolved APIs as comments to Ghidra

**ghidra_cobaltstrike_resolve_api_hashes_by_createrefs.py** does the same but applies external references, it is recommended to add [winapi_64.gdt](https://github.com/0x6d696368/ghidra-data/blob/master/typeinfo/winapi_64.gdt) to the type libraries.

**python3_cobaltstrike_api_resolve.py** is a standalone Python3 script, usage below.

Usage: `python python3_cobaltstrike_api_resolve.py 0xCAFEBABE`
Or: `python python3_cobaltstrike_api_resolve.py CAFEBABE`