# hedgehog-tools
 
Repo of smaller scripts for malware analysis, deobfuscation and configuration extraction.

See README.md files within the folders for more details.

## Overview of generic tools

| Folder                   | Script                                | Depends | Static | Purpose                                                                    |
|--------------------------|---------------------------------------|---------|--------|----------------------------------------------------------------------------|
| ECMAScript helpers       | extract_called_functions.js           | NodeJS  |   ✅   |   JavaScript deobfuscation. Recursively extracts all called functions based on a given start function | 
| ECMAScript helpers       | rename_identifiers.js                 | NodeJS  |   ✅   |   JavaScript deobfuscation. Renames all identifiers to `ren_<number>`      | 
| Ghidra scripts           | PropagateExternalParametersX64.java   | Java    |   ✅   |   x64 variant of Ghidra-provided 32-bit PropagateExternalParameters script |
| Ghidra scripts           | move_callers_to_malware_namespace.py  | Jython  |   ✅   |   Moves all caller functions into `malware::` namespace                    |
| Nuitka                   | nuitka_extractor.py                   | Python  |   ✅   |   Extracts Nuitka onefile executables                                      |
| Python helper scripts    | extract_export_symbols.py             | Python  |   ✅   |   Obtains a list of symbols for all exported functions of a DLL            |
| Python helper scripts    | monitor_and_dump_changed_files.py     | Python  |   ⛔   |   Monitors changes within a given folder and dumps the changed files       |
| PyInstaller mod          | pyinstaller-mod-extractor-ng.py       | Python  |   ✅   |   Extracts PyInstaller files that use a custom stub and custom encryption  |
| RenPy                    | rpa_extractor.py                      | Python  |   ✅   |   Extracts RenPy archives (`.rpa`, `.rpi`)                                 | 
| Shellcode2PE             | shellcode_to_pe.py                    | Python  |   ✅   |   Converts raw shellcode into a PE file with shellcode as entry point      | 


## Overview of family based deobfuscators

| Target                    | Depends                | Static | Config extraction | C2 extraction | Deobfuscation | Unpacking | Handles packed sample |
| ------------------------- | ---------------------- | ------ | ----------------- | ------------- | ------------- | --------- | --------------------- |
| AgentTesla (OriginLogger) | Python, dnlib          |   ✅   | ✅                | ✅            | ⛔            | ⛔        | ⛔                    |
| AllCome                   | Python                 |   ✅   | ✅                | ✅            | ⛔            | ⛔        | ⛔                    |
| BadSpace  | IDAPython (IDA 8), HexRays decompiler  |   ✅   | ⛔                | ⛔            | ✅            | ⛔        | ⛔                    |
| BeamNG Mod Malware        | Ghidra, Jython         |   ✅   | ⛔                | ⛔            | ✅            | ⛔        | ⛔                    |
| BrowserFixer              | .NET C#                |   ⛔   | ⛔                | ⛔            | ✅            | ⛔        | ⛔                    |
| CobaltStrike              | Python, Ghidra, Jython |   ✅   | ⛔                | ⛔            | ✅            | ⛔        | ⛔                    |
| Dave                      | IDAPython (IDA 9)      |   ✅   | ⛔                | ⛔            | ✅            | ⛔        | ⛔                    |
| EvilConwi                 | Python                 |   ✅   | ✅                | ⛔            | ⛔            | ⛔        | ⛔                    |
| GootLoader                | JavaScript, NodeJS     |   ✅   | ✅                | ✅            | ✅            | ✅        | ✅                    |
| LimeRAT                   | Python, dnlib          |   ✅   | ✅                | ✅            | ⛔            | ⛔        | ⛔                    |
| LummaStealer              | Ghidra, Jython         |   ✅   | ⛔                | ⛔            | ✅            | ⛔        | ⛔                    |
| NightHawk                 | IDAPython (IDA 8)      |   ✅   | ⛔                | ⛔            | ✅            | ⛔        | ✅                    |
| PEUnion                   | Python, Speakeasy      |   ✅   | ⛔                | ⛔            | ⛔            | ✅        | ✅                    |
| PrivateLoader             | IDAPython (IDA 8)      |   ✅   | ⛔                | ⛔            | ✅            | ⛔        | ⛔                    |
| Qakbot                    | Python                 |   ✅   | ✅                | ✅            | ✅            | ⛔        | ⛔                    |
| RokRAT                    | Python, Ghidra, Jython |   ✅   | ⛔                | ⛔            | ✅            | ⛔        | ✅                    |
| Virut                     | Python, Ghidra, Jython |   ✅   | ⛔                | ⛔            | ✅            | ⛔        | ✅                    |
| XWormRAT                  | Python, dnlib          |   ✅   | ✅                | ✅            | ⛔            | ⛔        | ⛔                    |

## Licensing

Unless stated otherwise, tools in this repository are licensed under
the MIT License (see LICENSE).

Some tools are derived from GPLv3 projects and therefore remain licensed
under GPLv3+. These tools contain their own LICENSE files and headers.