# hedgehog-tools
 
Repo of smaller scripts for malware analysis, deobfuscation and configuration extraction

## Overview

| Target                    | Depends                | Static | Config extraction | C2 extraction | Deobfuscation | Unpacking | Handles packed sample |
| ------------------------- | ---------------------- | ------ | ----------------- | ------------- | ------------- | --------- | --------------------- |
| AgentTesla (OriginLogger) | Python, dnlib          |   ✅   | ✅                | ✅            | ⛔            | ⛔        | ⛔                    |
| AllCome                   | Python                 |   ✅   | ✅                | ✅            | ⛔            | ⛔        | ⛔                    |
| BadSpace                  | IDAPython, HexRays decompiler  |   ✅   | ⛔        | ⛔            | ✅            | ⛔        | ⛔                    |
| CobaltStrike              | Python, Ghidra, Jython |   ✅   | ⛔                | ⛔            | ✅            | ⛔        | ⛔                    |
| GootLoader                | JavaScript, NodeJS     |   ✅   | ✅                | ✅            | ✅            | ✅        | ✅                    |
| LimeRAT                   | Python, dnlib          |   ✅   | ✅                | ✅            | ⛔            | ⛔        | ⛔                    |
| LummaStealer              | Ghidra, Jython         |   ✅   | ⛔                | ⛔            | ✅            | ⛔        | ⛔                    |
| NightHawk                 | IDAPython              |   ✅   | ⛔                | ⛔            | ✅            | ⛔        | ✅                    |
| PEUnion                   | Python, Speakeasy      |   ✅   | ⛔                | ⛔            | ⛔            | ✅        | ✅                    |
| PrivateLoader             | IDAPython              |   ✅   | ⛔                | ⛔            | ✅            | ⛔        | ⛔                    |
| Qakbot                    | Python                 |   ✅   | ✅                | ✅            | ✅            | ⛔        | ⛔                    |
| XWormRAT                  | Python, dnlib          |   ✅   | ✅                | ✅            | ⛔            | ⛔        | ⛔                    |

Additionally there is a folder called **ECMAScript helpers** with generic scripts for deobfuscation of JScript, JavaScript and similar.

**Shellcode2PE** converts a shellcode to a Portable Executable file with the shellcode at the entry point and ASLR disabled.

See README.md files within the folders for more.
