# hedgehog-tools
 
Repo of smaller scripts for malware analysis, deobfuscation and configuration extraction

## Overview

| Target                    | Depends                | Static | Config extraction | C2 extraction | Deobfuscation | Unpacking | Handles packed sample |
| ------------------------- | ---------------------- | ------ | ----------------- | ------------- | ------------- | --------- | --------------------- |
| AgentTesla (OriginLogger) | Python, dnlib          |   ✅   | ✅                | ✅            | ⛔            | ⛔        | ⛔                    |
| AllCome                   | Python                 |   ✅   | ✅                | ✅            | ⛔            | ⛔        | ⛔                    |
| GootLoader                | JavaScript, NodeJS     |   ✅   | ✅                | ✅            | ✅            | ✅        | ✅                    |
| LimeRAT                   | Python, dnlib          |   ✅   | ✅                | ✅            | ⛔            | ⛔        | ⛔                    |
| NightHawk                 | IDAPython              |   ✅   | ⛔                | ⛔            | ✅            | ⛔        | ✅                    |
| Qakbot                    | Python                 |   ✅   | ✅                | ✅            | ✅            | ⛔        | ⛔                    |
| XWormRAT                  | Python, dnlib          |   ✅   | ✅                | ✅            | ⛔            | ⛔        | ⛔                    |

Additionally there is a folder called ECMAScript helpers with generic scripts for deobfuscation of JScript, JavaScript and similar.

See README.md files within the folders for more.
