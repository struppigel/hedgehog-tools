# Shellcode to PE converter

Small script to allow easier shellcode debugging by converting the shellcode into a PE file. Supports Win 32 and Win 64 PE files. 
The resulting PE will have disabled ASLR and the shellcode at the entry point.

## Usage

usage 32-bit:

```
python shellcode_to_pe.py win32 C:\shellcode_file
```

usage 64-bit:

```
python shellcode_to_pe.py win64 C:\shellcode_file
```

## Limitations

The shellcode's size must be smaller than 0x2800 (32-bit) or 0x2A00 (64-bit) because those are section sizes of the respective PE stub.
This should be enough for most cases, though. 
