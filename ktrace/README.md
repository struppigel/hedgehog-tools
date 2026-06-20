# ktrace: Speakeasy-based Windows kernel-mode driver API tracer

AI note: This tool is fully vibe-coded (this readme is not). I created it by manually analyzing roughly 20 kernel mode rootkits and kernel mode drivers and verifying and improving the results. Focus is on making the output useful for as many samples as possible without tinkering on them yourself.

There are ton of command line switches, which the AI created to test adjustments and see whether they improve the overall output or not. The metric was how many different, non-repeating API calls it can trace successfully in a corpus of 100 kernel mode drivers with a 30 second timeout per sample.

## Preparation

Install speakeasy

```bash
pip install speakeasy-emulator
```

## Usage

General usage:


```bash
ktrace <driver.sys> [options]
```

Ignore most of the switches, these are the main ones, you will need:

| Flag | Default | Purpose |
|---|---|---|
| `--out OUTDIR` | `./ktrace_out` | output directory for the trace and log files |
| `--timeout N` | `300` | Speakeasy emulation timeout in seconds. |
| `--quiet` | off | Suppress stdout (still writes log/jsonl/meta). |
| `--fake-processes LIST` | empty | Create fake processes during emulation. Comma-separated. Presets: `av`, `common`, `all`. Or specify concrete processes like so: `msmpeng.exe,avp.exe` or `0x1004:msmpeng.exe` where the first part is the pid. |
| `--dump-mem DIR` | none | Dump every emulated memory region into `DIR/` |
| `--dump-files DIR ` | none | Dump files written by the driver into the `DIR/` |
| `--ghidra-export PATH.java` | none | Emit a self-contained Ghidra GhidraScript (.java) that ports the trace findings into your Ghidra db |