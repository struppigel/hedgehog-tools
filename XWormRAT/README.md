# XWormRAT Config Extractor

## Requirements

The script uses dnlib. This line of the script must point to the dnlib binary on your system:

`clr.AddReference(r"dnlib.dll")`

You need a .NET Runtime on your system. Install it and run

`pip install -r requirements.txt`

## Usage

`python xwormrat_extractor.py <sample>`


Works on non-packed samples, so use unpacme or similar before applying the extractor.
