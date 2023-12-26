## AllCome Clipbanker Config Extractor

Usage:

`python allcome_extractor.py <sample>`
  
Reference: https://twitter.com/3xp0rtblog/status/1486368999919300611
  
Sample: https://bazaar.abuse.ch/sample/f234b6d1801e1d4105de18a74ecd99f64cbdd7c47d6079bb2994d38ed7b0de44/

## LimeRAT Config Extractor

### Requirements

The script uses dnlib. This line of the script must point to the dnlib binary on your system:

`clr.AddReference(r"dnlib.dll")`

You need a .NET Runtime on your system. Install it and run

`pip install -r requirements.txt`
