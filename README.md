# hedgehog-tools
 
Repo of smaller scripts for malware analysis, deobfuscation and configuration extraction

## AgentTesla Config Extractor

### Requirements

The script uses dnlib. This line of the script must point to the dnlib binary on your system:

`clr.AddReference(r"dnlib.dll")`

You need a .NET Runtime on your system. Install it and run

`pip install -r requirements.txt`

### Usage

`python AgentTesla_config_extractor.py <folder_with_samples>`

Configs will be placed or appended to a file named agenttesla_configs.txt

For sample hashes look at the extracted configs.

Works on non-packed samples, so use unpacme or similar before applying the extractor.

## AllCome Clipbanker Config Extractor

Usage:

`python allcome_extractor.py <sample>`
  
Reference: https://twitter.com/3xp0rtblog/status/1486368999919300611
  
Sample: https://bazaar.abuse.ch/sample/f234b6d1801e1d4105de18a74ecd99f64cbdd7c47d6079bb2994d38ed7b0de44/

## NightHawk String Decoder

IDAPython script that adds comments with decoded string contents into the idb. Needs polishing as it misses some strings.

Tested on samples:

* https://bazaar.abuse.ch/sample/0551ca07f05c2a8278229c1dc651a2b1273a39914857231b075733753cb2b988/

* https://bazaar.abuse.ch/sample/9a57919cc5c194e28acd62719487c563a8f0ef1205b65adbe535386e34e418b8/
