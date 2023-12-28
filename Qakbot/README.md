# QBot/Qakbot configuration extractor

Extracts Qakbot configuration data and C2 ips.

## Usage

`python qbot_extractor.py <sample_folder>`

## Output

terminal:

![screenshot_output.png]

config file: see qbot_configs.txt

## Resources

Some of the code is from these:

* https://github.com/OALabs/Lab-Notes/blob/main/Qakbot/qakbot.ipynb
* https://n1ght-w0lf.github.io/malware%20analysis/qbot-banking-trojan/

## Samples

* 76d9e9e59d2a939f773e953a843906284bb52a14eb573c42c0b09402b65fa430
* 670e990631c0b98ccdd7701c2136f0cb8863a308b07abd0d64480c8a2412bde4
* 84669a2a67b9dda566a1d8667b1d40f1ea2e65f06aa80afb6581ca86d56981e7

## TODO

* add string decryption as output option
* add single file usage
* support IPv6