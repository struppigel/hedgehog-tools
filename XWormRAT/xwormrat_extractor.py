# Author: Karsten Hahn @ GDATA CyberDefense
# Twitter: @struppigel
# Extract config of XWormRAT

import os
import shutil
import sys
import subprocess
import clr
import traceback
import urllib.request
import hashlib
from hashlib import sha256
import base64
from string import printable
from Crypto.Cipher import AES
clr.AddReference("dnlib.dll")

import dnlib
from dnlib.DotNet import *
from dnlib.DotNet.Emit import OpCodes

def file_hash(afile):
    hash = ""
    with open(afile, 'rb') as f:
        hash = sha256(f.read()).hexdigest()
    return hash

def extract_config(afile):
    module = None
    try:
        module = dnlib.DotNet.ModuleDefMD.Load(afile)
        # Mutex is a must for this extractor because the config decryption relies on it
        config_type = next(t for t in module.GetTypes() for f in t.Fields if "Mutex" in str(f.Name))
        if config_type == None: return ""
        
        method = next(m for m in config_type.Methods if m.Name == ".cctor")
        if method == None: return ""
        
        config = dict()
        last_string = ""
        for instr in method.Body.Instructions:
            if instr.OpCode == OpCodes.Ldstr:
                last_str = instr.Operand
                if last_str == "": last_str = "<empty>"
            if instr.OpCode == OpCodes.Stsfld:
                key = str(instr.Operand.Name)
                value = str(last_str)
                if value.startswith("http") or value.startswith("www."): 
                   value = defang_ip(value)
                config[key] = value
        module.Dispose(True)
        config = decode_config_values(config)
        return config
    except:
        # traceback.print_exc()
        if module != None: module.Dispose(True)
        return dict()
    
def try_decode(config, item):
    if not "Mutex" in config: return None
    if not item in config: return None
    encoded = base64.b64decode(config[item])
    key_str = config["Mutex"]
    md5_kstr = hashlib.md5(key_str.encode('UTF-8')).digest()
    key = md5_kstr[:15] + md5_kstr[:16] + bytearray([0])
    cipher = AES.new(key, AES.MODE_ECB)
    try:
        decoded = cipher.decrypt(encoded)
        decoded = str(decoded, 'utf-8').strip()
        decoded = ''.join(filter(lambda x: x in printable, decoded))
        return decoded
    except:
        traceback.print_exc()
        return None
    
def retrieve_pastebin_text(pastebin):
    if not pastebin.startswith('https://pastebin.com/raw/'): return '<no pastebin link>'
    try:
        data = urllib.request.urlopen(pastebin).read(200)
        ip = data.decode('utf-8').split('\n')[0]
        return ip
    except:
        return "<could not retrieve>"
    
def decode(config, item, defang=False):
    val = try_decode(config, item)
    if val != None:
        config[item] = val
        if defang:
            config[item] = defang_ip(val)


def decode_config_values(config):
    decode(config, "PasteUrl", defang=False)
    if "PasteUrl" in config:
        paste_content = defang_ip(retrieve_pastebin_text(config["PasteUrl"]))
        config["PasteUrl content"] = paste_content
        config["PasteUrl"] = defang_ip(config["PasteUrl"])
    decode(config, "Host", defang=True)
    decode(config, "Hosts", defang=True)
    decode(config, "Port")
    decode(config, "KEY")
    decode(config, "SPL")
    decode(config, "USBNM")
    decode(config, "ChatID")
    decode(config, "Token")
    decode(config, "Sleep")
    decode(config, "Groub")
    decode(config, "InstallDir")
    decode(config, "InstallStr")
  
    return config

def defang_ip(ip):
    if "," in ip:
        ips = ip.split(",")
        return ",".join([defang_ip(i)] for i in ips)
    else:    
        return defang(ip.replace('.', '(.)', 1).replace(':','(:)', 1))

def defang(txt):
    return txt.replace('http:','hxxp:').replace('https:', 'hxxps:').replace('www.', 'www(.)')

def main(afile):
    print('checking', afile)
    config = extract_config(afile)
    print(config)
    print("done")

if __name__ == '__main__':
    if len(sys.argv) == 0:
        print("please provide a file name")
    else:
        main(sys.argv[1])