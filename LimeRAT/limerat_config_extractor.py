# Author: Karsten Hahn @ GDATA CyberDefense
# Twitter: @struppigel
# Extract config of LimeRAT

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
import string
from Crypto.Cipher import AES
clr.AddReference(r"dnlib.dll")

import dnlib
from dnlib.DotNet import *
from dnlib.DotNet.Emit import OpCodes

def file_hash(afile):
    hash = ""
    with open(afile, 'rb') as f:
        hash = sha256(f.read()).hexdigest()
    return hash

def is_config(method):
    if not method.Name == '.cctor': 
        return False
    pattern = ["ldstr", "stsfld", "ldstr", "stsfld", "ldstr", "stsfld","ldstr", "stsfld", "ldstr", "stsfld", "ldstr" ,
                "call", "stsfld", "ldstr" ,"call", "stsfld", "ldstr" ,"call", "stsfld", "ldstr" ,"call"]
    if method.HasBody:
        if len(method.Body.Instructions) >= len(pattern):
            instr = [x.OpCode.Name for x in method.Body.Instructions]
            if instr[:len(pattern)] == pattern:
                return True
    return False

def find_config_method(module):
    for t in module.GetTypes():
        for m in t.Methods:
            if is_config(m):
                return m
    print("no config method found")
    return None

def extract_config(afile):
    try:
        module = dnlib.DotNet.ModuleDefMD.Load(afile)
        method = find_config_method(module)
        if not method: return ""
        config_list = []
        last_string = ""
        for instr in method.Body.Instructions:
            if instr.OpCode == OpCodes.Ldstr:
                last_str = instr.Operand
                if last_str == "": last_str = '<empty>'
            if instr.OpCode == OpCodes.Stsfld:
                config_list.append(str(last_str))
        return config_list
    except:
        traceback.print_exc()
        return []

def config_list_to_dict(config_list):
    config = dict()
    config['Pastebin'] = config_list[0]
    config['EncryptionKey'] = config_list[1]
    config['ENDOF'] = config_list[2]
    config['SPL'] = config_list[3]
    config['EXE'] = config_list[4]
    config['USB'] = config_list[5]
    config['PIN'] = config_list[6]
    config['ANTI'] = config_list[7]
    config['DROP'] = config_list[8]
    config['PATH1'] = '%' + config_list[9] + '%'
    config['PATH2'] = config_list[10]
    config['fullpath'] = config['PATH1'] + config['PATH2'] + config['EXE']
    config['BTC_ADDR'] = config_list[12]
    config['DWN_CHK'] = config_list[13]
    config['DWN_LINK'] = config_list[14]
    config['Delay'] = config_list[15]
    return config

def defang_ip(ip):
    return defang(ip.replace('.', '(.)', 1).replace(':','(:)', 1))


def defang(txt):
    return txt.replace('http:','hxxp:').replace('https:', 'hxxps:').replace('www.', 'www(.)')

def write_config_to_file(config, out_file):
    with open(out_file, 'a', encoding='utf-8') as f:
        f.write("------------------------------------------\n\n" + defang(config) + "\n")

def retrieve_pastebin_text(pastebin):
    if not pastebin.startswith('https://pastebin.com/raw/'): return '<no pastebin link>'
    try:
        data = urllib.request.urlopen(pastebin).read(200)
        ip = data.decode('utf-8').split('\n')[0]
        return ip
    except:
        return "<could not retrieve>"

def decode_pastebin_url(config_list):
    if len(config_list) < 2: return "config contains no key" 
    pastebin_encoded = base64.b64decode(config_list[0])
    key_str = config_list[1]
    md5_kstr = hashlib.md5(key_str.encode('UTF-8')).digest()
    key = md5_kstr[:15] + md5_kstr[:16] + bytearray([0])
    cipher = AES.new(key, AES.MODE_ECB)
    try:
        pastebin = cipher.decrypt(pastebin_encoded)
        pastebin = str(pastebin, 'utf-8').strip()
        printable = set(string.printable)
        pastebin = ''.join(filter(lambda x: x in printable, pastebin))
        return pastebin
    except:
        traceback.print_exc()
        return config_list[0]

def convert_to_config_string(config_list, afile):
    if len(config_list) < 16: return "<no config>"
    config_dict = config_list_to_dict(config_list)
    config_str = "\n".join(['{k}: {v}'.format(k=k,v=v) for k, v in config_dict.items()])
    pastebin = decode_pastebin_url(config_list)
    c2 = retrieve_pastebin_text(pastebin)
    pastebin_str = "decrypted pastebin retrieval URL: " + defang_ip(pastebin) + "\n"
    c2_str = "retrieved c2 ip: " + defang_ip(c2) + "\n"
    config_str = "extracted from " + file_hash(afile) + "\n\n" + pastebin_str + c2_str + config_str
    return config_str
    

def main(folder):
    if folder.endswith('\\'): 
        folder = folder[:-1]

    configs = []
    for directory, subdirs, files in os.walk(folder):
        for pfile in files:
            print('checking', pfile)
            afile = os.path.join(directory, pfile)
            config_list = extract_config(afile)
            if len(config_list) >= 16: 
                config_str = convert_to_config_string(config_list, afile)
                configs.append(config_str)
                write_config_to_file(config_str, 'limerat_configs.txt')

    for config in configs:
        print()
        print('-------------------------------------')
        print()
        print(config)
        print()
    print('Configs extracted: ' + str(len(configs)))

if __name__ == '__main__':
    if len(sys.argv) == 0:
        print("please provide a folder name")
    else:
        main(sys.argv[1])