# Author: Karsten Hahn @ GDATA CyberDefense
# Twitter: @struppigel
# Extract config of AgentTesla, OriginLogger variant

import os
import sys
import clr
import argparse
import traceback
from hashlib import sha256
import pathlib

curr_dir = pathlib.Path(__file__).parent.resolve()
clr.AddReference(os.path.join(curr_dir, "dnlib.dll"))

import dnlib
from dnlib.DotNet import *
from dnlib.DotNet.Emit import OpCodes

def file_hash(afile):
    hash = ""
    with open(afile, 'rb') as f:
        hash = sha256(f.read()).hexdigest()
    return hash

def extract_config(afile):
    try:
        module = dnlib.DotNet.ModuleDefMD.Load(afile)
        
        config_type = next(t for t in module.GetTypes() for f in t.Fields if "EnableKeylogger" in str(f.Name))
        if config_type == None: return ""
        
        method = next(m for m in config_type.Methods if m.Name == ".cctor")
        if method == None: return ""
        
        config = ""
        last_string = ""
        for instr in method.Body.Instructions:
            if instr.OpCode == OpCodes.Ldstr:
                last_str = instr.Operand
                if last_str == "": last_str = "<empty>"
            if instr.OpCode == OpCodes.Stsfld:
                config += str(instr.Operand.Name) + ": " + str(last_str) + "\n"
        return "extracted from " + file_hash(afile) + "\n\n" + config
    except:
        traceback.print_exc()
        return ""

def defang(txt):
    return txt.replace('http:','hxxp:').replace('https:', 'hxxps:').replace('www.', 'www(.)')

def write_config_to_file(config, out_file):
    with open(out_file, 'a', encoding='utf-8') as f:
        f.write("------------------------------------------\n\n" + defang(config) + "\n")
        
def extract_config_from_sample(sample):
    config = extract_config(sample)
    if len(config.strip()) > 0:
        write_config_to_file(config, 'agenttesla_configs.txt')
        return config
    return None

def main():
    parser = argparse.ArgumentParser(description='QBot config extractor and string decrypter')
    parser.add_argument('path', help='file or folder to decode')
    args = parser.parse_args()
    path = args.path
    configs = []
    
    if os.path.isfile(path):
        afile = path
        config = extract_config_from_sample(afile)
        if config: configs.append(config)
    elif os.path.isdir(path):
        folder = path
        for directory, subdirs, files in os.walk(folder):
            for pfile in files:
                config = extract_config_from_sample(os.path.join(directory, pfile))
                if config: configs.append(config)
    else:
        sys.stderr.write("Error: given path is not a directory nor a file")
        sys.exit(1)

    for config in configs:
        print()
        print('-------------------------------------')
        print()
        print(config)
        print()
    print('Configs extracted: ' + str(len(configs)))

if __name__ == '__main__':
    main()
