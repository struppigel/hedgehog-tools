# Author: Karsten Hahn @ GDATA CyberDefense
# Twitter: @struppigel
# Extract config of AgentTesla, OriginLogger variant

import os
import shutil
import sys
import subprocess
import clr
import traceback
from hashlib import sha256
clr.AddReference(r"dnlib.dll")

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

def main(folder):
    print(folder)
    if folder.endswith('\\'): 
        folder = folder[:-1]

    configs = []
    for directory, subdirs, files in os.walk(folder):
        for pfile in files:
            print(pfile)
            config = extract_config(os.path.join(directory, pfile))
            if len(config.strip()) > 0: 
                configs.append(config)
                write_config_to_file(config, 'agenttesla_configs.txt')

    #shutil.rmtree(temp_dumps)
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
