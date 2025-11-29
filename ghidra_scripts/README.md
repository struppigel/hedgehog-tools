# Ghidra scripts
 
Collection of small helper scripts for Ghidra.

## PropagateExternalParametersX64.java

This script is the x64 variant of the PropagateExternalParameters.java script / analysis. 
The 32 bit version of the script is available per default in Ghidra in: https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/ghidra_scripts/PropagateExternalParametersScript.java 

The script propagates Windows external and library function parameter names and types. It puts the parameter names and types in the comments next to the pushes before a function call. It currently does not check for branches in the middle of a series of parameters.

## move_callers_to_malware_namespace.py

I like to put all malware-related functions into the `malware::` namespace to better distinguish between library code and malware code.

The scripts asks for a function address and will move all caller functions into this namespace.
Use it on commonly called malware-specific functions, e.g., an api resolve or string decryption function.