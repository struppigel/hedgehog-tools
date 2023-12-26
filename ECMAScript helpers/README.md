# ECMAScript helpers

Scripts for JScript, JavaScript deobfuscation.

## Requirements

Install NodeJS and npm

Execute this to install required packages

`npm.exe install -save-dev @babel/core commander`


## extract_called_functions.js

Recursively extracts all called functions based on a given start function. 

Will also extract assignments to variables which are not in those functions but used by them, however this is still somewhat tailored to Gootloader and may not get all relevant assignments.

### Usage

`extract_called_functions.js -f <sample> -s <function name>`

The result will be saved in <sample>.extracted