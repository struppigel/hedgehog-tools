# GootLoader JS Unpacker and C2 Extractor

## Why

This was a project to learn AST manipulation with babel and JavaScript.

So it is likely that this is not the best code because I am a JavaScript noob.

The script is static, it does not execute any of the manipulated code.

## Requirements

Install NodeJS and npm

Execute this to install required packages

`npm.exe install -save-dev @babel/core commander`

## Usage

`node.exe gootloader_decoder.js -f <sample>`

This will unpack the Gootloader script layers to _transpiled.layer\<nr\>.js_. After that it will attempt to find C2 data. Even if some of it fails, it should serve in saving some unpacking steps.

The very first transpiled layer is the extraction of just the relevant functions which are often buried in > 6000 lines of code. This step allows manual analysis of the initial code, e.g., in case of debugging the script but also to see how the layer works.

Starting from the second layer the unpacker will determine the responsible decrypt function, the key and a decoding constant which is changed in every sample.

It will attempt to extract C2's at the last layer, which it currently assumes to be either the third or the 6th (as these are the samples I got).

Note: Some of the layers will be wrapped into a function named _gldr()_. This function is **not** part of the malware but the decoder. It is necessary where gootloader dynamically wraps the unpacked code into an unnamed function. Since the body contains the a return, the AST can only be parsed with this wrapped function.

## Samples 


`1bc77b013c83b5b075c3d3c403da330178477843fc2d8326d90e495a61fbb01f` --> complete, has 3 layers

`08f06fc48fe8d69e4ab964500150d1b2f5f4279fea2f76fdfcefd32266dfa1af` --> complete, has 6 layers

`320b4d99c1f5fbc3cf1dfe593494484b1d4cb1ac7ac1f6266091e85ef51b4508` --> complete, has 6 layers

`445a5c6763877994206d2b692214bb4fba04f40a07ccbd28e0422cb1c21ac95b` --> complete, has 6 layers

`cbd826f59f1041065890cfe71f046e59ae0482364f1aaf79e5242de2246fb54b` --> complete, has 6 layers

`b34bcf097ad6ab0459bc6a4a8f487ca3526b6069ec01e8088fd4b00a15420554` --> complete, has 6 layers

`1b8b2fbdff9e4109edae317c4dd8cef7bb7877d656e97a3dd0a1e8c0c9d72b0b` --> only unpacks until layer 6

## Example Output

Decoded last layer with C2 data:

![Extracted layer 6](gootloader_decoded_c2layer.png)

Output of unpacking and extraction:

![GootLoader Decoder Example Output](gootloader_decoder_output.png)

