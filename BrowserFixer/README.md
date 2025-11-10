## Browser Fixer string decrypter

This script is initially based on Dump_GUY's [ConfuserEx2_String_Decryptor](https://github.com/Dump-GUY/ConfuserEx2_String_Decryptor).

It uses [AsmResolver](https://github.com/Washi1337/AsmResolver) and [Harmony2](https://github.com/pardeike/Harmony).

WARNING: It dynamically executes code, thus, it is unsafe and must only be run in a malware lab.

It decrypts the strings of Browser Fixer, BuyBricksAi and similar malware.

* test sample: 9d59ab9bd34c3146c086feb0605048005433d4e9aba32516c07dbd02dd48b240 BrowserFixerSetup
* test sample: 6981b024f5614d6a9e9f154d4e985b728dd09dcf2c716c2219235df61ed97acc BuyBricksAiSetup

### Key characteristcs of sample's decryption functions

* one static non-generic string decryption function that takes an integer as input
* MBA in string decryption
* decrypt function returns 'X0X' if it detects reflection usage
* reflection usage detection: checks types of methods in the stackframe and checks the assembly that called the function

### How the decrypter works

* dynamically executes the decrypt function with AsmResolver
* defeats reflection usage detection via Harmony2 hooks
* patches IL instructions that call the decrypt function with the decrypted string
* saves a cleaned version of the assembly to <filename>-cleaned
