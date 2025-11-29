# Lumma API resolver

This is a Ghidra Jython script. It resolves LummaStealer API hashes calculated with MurmurHash2.

I tested it on an unpacked sample f33a6585faa522f1f03b4bacbd77cb5adc0d1ad54223b89dc8f6ebb05edfe000

This is an old Lumma sample from 2022, it is ideal for educational purposes in resolving API hashes.

It is also an example script that features a bit more than just adding comments.

## The script will do the following:

* add comments with resolved API hash
* create an enum named LummaAPIHash (not that useful actually, I did that because it's something you do in IDA instead of equates)
* create equates for resolved API hashes -- that means the hash values will be represented by the api name instead of the integer
* create labels for the resolved function variables -- that means subsequent function calls have the resolved API name
