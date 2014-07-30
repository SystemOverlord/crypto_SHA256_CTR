crypto_SHA256_CTR
=================

This is a small c++/QT class which is written for encrypting QStrings and binary data.
I only wrote it because i wanted to improve my programming skills.
This encryption is INSECURE!

To encrypt and decrypt i use the same function:
I use sha256 in counter mode to encrypt data.
The encryption key, a salt/nounce and a counter are hased with sha256.
The sha256 output is xored with a 256bit data block.

Please send feedback (sugestions, ideas, respond and bugs) to system.overlord@magheute.net

