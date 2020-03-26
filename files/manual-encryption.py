#!/usr/bin/env python
# -*- coding: utf-8 -*-
# source: https://stackoverflow.com/questions/23312571/fast-xoring-bytes-in-python-3
#         https://stackoverflow.com/questions/30092226/how-to-calculate-crc32-with-python-to-match-online-results


""" Encryption WEB"""

__author__      = "Stefan Dejanovic, Nathanael Mizutani"
__copyright__   = "Copyright 2020, HEIG-VD"
__version__ 	= "1.0"

from scapy.all import *
import binascii
import zlib
from rc4 import RC4

# bytes xor function
def bxor(b1, b2): # use xor for bytes
    parts = []
    for b1, b2 in zip(b1, b2):
        parts.append(bytes([b1 ^ b2]))
    return b''.join(parts)

# Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

# Text defined
text = b'Je mappelle stefan'

# Read the template
arp = rdpcap('arp.cap')[0] 

# Generate the ICV with CRC-32
icv = hex(zlib.crc32(text) & 0xffffffff)

# Concatenation text + ICV
text = "%s%s" % (text,icv)
text = bytes(text, 'utf8')

# Encryption iv + key 
tmp = "%s%s" % (arp.iv,key)
cipher = RC4(key, streaming=False)
ciphertext=cipher.crypt(bytes(tmp, 'utf8'))

# Xor the text with ICV with the ciphertext from iv + key
ciphertext = bxor(ciphertext, text)

# Concatenation the IV and the finalciphertext
#finalCipher = str(arp.iv, 'utf-8') + str(ciphertext, 'latin-1')

# Modify the arp parameter
arp.wepdata = str(ciphertext, 'latin-1')
arp.icv = int(icv, 0)

# Create the new cap file
wrpcap("test.cap", arp)

