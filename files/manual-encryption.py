#!/usr/bin/env python
# -*- coding: utf-8 -*-
# source: https://stackoverflow.com/questions/30092226/how-to-calculate-crc32-with-python-to-match-online-results


""" Encryption WEB"""

__author__      = "Stefan Dejanovic, Nathanael Mizutani"
__copyright__   = "Copyright 2020, HEIG-VD"
__version__ 	= "1.0"

from scapy.all import *
import binascii
from rc4 import RC4

# Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

# Text defined
text = b'AAAAAA'*6

# Read the template
arp = rdpcap('arp.cap')[0]

# Generate the ICV with CRC-32
icv = struct.pack('<l', binascii.crc32(text))

# Concatenation text + ICV
plaintext = text + icv

# Encryption RC4•
seed = arp.iv+key
cipher = RC4(seed, streaming=False)
ciphertext=cipher.crypt(plaintext)

# Modify the arp parameter
arp.wepdata = ciphertext
arp.icv = struct.unpack('!L', ciphertext[-4:])[0]

# Create the new cap file
wrpcap("test.cap", arp)


