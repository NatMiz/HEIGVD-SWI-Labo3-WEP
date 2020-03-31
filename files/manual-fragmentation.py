#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Sources : - https://github.com/secdev/scapy/blob/652b77bf12499451b47609b89abc663aa0f69c55/scapy/layers/inet.py#L891
#           - http://www.packetstan.com/2011/04/crafting-overlapping-fragments.html

""" Fragmentation WEP"""

__author__      = "Stefan Dejanovic, Nathanael Mizutani"
__copyright__   = "Copyright 2020, HEIG-VD"
__version__ 	= "1.0"

from scapy.all import *
from rc4 import RC4
import binascii
import zlib
import math

# Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

# Text defined
# Each fragment will have 36 bytes of data to be coherent with the template
texts = []
texts.append(b'AAAAAA'*6)
texts.append(b'BBBBBB'*6)
texts.append(b'CCCCCC'*6)

# Read the template
arp = rdpcap('arp.cap')[0]

# List to store the fragments
lst = []

# Define the parameter for RC4
seed = arp.iv+key
cipher = RC4(seed, streaming=False)

# Loop to create all fragments
for x in range(0,len(texts)):
    
    # Retrieving the template
    fragment = arp.copy()
    
    # Generating the icv for each fragment
    icv = struct.pack('<l', binascii.crc32(texts[x]))
    
    # Concatenation text + ICV
    plaintext = texts[x] + icv
    
    # Encryption RC4
    ciphertext = cipher.crypt(plaintext)
    fragment.icv = struct.unpack('!L', ciphertext[-4:])[0]
    fragment.wepdata = ciphertext
    fragment.SC += x
    
    # Check if it is the last fragment
    if x != len(texts) -1:
        fragment.FCfield = 0x845
    else:
        fragment.FCfield = 0x841
    
    # Add the fragment to the list
    lst.append(fragment)

# Create the new cap file
wrpcap("test-fragmentation.cap", lst)
