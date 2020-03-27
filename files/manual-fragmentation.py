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

# Fragment a packet
# pkt : packet template
# data : packet data
# frag_num : Number of fragment desired
# Return a list of the fragments
def fragmentation(pkt, data, frag_num):
    lst = [] # List for the fragments
    pkt.show()

    return lst

# Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

# Text defined
# Each fragment will have 36 bytes of data to be coherent with the template
text1 = b'AAAAAA'*6
text2 = b'BBBBBB'*6
text3 = b'CCCCCC'*6

# Read the template
arp = rdpcap('arp.cap')[0]

# Generating the icv for each fragment
icv1 = struct.pack('<l', binascii.crc32(text1))
icv2 = struct.pack('<l', binascii.crc32(text2))
icv3 = struct.pack('<l', binascii.crc32(text3))

# Concatenation text + ICV
plaintext1 = text1 + icv1
plaintext2 = text2 + icv2
plaintext3 = text3 + icv3

# Encryption RC4
seed = arp.iv+key
cipher = RC4(seed, streaming=False)

ciphertext1 = cipher.crypt(plaintext1)
ciphertext2 = cipher.crypt(plaintext2)
ciphertext3 = cipher.crypt(plaintext3)

# List to store the fragments
lst = []

fragment1 = arp.copy()
# Modifying arp parameters
fragment1.icv = struct.unpack('!L', ciphertext1[-4:])[0]
fragment1.wepdata = ciphertext1
fragment1[RadioTap].Fragmentation = 1
fragment1.FCfield = 0x845
lst.append(fragment1)

fragment2 = arp.copy()
# Modifying arp parameters
fragment2.icv = struct.unpack('!L', ciphertext2[-4:])[0]
fragment2.wepdata = ciphertext2
fragment1[RadioTap].Fragmentation = 1
fragment2.SC += 1
fragment2.FCfield = 0x845
lst.append(fragment2)

fragment3 = arp.copy()
# Modifying arp parameters
fragment3.icv = struct.unpack('!L', ciphertext3[-4:])[0]
fragment3.wepdata = ciphertext3
fragment1[RadioTap].Fragmentation = 1
fragment3.SC += 2
fragment3.FCfield = 0x841
lst.append(fragment3)

# Create the new cap file
wrpcap("test-fragmentation.cap", lst)
