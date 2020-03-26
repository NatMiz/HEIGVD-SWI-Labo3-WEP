#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Sources : -https://github.com/secdev/scapy/blob/652b77bf12499451b47609b89abc663aa0f69c55/scapy/layers/inet.py#L891

""" Fragmentation WEP"""

__author__      = "Stefan Dejanovic, Nathanael Mizutani"
__copyright__   = "Copyright 2020, HEIG-VD"
__version__ 	= "1.0"

from scapy.all import *
from rc4 import RC4
import binascii
import zlib

