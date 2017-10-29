#!/usr/bin/python

import socket
import os
import sys
import netifaces
import struct
import binascii

def router():
	
	try:
		s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x003))
		print "Socket connected"
	except socket.error, msg:
		print msg
		return











router()
