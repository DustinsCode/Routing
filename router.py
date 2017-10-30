#!/usr/bin/python

import socket
#import os
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
		sys.exit(-1)


        #  https://stackoverflow.com/questions/24415294/python-arp-sniffing-raw-socket-no-reply-packets

        while True:

		packet = s.recvfrom(1024)

                #Ethernet Header Stuff
		ethHeader = packet[0][0:14]
                ethContents = struct.unpack("!6s6s2s", ethHeader)

                destinationMac = ethContents[0]
                sourceMac = ethContents[1]
                ethType = ethContents[2]


                # Eth type should be 0806 for arp request as shown in wireshark
                # If packet isn't this, skip dat boi
                if ethType == 'x08\x06':

                    #ARP header stuff
                    arpHeader = packet[14:42]
                    arpContents = struct.unpack("!2s2s1s1s2s6s4s6s4s", arpHeader)

                    opCode = arpContents[4]
                    sourceIP = arpContents[6]
                    targetMac = arpContents[7]
                    targetIP = arpContents[8]



                    print "##########ARP_REQUEST##########"
                    print "##########ETH_HEADER###########"
                    print "Destination MAC:     ", binascii.hexlify(destinationMac)
                    print "Source MAC:          ", binascii.hexlify(sourceMac)
                    print "Eth Type:            ", binascii.hexlify(ethType)
                    print "###############################"
                    print "##########ARP_HEADER##########"
                    print "Op code:             ", binascii.hexlify(opCode)
                    print "Source MAC:          ", binascii.hexlify(sourceMac)
                    print "Source IP:           ", binascii.hexlify(sourceIP)
                    print "Target MAC:          ", binascii.hexlify(targetMac)
                    print "Target IP:           ", binascii.hexlify(targetIP)
                    print "\n\n\n"


                    #obtain list of addresses on the network
                    networkList = netifaces.interfaces()



                #if ICMP
                elif ethType == 'x08\x00':
                    #do icmp stuff
                    print "icmp request"




router()
