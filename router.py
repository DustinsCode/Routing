#!/usr/bin/python

import socket
#import os
import sys
import netifaces
import struct
import binascii

'''
Virtual Router Project

@author Dustin Thurston
@author Ryan Walt
'''

'''
Finds the MAC address of the router

@return
'''
global listIP1
global listIP2

def findMac(IP):
	#obtain list of addresses on the network
	networkList = netifaces.interfaces()
	print networkList
	for iface in networkList:
		addr = netifaces.ifaddresses(iface)[2][0]['addr']
		mac = netifaces.ifaddresses(iface)[17][0]['addr']
		print addr
		print mac
		#print socket.inet_ntoa(targetIP)
		if addr == socket.inet_ntoa(IP):
			return binascii.unhexlify(mac.replace(':', ''))

	return "MAC_NOT_FOUND"

def findNextHop(iplist, destIp):
	for entry in iplist:
		ipNum = entry[0].spit('/')
		destIpList = destIP.split('.')

		#checking 16 and 24 bit patterns
		if ipNum[1] == 16:
			newIpList = ipNum.split('.')
			if newIpList[0-1] == destIpList[0-1]:
				return entry[2]
		elif ipNum[1] == 24:
			newIpList = ipNum.split('.')
			if newIpList[0-2] == destIpList[0-2]:
				return entry[2]
	return False

def getRoutingList():
	table1 = open("r1-table.txt", "r")
	table2 = open("r2-table.txt", "r")
	listIP1 = table1.read().replace("/", " ").split("\n")
	listIP2 = table2.read().replace("/", " ").split("\n")
	print listIP1
	print listIP2

def makeArpHeader(reply, hwareType, pcType, hwareSize, pcSize, srcMac, srcIp, destMac, destIp):

	if reply is True:
		opCode = '\x00\x02'

	else:
		opCode = '\x00\x01'
		nextHop = findNextHop(listIP1, destIp)
		if nextHop is False:
			nextHop = findNextHop(listIP2, destIp)


	arpHeader = struct.pack("2s2s1s1s2s6s4s6s4s", hwareType, pcType, hwareSize, pcSize,
		opCode , srcMac, srcIp, destMac, destIp)

	return arpHeader

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
                if ethType == '\x08\x06':

                    #ARP header stuff
                    arpHeader = packet[0][14:42]
                	arpContents = struct.unpack("2s2s1s1s2s6s4s6s4s", arpHeader)

                    opCode = arpContents[4]
                    sourceIP = arpContents[6]
                    targetMac = arpContents[7]
                    targetIP = arpContents[8]


                    if binascii.hexlify(opCode) == "0001":

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
                        print "\n\n"

						#finds mac address of router
						targetMac = findMac(targetIP)


                        #start building reply packet
                        newEthHeader = struct.pack("!6s6s2s", sourceMac, targetMac, ethType)

						#make reply arp header 
                        newArpHeader = makeArpHeader(True, arpContents[0], arpContents[1], arpContents[2], arpContents[3],
                        	targetMac, targetIP, sourceMac, sourceIP)

                        replyPacket = newEthHeader + newArpHeader
                        #print binascii.hexlify(replyPacket)

                        s.sendto(replyPacket, packet[1])



                #if ICMP also apparently tcp is 800 so that's fun
                elif ethType == '\x08\x00':

                    #ip header
                    ipHeader = packet[0][14:34]
                    ipContents = struct.unpack("1s1s2s2s2s1s1s2s4s4s",ipHeader)

                    sourceIP = ipContents[8]
                    destinationIP = ipContents[9]
                    ttl = ipContents[5]
                    checkSum = ipContents[7]
                    ipProtocol = ipContents[6]

                    if ipContents[1] == '\x00' and ipProtocol == '\x01':

                        #icmp header
                        icmpHeader = packet[0][34:98]
                        icmpContents = struct.unpack("1s1s2s2s2s8s48s",icmpHeader)

                        icmpType = icmpContents[0]
                        icmpCode = icmpContents[1]
                        icmpChecksum = icmpContents[2]
                        icmpID = icmpContents[3]
                        icmpSeq = icmpContents[4]
                        icmpTime = icmpContents[5]
                        icmpData = icmpContents[6]

                        #Start building reply
                        #if type is echo request
                        if icmpType == '\x08':
                            print "echo request recd"

                            #new eth header
                            newEthHeader = struct.pack("!6s6s2s", sourceMac, destinationMac, ethType)

                            #new ip header
                            #newIpChecksum = '\x00\x00'

                            #tempIpHeader = struct.pack("1s1s2s2s2s1s1s2s4s4s", ipContents[0], ipContents[1], ipContents[2], ipContents[3], ipContents[4], ttl, ipContents[6],newIpChecksum, destinationIP, sourceIP)

                            #newIpChecksum = str(binascii.crc32(tempIpHeader))

                            newIpHeader =  struct.pack("1s1s2s2s2s1s1s2s4s4s", ipContents[0], ipContents[1], ipContents[2],ipContents[3], ipContents[4], ttl, ipContents[6],checkSum, destinationIP, sourceIP)

                            #new ICMP header
                            newIcmpChecksum = '\x00\x00'

                            tempIcmpHeader = struct.pack("1s1s2s2s2s8s48s", '\x00', icmpCode, newIcmpChecksum, icmpID, icmpSeq, icmpTime, icmpData)


                            newIcmpChecksum = str(binascii.crc32(tempIcmpHeader))

							#Pack new header
                            newIcmpHeader = struct.pack("1s1s2s2s2s8s48s", '\x00', icmpCode, newIcmpChecksum, icmpID, icmpSeq, icmpTime, icmpData)

                            #send it
                            replyPacket = newEthHeader + newIpHeader + newIcmpHeader
                            s.sendto(replyPacket, packet[1])
                            print "icmp echo sent"


getRoutingList()
router()
