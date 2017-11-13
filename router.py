#!/usr/bin/python

import socket
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
class myRouter:

	def __init__(self):
		self.listIP1 = []
		self.listIP2 = []
		self.routerMac = ''
		self.routerIp = ''
		self.nextIp = ''
		self.nextMac = ''
		self.knownAddrs = {}

	"""
	Finds MAC address of requested IP
	"""
	def findMac(self, IP, hop):
		if hop is None:
			#obtain list of addresses on the network
			networkList = netifaces.interfaces()
			for iface in networkList:
				addr = netifaces.ifaddresses(iface)[2][0]['addr']
				mac = netifaces.ifaddresses(iface)[17][0]['addr']
				if addr == socket.inet_ntoa(IP):
					return binascii.unhexlify(mac.replace(':', ''))
		else:
			addr = netifaces.ifaddresses(hop)[2][0]['addr']
			mac = netifaces.ifaddresses(hop)[17][0]['addr']
			return [addr, mac]
		return "MAC_NOT_FOUND"

	"""
	find next hop
	"""
	def findNextHop(self, iplist, fdestIp, nextIP):
		#remove empty indexes
		for i in iplist:
			if len(i.strip()) <= 1:
				iplist.remove(i)

		for entry in iplist:
			entryList = entry.split(' ')

			if nextIP is False:

				if len(entry) <= 1:
					break
				ipNum = entryList[1]
				destIpList = fdestIp.split('.')

				#checking 16 and 24 bit patterns
				if ipNum == '16':
					newIpList = entryList[0].split('.')
					if newIpList[0:2] == destIpList[0:2]:
						return entryList[3]
				elif ipNum == '24':
					newIpList = entryList[0].split('.')
					if newIpList[0:3] == destIpList[0:3]:
						return entryList[3]
			else:
				if entryList[2] is not '-':
					return entryList[2]

		return False

	"""
	gets routing tables and puts them into lists
	"""
	def getRoutingList(self):
		table1 = open("r1-table.txt", "r")
		table2 = open("r2-table.txt", "r")
		self.listIP1 = table1.read().replace("/", " ").split("\n")
		self.listIP2 = table2.read().replace("/", " ").split("\n")

	"""
	Creates ARP header
	"""
	def makeArpHeader(self, reply, hwareType, pcType, hwareSize, pcSize, srcMac, srcIp, destMac, destIp):

		#arp reply
		if reply is True:
			opCode = '\x00\x02'

		#this is an ARP request
		else:
			opCode = '\x00\x01'
			nextHop = myRouter.findNextHop(self, self.listIP1, destIp, False)
			print nextHop
			print destIp
			if nextHop is False:
				nextHop = myRouter.findNextHop(self, self.listIP2, destIp, False)
				#if nextHop is False: send error message.  Part three stuff
				if nextHop is False:
					print "Error.  Destination not found"

			destIp = myRouter.findNextHop(self, self.listIP1, destIp, True)
			self.nextIp = destIp
			destMac = binascii.hexlify(destMac)
			destIp = binascii.hexlify(destIp)
			srcMac = binascii.unhexlify(srcMac.replace(':',''))
			destMac = binascii.unhexlify(destMac)
			srcIp = socket.inet_aton(srcIp)
			destIp = socket.inet_aton(binascii.unhexlify(destIp))
			hwareType = '\x00\x01'
			pcType = '\x08\x00'
			hwareSize = '\x06'
			pcSize = '\x04'
			opCode = '\x00\x01'
		arpHeader = struct.pack("2s2s1s1s2s6s4s6s4s", hwareType,pcType,hwareSize,pcSize,opCode ,srcMac,srcIp,destMac,destIp)

		return arpHeader

	'''
	make arp request packet
	'''
	def makeArpRequest(self, targetIP, targetMac):
		print 'router mac: ', self.routerMac
		ethHeader = struct.pack('!6s6s2s', '\xFF\xFF\xFF\xFF\xFF\xFF', binascii.unhexlify(self.routerMac.replace(':','')),  '\x08\x06')
		arpHeader = myRouter.makeArpHeader(self, False, '\x00\x01', '\x08\x00', '\x06', '\x04', self.routerMac, self.routerIp, '\x00\x00\x00\x00\x00\x00', targetIP)
		return ethHeader + arpHeader

	"""
	calculates checkSum
	obtained from:
	https://stackoverflow.com/questions/1767910/checksum-udp-calculation-python
	"""
	def carry_around_add(self, a, b):
		c = a + b
		return (c & 0xffff) + (c >> 16)

	def calcChecksum(self, msg):
		s = 0
		for i in range(0, len(msg), 2):
			w = ord(msg[i]) + (ord(msg[i+1]) << 8)
			s =self.carry_around_add(s, w)
		return binascii.hexlify(str(~s & 0xffff))


	"""
	Runs the router
	"""
	def router(self):

		try:
			s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x003))
			print "Socket connected"
		except socket.error, msg:
			print msg
			sys.exit(-1)

		# https://stackoverflow.com/questions/24415294/python-arp-sniffing-raw-socket-no-reply-packets

		while True:
			packet = s.recvfrom(1024)

			#Ethernet Header Stuff
			ethHeader = packet[0][0:14]
			ethContents = struct.unpack("!6s6s2s", ethHeader)

			destinationMac = ethContents[0]
			self.routerMac = destinationMac
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
				self.routerIp = targetIP
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
					self.routerMac = myRouter.findMac(self, targetIP, None)

					#start building reply packet
					newEthHeader = struct.pack("!6s6s2s", sourceMac, self.routerMac, ethType)

					#make reply arp header
					newArpHeader = myRouter.makeArpHeader(self, True, arpContents[0], arpContents[1], arpContents[2], arpContents[3],
					self.routerMac, targetIP, sourceMac, sourceIP)

					replyPacket = newEthHeader + newArpHeader
					#print binascii.hexlify(replyPacket)

					s.sendto(replyPacket, packet[1])
				elif binascii.hexlify(opCode) == "0002":
					print "#########ARP_REPLY##########"
					print "##########ETH_HEADER########"
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
					self.nextMac = sourceMac
					self.knownAddrs[socket.inet_ntoa(sourceIP)] = sourceMac

			#ICMP also apparently tcp is 800 so that's fun
			elif ethType == '\x08\x00':

				#ip header
				ipHeader = packet[0][14:34]
				ipContents = struct.unpack("1s1s2s2s2s1s1s2s4s4s",ipHeader)
				fsourceIP = ipContents[8]
				destinationIP = ipContents[9]
				ttl = ipContents[5]
				checkSum = ipContents[7]
				ipProtocol = ipContents[6]

				#ipProtocol x01 is ICMP
				if ipContents[1] == '\x00' and ipProtocol == '\x01':

					#TODO: decrement TTL

					#icmp header
					icmpHeader = packet[0][34:98]
					icmpContents = struct.unpack("1s1s2s2s2s8s48s",icmpHeader)
					#print ipContents
					icmpType = icmpContents[0]
					icmpCode = icmpContents[1]
					icmpChecksum = icmpContents[2]
					icmpID = icmpContents[3]
					icmpSeq = icmpContents[4]
					icmpTime = icmpContents[5]
					icmpData = icmpContents[6]

					#TCheck if destination is on this network, if not, we need arp request
					sourceIp = socket.inet_ntoa(fsourceIP)
					print 'source IP in icmp: ',  sourceIp
					print 'desination IP: ', socket.inet_ntoa(destinationIP)
					#Arp Request
					nextiface = myRouter.findNextHop(self, self.listIP1, socket.inet_ntoa(destinationIP), False)
					if nextiface == False:
						nextiface = myRouter.findNextHop(self, self.listIP2, socket.inet_ntoa(destinationIP), False)

					print 'nextiface = ', nextiface
					if nextiface != False and self.nextMac == '' and destinationIP != self.routerIp:
						iface = myRouter.findNextHop(self, self.listIP1,sourceIp, False)
						if iface is False:
							iface = myRouter.findNextHop(self, self.listIP2, sourceIp, False)

						print 'iface = ', iface
						routerAddrs = myRouter.findMac(self, '', iface)
						self.routerIp = routerAddrs[0]
						self.routerMac = routerAddrs[1]
						destMac = myRouter.findMac(self, destinationIP, None)
						destinationIP = socket.inet_ntoa(destinationIP)
						print 'Destination IP: ', destinationIP
						#it won't know the next mac address....that's why we do an arp request ya dummy
						print 'Destination mac: ', destMac
						arpReq = myRouter.makeArpRequest(self, destinationIP, destMac)
						print 'packet[1]', packet[1]
						s.sendto(arpReq, (nextiface, 2048, 0, 1, '\xFF\xFF\xFF\xFF'))

					#Start building reply
					#if type is echo request
					if icmpType == '\x08':
						print "echo request recd"

						if destinationIP in myRouter.findMac(self,None, nextiface):
							newDestIp = fsourceIP
							destMac = sourceMac
							icmpType = '\x00'
						else:
							destMac = myRouter.findMac(self, None, nextiface)
							icmpType = '\x08'

						#new eth header
						print "new eth: self.routerMac: ", self.routerMac
						if ':' in self.routerMac:
							self.routerMac = binascii.unhexlify(self.routerMac.replace(':', ''))

						newEthHeader = struct.pack("!6s6s2s", destMac, self.routerMac, ethType)

						#calculate checksum.  Part 3 shenanigans
						newsource = self.routerIp
						if '.' in self.routerIp:
							newsource = socket.inet_aton(self.routerIp)
						if '.' in newDestIp:
							newdest = socket.inet_aton(newDestIp)
						tempIpHeader = struct.pack("1s1s2s2s2s1s1s2s4s4s", ipContents[0], ipContents[1], ipContents[2],ipContents[3], ipContents[4], ttl, ipContents[6],'\x00\x00', newsource, newDestIp)
						newIpChecksum = self.calcChecksum(tempIpHeader)
						newIpHeader =  struct.pack("1s1s2s2s2s1s1s2s4s4s", ipContents[0], ipContents[1], ipContents[2],ipContents[3], ipContents[4], ttl, ipContents[6],newIpChecksum, newsource, newDestIp)

						#new ICMP header
						newIcmpChecksum = '\x00\x00'

						tempIcmpHeader = struct.pack("1s1s2s2s2s8s48s", icmpType, icmpCode, newIcmpChecksum, icmpID, icmpSeq, icmpTime, icmpData)

						newIcmpChecksum = self.calcChecksum(tempIcmpHeader)

						#Pack new header
						newIcmpHeader = struct.pack("1s1s2s2s2s8s48s",icmpType, icmpCode, newIcmpChecksum, icmpID, icmpSeq, icmpTime, icmpData)

						#send it
						replyPacket = newEthHeader + newIpHeader + newIcmpHeader
						s.sendto(replyPacket, packet[1])
						print "icmp echo sent"

temp = myRouter()
temp.getRoutingList()
temp.router()
