#!/usr/bin/python
#
# File: Sniff.py
# Author: Claes M Nyberg <cmn@fuzzpoint.com>
# Date: November 2016
# Desc: NetNeigbor program network sniffer module
#
# The contents in this file has been inspired by sniff.py
# in the impacket module from CoreSecurity
#

from Utils import *
from Log import *
from GUI import *

import threading
import socket
from struct import *
import datetime
import sys

import pcapy
from pcapy import open_live, findalldevs, PcapError

# Static values only used in this file
ETH_HDR_LEN = 14
ETH_PROTO_ARP = 0x0608
ARP_HDR_LEN = 28
ARP_REQUEST = 0x0001
ARP_REPLY = 0x0002
ETH_PROTO_IP=8
IP_HDR_LEN = 20
IP_PROTO_ICMP = 1
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17
TCP_HDR_LEN=20

# TCP Flags
TCP_FIN=0x01
TCP_SYN=0x02
TCP_RST=0x04
TCP_PSH=0x08
TCP_ACK=0x10
TCP_URG=0x20

# Special purpose IPv4 subnets
# filter out these to avoid wrong detection of a gateway 
ipv4_subnets_ignore = [
	'255.255.255.255/32', # Limited broadcast
	'240.0.0.0/4',        # Future use
	'224.0.0.0/4',        # Multicast 
	'203.0.113.0/24',     # Test net 3
	'198.51.100.0/24',    # Test net 2
	'198.18.0.0/15',      # Inter network communications
	'169.254.0.0/16',     # Link local  
	'127.0.0.0/8',        # Loopback 
	'0.0.0.0/8']          # Broadcast for current

# private IPv4 subnet adddresses
ipv4_subnets_private = [
	'10.0.0.0/8',
	'172.16.0.0/12',
	'192.168.0.0/16']

class Sniff(threading.Thread):
	''' Sniff packets from network in a single thread and detect new neighbours '''

	def __init__(self, iface, log, gui=None):
		''' Initialize the thread and open the interface in promiscuous mode '''
		try:
			self.cap = pcapy.open_live(iface, 65536, True ,0)

		except(PcapError, e):
			sys.exit('** Error: Failed to open interface: ' + str(e) + '\n')

		# Initialize threading
		threading.Thread.__init__(self, daemon=True)

		self.log = log
		self.iface = iface
		self.gui = gui
		self.datalink = self.cap.datalink()
		self.offset = 0

		# Gateway MAC addresse(s)
		self.gw_macs = []

		# Local dictionary (if running without GUI)
		if not self.gui:
			self.sqlite = SQLite(Conf.sqlite, True)
			self.hosts = {}

		# Local dictionaries 
		self.hostports = {}
		self.hostinternet = {}
		self.agent = {}
		self.hostmacs = {}

		# Store network information in big endian
		self.mask = unpack('!L', socket.inet_aton(self.cap.getmask()))[0]
		self.net = unpack('!L', socket.inet_aton(self.cap.getnet()))[0]


		# Only ethernet supported for now
		if self.datalink != pcapy.DLT_EN10MB:
			raise RuntimeError('Invalid link layer type, only Ethernet supported for now')
		
		# Set link layer offset
		if self.datalink == pcapy.DLT_EN10MB:
			self.offset = ETH_HDR_LEN
		else:
			sys.exit('Link layer not supported (only ethernet for now)!')

		self.log.line(0, 'Opened %s net=%s mask=%s in promiscuous mode' 
			%(iface, self.cap.getnet(), self.cap.getmask()))


	def run(self):
		''' Sniff packets and register detected neighbour hosts '''

		# Capture packets forever and send them to analyze
		while(1):
			try:
				(header, packet) = self.cap.next()
				self.log.line(4, 'Captured %d bytes, truncated to %d bytes' 
					%(header.getlen(), header.getcaplen()))
			except(PcapError, e):
				if self.log:
					self.log.line(0, '*** Aborting packet capturing: ' + str(e))
				if self.gui:
					self.gui.warningMsg('*** Aborting packet capturing ***\n' + 
						 '\n' + str(e) + '\n')
				return

			self.__packetAnalyze__(header, packet)



	def __packetAnalyze__(self, hdr, packet):
		''' Analyze packet '''

		#----------------
		# Ethernet header 
		#----------------
		if hdr.getlen() < ETH_HDR_LEN:
			self.log.line(3, 'Ignoring short packet')
			return

		eth_header = packet[:ETH_HDR_LEN]
		eth = unpack('!6s6sH' , eth_header)
		eth_protocol = socket.ntohs(eth[2])
		
		src_mac = Utils.ethAddr(packet[6:12])
		dst_mac = Utils.ethAddr(packet[0:6])	

		src_ipv4 = ''
		dst_ipv4 = ''

		#-----
		# ARP
		#-----
		if eth_protocol == ETH_PROTO_ARP:
			if hdr.getlen() < ETH_HDR_LEN + ARP_HDR_LEN:
				self.log.line(3, 'Ignoring short ARP packet')
				return

			# Extract the ARP header and unpack it
			arp_hdr = packet[ETH_HDR_LEN:ARP_HDR_LEN+ETH_HDR_LEN]
			arph = unpack("!HHBBH6sL6sL", arp_hdr)
			arp_hwtype = arph[0]
			arp_proto = arph[1]
			arp_hwlen = arph[2]
			arp_plen = arph[3]
			arp_op = arph[4]
			arp_smac = Utils.ethAddr(arph[5])
			arp_sipv4 = arph[6]
			arp_dmac = Utils.ethAddr(arph[7])
			arp_dipv4 = arph[8]

			# Create dotted decimal addresses
			src_ipv4 = socket.inet_ntoa(pack('!L', arp_sipv4))
			dst_ipv4 = socket.inet_ntoa(pack('!L', arp_dipv4))

			#------------
			# ARP Request
			# Extract the source IPv4 address.
			# Assume that the sender MAC address in the ARP header
			# match the sender address in the ethernet header 
			#------------
			if arp_op == ARP_REQUEST:
				self.__checkForHost__(arp_smac, arp_sipv4, 
					src_ipv4, arp_dipv4, dst_ipv4)

			#----------
			# ARP Reply
			# Lookup the MAC address in the host-list and set the IPv4 address
			# This is useful if the host is a gateway.
			#----------
			elif arp_op == ARP_REPLY:
				self.__checkForHost__(arp_smac, arp_sipv4, 
					src_ipv4, arp_dipv4, dst_ipv4)

		#------------
		# IPv4 header
		#------------
		elif eth_protocol == ETH_PROTO_IP:
			if hdr.getlen() < ETH_HDR_LEN+IP_HDR_LEN:
				self.log.line(3, 'Ignoring short IP packet')
				return

			# Extract the IPv4 header and unpack it
			ip_hdr = packet[self.offset:IP_HDR_LEN+self.offset]
			iph = unpack('!BBHHHBBHLL' , ip_hdr)

			# IPv4 version and header length
			ip_ver_hl = iph[0]
			ip_ver = ip_ver_hl >> 4
			ip_hl = ip_ver_hl & 0xF
			ip_len = ip_hl * 4

			# Only IPv4 for now
			if ip_ver != 4:
				self.log.line(3, 'Ignoring IP version ' + str(ip_ver))
				return

			# IPv4 TTL
			ip_ttl = iph[5]
			ip_proto = iph[6]
		
			# Ignore zero IPv4 source 
			if iph[8] == 0:
				self.log.line(3, 'Ignoring zero source IPv4 address')
				return

			# Create dotted decimal addresses
			src_ip = iph[8]
			dst_ip = iph[9]
			src_ipv4 = socket.inet_ntoa(pack('!L', iph[8]))
			dst_ipv4 = socket.inet_ntoa(pack('!L', iph[9]))

			# Only listen for TCP, UDP and ICMP
			if not ip_proto in [IP_PROTO_TCP, IP_PROTO_UDP, IP_PROTO_ICMP]:
				self.log.line(3, 'Ignoring IPv4 protocol ' + str(ip_proto))
				return

			tcp_sprt = None
			tcp_dprt = None
			tcp_flags = None
			tcp_data = None

			# Check for listening TCP port by detecting SYN ACK packets 
			# as part of the TCP handshake
			if ip_proto == IP_PROTO_TCP:
				if hdr.getlen() < ETH_HDR_LEN+IP_HDR_LEN+TCP_HDR_LEN:
					self.log.line(3, 'Ignoring short TCP packet')
					return

				# Extract the TCP header and unpack it
				to = self.offset+IP_HDR_LEN
				tcp_hdr = packet[to:to+TCP_HDR_LEN]
				tcph = unpack('!HHLLBBHHH' , tcp_hdr)

				# Source and destination port
				tcp_sprt = tcph[0]
				tcp_dprt = tcph[1]

				# Seq and Ack
				tcp_seq = tcph[2]
				tcp_ack = tcph[3]
				
				# TCP header length
				res = tcph[4]
				tcp_len = res >> 4

				# Flags
				tcp_flags = tcph[5]
			
				# Data at end of packet
				tcp_data_off = ETH_HDR_LEN + IP_HDR_LEN + (tcp_len * 4)
				tcp_data_len = hdr.getlen() - tcp_data_off

				# Short packet
				if hdr.getlen() != (tcp_data_off + tcp_data_len):
					self.log.line(3, 'Ignoring short TCP packet ' +
						str(hdr.getlen()) + ' != ' + 
						str((tcp_data_off + tcp_data_len)))
					return

				# Extract TCP data
				tcp_data = packet[tcp_data_off:]
				if len(tcp_data) > 0 and self.__hostExist__(src_ipv4):
				
					# Extract browser information
					if tcp_dprt == 80:
						self.__browserInfo__(src_ipv4, tcp_dprt, tcp_data)

			# Check host list
			self.__checkForHost__(src_mac, src_ip, src_ipv4, 
				dst_ip, dst_ipv4, tcp_sprt, tcp_flags)


	def __checkForHost__(self, src_mac, src_ip, src_ipv4, 
			dst_ip, dst_ipv4, tcp_sprt=None, tcp_flags=None):
		''' Check for new host '''


		# Ignore new hosts until we know the MAC address of the gateway
		#if self.gw_mac == '':
		#	self.log.line(2, 'Ignoring packets, no gateway info ')
		#	return

		if Utils.ipv4InSubnets(src_ipv4, ipv4_subnets_ignore):
			self.log.line(1, 'Dropping packet from ignored subnet ' 
				+ src_ipv4 + ' (sent from MAC ' + src_mac + ')')
			return

		# Update any listening TCP port
		if tcp_sprt and tcp_flags:
			self.__updateTCP__(src_ipv4, tcp_sprt, tcp_flags)

		# We know the gateway MAC, filter it out
		if src_mac in self.gw_macs:
			self.log.line(5, 'Ignoring packet from gateway')
			return

		# If the source address does not match the network
		# we might have detected a gateway. 
		if (src_ip & self.mask) != (self.net & self.mask):

			# Previously seen ipv4 address for this segment
			if src_mac in self.hostmacs:
				ip_seen = self.hostmacs[src_mac]
				self.gw_macs.append(src_mac)
				self.log.line(0, ip_seen + " is a gateway with MAC " 
					+ src_mac + " (detected from source IPv4 "
					+ src_ipv4 + ")")
				if self.gui:
					self.gui.setGateway(ip_seen)

			# Check internet access
			elif (dst_ip & self.mask) == (self.net & self.mask):
				if self.__hostExist__(dst_ipv4):
					self.__checkInternet__(src_ipv4, dst_ipv4, 
						tcp_sprt, tcp_flags)
			else:
				self.log.line(3, 'Ignoring out of segment packet ' 
					+ src_ipv4 + ' -> ' + dst_ipv4)

			return

		# Host already exist
		if self.__hostExist__(src_ipv4, src_mac):
			return

		# We detected a new neighbour
		self.__addHost__(src_mac, src_ipv4, tcp_sprt, tcp_flags)


	def __hostExist__(self, ipv4, src_mac=None):
		# Running with GUI (host already detected)
		if (self.gui and self.gui.exist(ipv4, src_mac)): 
			return True

		# Running without GUI (host already detected)
		if not self.gui and (ipv4 in self.hosts):
			return True

		return False

	def __TCPFlags__(self, flags):
		''' Return TCP flags as a string '''
		ret = ''

		if type(flags) is not int:
			return ''

		if flags & TCP_FIN:
			ret += ' FIN'

		if flags & TCP_SYN:
			ret += ' SYN'

		if flags & TCP_RST:
			ret += ' RST'

		if flags & TCP_PSH:
			ret += ' PSH'

		if flags & TCP_ACK:
			ret += ' ACK'
		
		if flags & TCP_URG:
			ret += ' URG'

		return ret.strip()


	def __checkInternet__(self, src_ipv4, dst_ipv4, tcp_sprt, tcp_flags):
		''' Check if destination host has Internet access '''

		if not tcp_sprt:
			return

		# Host already detected with Internet access
		if dst_ipv4 in self.hostinternet:
			return

		# This should already have been checked, but what the heck
		if Utils.ipv4InSubnets(src_ipv4, ipv4_subnets_ignore):
			return	
	
		# No internet address, just a private block
		# This might be interesting later
		if Utils.ipv4InSubnets(src_ipv4, ipv4_subnets_private):
			return

		if self.gui:
			self.gui.setInternet(dst_ipv4)
		
		if self.log:
			self.log.line(0, dst_ipv4 + ' has Internet access (Source: '+
			src_ipv4 + ':' + str(tcp_sprt) + 
			' TCP flags:' + self.__TCPFlags__(tcp_flags) + ')')

		self.hostinternet[dst_ipv4] = tcp_sprt


	def __browserInfo__(self, ipv4, tcp_dport, tcp_data):
		''' Attempt to extract browser agent from http connection '''

		# Already extracted from this host
		if ipv4 in self.agent:
			return

		# Traverse the HTTP lines
		for line in tcp_data.splitlines(True):
			if line.find('User-Agent:') >= 0:
				line = line.strip()
				self.agent[ipv4] = line
				self.log.line(0, ipv4 + " " + line)
				line = line.strip('User-Agent:').strip()
				if self.gui:
					self.gui.SetBrowserAgent(ipv4, line)

	def __addHost__(self, src_mac, ipv4, tcp_sprt=None, tcp_flags=None):
		''' Add new host '''

		if not Utils.isValidIPv4(ipv4):
			raise TypeError('Invalid IPv4 address')

		if not Utils.isValidMAC(src_mac):
			raise TypeError('Invalid MAC address')

		if tcp_sprt and not Utils.isValidPort(tcp_sprt):
			raise TypeError('Invalid port number: ' +  str(tcp_sprt))

		# Add new host
		if self.gui:
			self.gui.add(ipv4, src_mac)

		# Running without GUI
		else:
			self.hosts[ipv4] = src_mac
			self.log.line(0, '** Detected NEW host ' +
				'(' + src_mac + ') ' + ipv4);

			now = datetime.datetime.now()
			stamp = now.strftime('%d %b %Y %H:%M:%S')
			self.sqlite.addHost(ipv4, src_mac, stamp)

		# Make sure to clear ports list
		# in case we detected this host after it has been removed 
		self.hostports[ipv4] = {}

		# Save mac -> ipv4 for gateway lookup
		self.hostmacs[src_mac] = ipv4

		# Update any listening TCP port
		self.__updateTCP__(ipv4, tcp_sprt, tcp_flags)



	def __updateTCP__(self, ipv4, tcp_sprt, tcp_flags):
		''' Update list of detecteddetected  listening TCP ports for host '''

		if not Utils.isValidIPv4(ipv4):
			raise TypeError('Invalid IPv4 address')

		if tcp_sprt and not Utils.isValidPort(tcp_sprt):
			raise TypeError('Invalid port number: ' +  str(tcp_sprt))

		if not ipv4 in self.hostports:
			return

		# Check for listening port
		if tcp_sprt and tcp_flags:
			# SYN ACK
			if (tcp_flags == (TCP_SYN | TCP_ACK)):
				ports = self.hostports[ipv4]
				if not tcp_sprt in ports.keys():
					ports[tcp_sprt] = True
					self.log.line(0, ipv4 + " Listens on TCP " + str(tcp_sprt))
					if self.gui:
						self.gui.updateListeningPorts(ipv4, ports)


