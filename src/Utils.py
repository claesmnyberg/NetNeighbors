#
# File: Utils.py
# Author: Claes M Nyberg <cmn@fuzzpoint.com>
# Date: November 2016
# Desc: NetNeigbour program utilities module
#


import socket
from netaddr import *
import re

class Utils(object):
	''' Utilities class '''

	@staticmethod
	def isValidIPv4(ipv4):
		''' Test ip string is a valid IPv4 address '''

		if type(ipv4) is not str:
			return False

		try:
			socket.inet_aton(ipv4)
		except(socket.error, e):
			return False
		except(TypeError, e):
			return False

		return True

	@staticmethod
	def isValidPort(port):
		if type(port) is not int:
			return False

		if port > 0 and port < 65536:
			return True

		return False

	@staticmethod
	def isValidMAC(mac):
		''' Determine if string is a valid MAC address '''

		if type(mac) is not str:
			return False
		
		if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac):
			return True

		return False

	@staticmethod
	def ipv4InSubnets(ipv4, subnets):

		if not Utils.isValidIPv4(ipv4):
			raise TypeError('Invalid IPv4 address')

		for sub in subnets:
			if IPAddress(ipv4) in IPNetwork(sub):
				return True

		return False

	@staticmethod
	def ethAddr(addy):
		''' Convert byte array into MAC address '''
		mac = ("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x"
			%(addy[0], addy[1], addy[2], addy[3], addy[4], addy[5]))
		return mac
	

if __name__ == "__main__":
	print(Utils.ipv4InSubnet('192.168.0.0', ['192.168.0.0/16']))

