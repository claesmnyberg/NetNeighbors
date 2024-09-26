#!/usr/bin/python
#
# File: TCPService.py
# Author: Claes M Nyberg <cmn@fuzzpoint.com>
# Date: November 2016
# Desc: Lookup TCP service from a list
#

from InfoDB import *

class TCPService(InfoDB):


	def __init__(self, file):
		''' Load the TCP service file into memory '''
		InfoDB.__init__(self, file)


	def lookup(self, key):
		''' Lookup a value from the database 
			-key: The key '''
	
		if type(key) is not int:
			raise TypeError('lookup requires the key as an integer (port)')

		if key < 0 or key > 65535:
			raise TypeError('invalid port number')

		return InfoDB.lookup(self, str(key))


if __name__ == "__main__":
	ts = TCPService('./infodb/tcp-services')
	print(ts.lookup(22))
