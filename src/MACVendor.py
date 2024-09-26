#!/usr/bin/python
#
# File: MACVendor.py
# Author: Claes M Nyberg <cmn@fuzzpoint.com>
# Date: November 2016
# Desc: Lookup MAC vendor from a list
#

from InfoDB import *

class MACVendor(InfoDB):


	def __init__(self, file):
		''' Load the MAC vendor file into memory '''
		InfoDB.__init__(self, file)


	def lookup(self, mac):
		''' Lookup a vendor from the database 
			this is overrided since the supplied mac address need
			processing to fit the provided database
			-mac: The colon separated mac address '''

		if type(mac) is not str:
			raise TypeError('lookup requires a string as key value')

		lst = mac.split(':')

		if len(mac) != 17 or len(lst) != 6:
			raise TypeError('MAC address not on the form aa:bb:cc:dd:ee:ff')

		prefix = lst[0].upper() + lst[1].upper() + lst[2].upper()
		return InfoDB.lookup(self, prefix)



if __name__ == "__main__":
	mv = MACVendor('./infodb/mac-vendors')
	print(mv.lookup('08:05:81:c9:d3:5b'))
