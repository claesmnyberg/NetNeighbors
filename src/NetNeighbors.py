#!/usr/bin/python3
#
# File: NetNeighbor.py
# Author: Claes M Nyberg <cmn@fuzzpoint.com>
# Date: November 2016
# Desc: NetNeigbors program main file
#

from Conf import *
from Log import Log
from Sniff import *
from GUI import *

import os
import sys
import getopt
import _thread
import time

class NetNeighbors(object):
	''' The main class for NetNeighbor '''

	def __init__(self, iface, useGUI=True):
		''' Create the NetNeighbor object
			-iface: The interface to listen on '''

		self.log = Log(Conf.logFile)
		self.gui = None
		self.useGUI = useGUI

		if self.useGUI:
			self.gui = GUI(self.log, iface=iface)

		self.log.line(0, 'Network Neigbors v' + Conf.version + ' started')

		# Create the sniffer thread and set it as daemon
		# to alow for the process to terminate when the
		# window is closed
		self.sniff = Sniff(iface, self.log, self.gui)
		#self.sniff.setDaemon(True)

	def run(self):
		''' Start the sniffer thread and run the main GUI loop '''
		self.sniff.start()
		if self.useGUI:
			self.gui.run(self.sniff)
		
		# Running without a GUI, replacement loop
		else:
			while True:
				time.sleep(10)

def usage(pname):
	''' Print commandline options and exit '''

	print("")
	print('Network Neigbors v' + Conf.version + 
		' By Claes M Nyberg <cmn@fuzzpoint.com>')
	print("Usage: " + pname + ' <iface> [Options]')
	print("Options:")
	print("  -d --dbFile <file>  - The database file to write")
	print("  -g --noGUI          - Disable GUI")
	print("  -h --help           - This help")
	print("  -l --logFile <file> - The log file to use")
	print("  -v --verbose        - Be verbose, repeat to increase")
	print("")


def main(pname, argv):
	''' The main function. Process commandline arguments
		and starts the program '''

	iface = argv[0]
	Conf.sqlite = iface + '.sqlite'
	useGUI = True

	if not os.geteuid() == 0:
		sys.exit('This program requires root privileges to run')

	try:
		opts, args = getopt.getopt(argv[1:],
			"d:ghvl:",
			["noGUI", "logFile=", "dbFile="])

	except getopt.GetoptError:
		usage(pname)
		sys.exit(1)

	for opt, arg in opts:

		# Usage
		if opt in ('-h', '--help'):
			usage(pname)
			sys.exit()

		# No GUI, Terminal logging only
		if opt in ('-g', '--noGUI'):
			useGUI = False

		# Database file
		elif opt in ('-d', '--dbFile'):
			Conf.sqlite = arg

		# Log file
		elif opt in ('-l', '--logFile'):
			Conf.logFile = arg

		elif opt in ('-v', '--verbose'):
			Conf.verbose += 1

	# Start the main event loop
	netn = NetNeighbors(iface, useGUI)
	netn.run()	

if __name__ == "__main__":

	pname = sys.argv[0]

	if len(sys.argv) < 2:
		usage(pname)
		sys.exit(1)

	main(pname, sys.argv[1:])



