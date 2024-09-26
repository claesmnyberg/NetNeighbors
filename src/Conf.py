#
# File: Conf.py
# Author: Claes M Nyberg <cmn@fuzzpoint.com>
# Date: November 2016
# Desc: NetNeigbor program configuration module
#

class Conf(object):
	# Current version
	version = '2.0'

	# Path to log file 
	logFile = './netneighbor.log'

	# Verbose level
	verbose = 0

	# Mac vendors database
	macvendors = './infodb/mac-vendors'

	# TCP Service database
	tcpservices = './infodb/tcp-services'

	# SQlite database file (renamed to <iface>.sqlite later on)
	sqlite = './hosts.sqlite'



