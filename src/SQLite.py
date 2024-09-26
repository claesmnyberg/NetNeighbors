#
# File: SQLite.py
# Author: Claes M Nyberg <cmn@fuzzpoint.com>
# Date: November 2016
# Desc: NetNeigbor program SQLite module
#

from Utils import *
import sqlite3

class SQLite(object):

	def __init__(self, dbFile, reset=False):
		''' Connect to database '''
		self.dbFile = dbFile

		# Quick lookup hash tables
		self.hosts = {}
		self.hostports = {}

		conn = sqlite3.connect(dbFile)

		# Clear all tables 
		if reset:
			conn.execute('DROP TABLE IF EXISTS "hosts"')

		self.___createTables___(conn)
		conn.close()


	def ___createTables___(self, conn):
		''' Create database tables '''
		conn.execute(
		'''
			CREATE TABLE IF NOT EXISTS "hosts"
			(
        		"ipv4" VARCHAR(16) NOT NULL,
        		"mac" VARCHAR(20) NOT NULL,
        		"detected" VARCHAR(24) NOT NULL,
        		"desc" VARCHAR(120) NOT NULL

    		CHECK(
        		typeof("ipv4") = "text" AND
        		length("ipv4") <= 16
                	AND
        		typeof("mac") = "text" AND
       	 		length("mac") <= 20
                	AND
        		typeof("detected") = "text" AND
        		length("detected") <= 24
                	AND
        		typeof("desc") = "text" AND
        		length("desc") <= 120
    			)
			);

		''')
		conn.commit()


	def addHost(self, ipv4, mac, detected):
		''' Add host to database and also add it to a hash table
			for quick lookup
			-ipv4: The IPv4 address of the host
			-mac: The MAC address of the host 
			-detected: The time that the host was detected '''

		# To be able to add hosts from different threads
		# we need to repoen the connection each time
		conn = sqlite3.connect(self.dbFile)

		if not Utils.isValidIPv4(ipv4):
			raise TypeError('Invalid IPv4 address (dotted decimal required)')

		if not Utils.isValidMAC(mac):
			raise TypeError('Invalid MAC address (not on the form aa:bb:cc:dd:ee:ff)')

		conn.execute('INSERT INTO hosts VALUES (' + 
			'"' + ipv4 + '",' + 
			'"' + mac + '",' + 
			'"' + detected + '",' + 
			'"' + '' + '");' # Description
		)

		# Add host to quick lookup table
		self.hosts[ipv4] = mac

		conn.commit()
		conn.close()
	
	def delHost(self, ipv4):
		''' Delete host from database '''

		if not Utils.isValidIPv4(ipv4):
			raise TypeError('Invalid IPv4 address (dotted decimal required)')

		conn = sqlite3.connect(self.dbFile)
		conn.execute('DELETE FROM hosts WHERE ipv4 ="' + ipv4 +'"')
		conn.commit()
		conn.close()

		# Delete host from quick lookup table
		del self.hosts[ipv4]


	def setDesc(self, ipv4, desc):
		''' Set description for host '''

		if type(desc) is not str:
			raise TypeError('String required for description')

		if not Utils.isValidIPv4(ipv4):
			raise TypeError('Invalid IPv4 address (dotted decimal required)')

		conn = sqlite3.connect(self.dbFile)
		conn.execute('UPDATE hosts SET desc ="' + desc + 
			'" WHERE ipv4 ="' + ipv4 + '"')
		conn.commit()
		conn.close()


	def exist(self, ipv4, mac=None):
		''' Returns true if host exists in database '''

		if not Utils.isValidIPv4(ipv4):
			raise TypeError('Invalid IPv4 address (dotted decimal required)')

		if ipv4 in self.hosts:
			if mac != None:
				if self.hosts[ipv4] != mac:
					#print('** WARNING: ' + ipv4 + ' changed MAC from ' + 
					#	self.hosts[ipv4] + ' to ' + mac);
					pass
			return True
		return False	



