#!/usr/bin/python
#
# File: UnitTests.py
# Author: Claes M Nyberg <cmn@fuzzpoint.com>
# Date: November 2016
# Desc: NetNeigbor program Unit testing module
#

import unittest
import os

# Valid interface to use for testing
IFACE='lo'

from InfoDB import *
class testInfoDB(unittest.TestCase):
	
	def test__init__(self):
		self.assertRaises(Exception, MACVendor, -1)
		self.assertRaises(Exception, MACVendor, 'NOSUCHFILE')

	def test_lookup(self):
		idb = InfoDB('./infodb/tcp-services')
		self.assertRaises(Exception, idb.lookup, -1)
		self.assertRaises(Exception, idb.lookup, None)

		p22 = idb.lookup('22')
		self.assertEqual(p22, 'ssh')

	
from MACVendor import *
class testMACVendor(unittest.TestCase):

	def test__init__(self):
		self.assertRaises(Exception, MACVendor, -1)
		self.assertRaises(Exception, MACVendor, 'NOSUCHFILE')

	def test_lookup(self):
		mv = MACVendor('./infodb/mac-vendors')
		self.assertRaises(Exception, mv.lookup, None)
		self.assertRaises(Exception, mv.lookup, -1)
		self.assertRaises(Exception, mv.lookup, '')
		self.assertRaises(Exception, mv.lookup, 'AAAAAAA')
		
		rk = mv.lookup('08:05:81:c9:d3:5b')
		self.assertEqual(rk, 'Roku')

		rk = mv.lookup('ff:ff:ff:ff:ff:ff')
		self.assertEqual(rk, None)
		

from TCPService import *
class testTCPService(unittest.TestCase):

	def test__init__(self):
		self.assertRaises(Exception, TCPService, -1)
		self.assertRaises(Exception, TCPService, 'NOSUCHFILE')

	def test_lookup(self):
		ts = TCPService('./infodb/tcp-services')
		self.assertRaises(Exception, ts.lookup, None)
		self.assertRaises(Exception, ts.lookup, -1)
		self.assertRaises(Exception, ts.lookup, '')
		self.assertRaises(Exception, ts.lookup, 65537)
		self.assertRaises(Exception, ts.lookup, 'AAAAAAA')

		prt = ts.lookup(22)
		self.assertEqual(prt, 'ssh')

		prt = ts.lookup(80)
		self.assertEqual(prt, 'http')


from SQLite import *
class testSQLite(unittest.TestCase):

	def test__init__(self):
		self.assertRaises(Exception, SQLite, -1)
		self.assertRaises(Exception, SQLite, None)

	def test_addHost(self):
		file = './test.sqlite'
		db = SQLite(file)
		self.assertRaises(Exception, db.addHost, -1, '', '')
		self.assertRaises(Exception, db.addHost, '192.168.0.1', '', '')
		self.assertRaises(Exception, db.addHost, '', 'aa:bb:cc:dd:ee:ff', '')
		os.remove(file)		

	def test_delHost(self):
		file = './test.sqlite'
		db = SQLite(file)
		self.assertRaises(Exception, db.delHost, -1)
		self.assertRaises(Exception, db.delHost, None)
		self.assertRaises(Exception, db.delHost, '192.168.0.1')
		os.remove(file)		

	def test_setDesc(self):
		file = './test.sqlite'
		db = SQLite(file)
		self.assertRaises(Exception, db.setDesc, -1, 'desc')
		self.assertRaises(Exception, db.setDesc, None, 'desc')
		self.assertRaises(Exception, db.setDesc, '192.168.0.1', -1)
		os.remove(file)

	def test_exist(self):
		file = './test.sqlite'
		db = SQLite(file)
		self.assertRaises(Exception, db.exist, -1)
		self.assertRaises(Exception, db.exist, None)
		self.assertEqual(db.exist('192.168.1.1'), False)
		os.remove(file)


from Log import *
class testLog(unittest.TestCase):

	def test__init__(self):
		self.assertRaises(Exception, Log, -1)
		self.assertRaises(Exception, Log, None)

	def test_line(self):
		file = './test.log'
		l = Log(file)
		self.assertRaises(Exception, l.line, -1)
		self.assertRaises(Exception, l.line, None)
		os.remove(file)
	

	def test_stdout(self):
		file = './test.log'
		l = Log(file)
		self.assertRaises(Exception, l.line, -1)
		self.assertRaises(Exception, l.line, None)
		os.remove(file)


from NetNeighbors import *
class testNetNeighbors(unittest.TestCase):

	def test__init__(self):
		self.assertRaises(Exception, NetNeighbors, -1)
		self.assertRaises(Exception, NetNeighbors, None)
		self.assertRaises(SystemExit, NetNeighbors, 'nosuchinterface')


from GUI import *
from Sniff import *
class testSniff(unittest.TestCase):

	def test__init__(self):
		file = './testfile'
		iface='nosuchinterface'
		log = Log(file)
		self.assertRaises(SystemExit, Sniff, iface, None, None)
		self.assertRaises(SystemExit, Sniff, iface, log, None)
		self.assertRaises(SystemExit, Sniff, iface, log, GUI(iface, log))
		os.remove(file)


	def test__packetAnalyze__(self):
		file = './test.log'
		s = Sniff(IFACE, Log(file), None)
		self.assertRaises(Exception, s.__packetAnalyze__, '', '')
		self.assertRaises(Exception, s.__packetAnalyze__, '', None)
		self.assertRaises(Exception, s.__packetAnalyze__, '', [])
		self.assertRaises(Exception, s.__packetAnalyze__, None, 'AAAAAAAAAA')
		os.remove(file)


	def test__checkForHost__(self):
		file = './testfile'
		s = Sniff(IFACE, Log(file), None)
		self.assertRaises(Exception, s.__checkForHost__, None, None)
		self.assertRaises(Exception, s.__checkForHost__, '', '')
		self.assertRaises(Exception, s.__checkForHost__, 
			'aa:bb:cc:dd:ee:ff', None)
		self.assertRaises(Exception, s.__checkForHost__, 
			None, '192.168.1.1')
		self.assertRaises(Exception, s.__checkForHost__, 
			'aa:bb:cc:dd:ee:ff', None, 0, 0)
		os.remove(file)


	def test__addHost__(self):
		file = './testfile'
		s = Sniff(IFACE, Log(file), None)

		self.assertRaises(Exception, s.__addHost__, 
			'aa:bb:cc:dd:ee:ff', '192.168.1.900', 80, (TCP_SYN|TCP_ACK))

		self.assertRaises(Exception, s.__addHost__, 
			'aa:bb:cc:dd:ee:ff', '192.168.1.1', -1, (TCP_SYN|TCP_ACK))
		os.remove(file)

	def test__updateTCP__(self):
		file = './testfile'
		s = Sniff(IFACE, Log(file), None)
		self.assertRaises(Exception, s.__updateTCP__, 
			'192.168.1.900', 80, (TCP_SYN|TCP_ACK))

		self.assertRaises(Exception, s.__updateTCP__, 
			'192.168.1.100', 65537, (TCP_SYN|TCP_ACK))

		self.assertRaises(Exception, s.__updateTCP__, 
			'192.168.1.100', -1, (TCP_SYN|TCP_ACK))
		os.remove(file)


from Utils import *
class testUtils(unittest.TestCase):

	def test_isValidIPv4(self):
		self.assertEqual(Utils.isValidIPv4('192.168.1.1'), True)
		self.assertEqual(Utils.isValidIPv4('192.168.900.1'), False)
		self.assertEqual(Utils.isValidIPv4(''), False)
		self.assertEqual(Utils.isValidIPv4(None), False)

	def test_isValidPort(self):
		self.assertEqual(Utils.isValidPort(34), True)
		self.assertEqual(Utils.isValidPort(1), True)
		self.assertEqual(Utils.isValidPort(65535), True)
		self.assertEqual(Utils.isValidPort(-1), False)
		self.assertEqual(Utils.isValidPort(65537), False)

	def test_isValidMAC(self):
		self.assertEqual(Utils.isValidMAC('aa:bb:cc:dd:ee:ff'), True)
		self.assertEqual(Utils.isValidMAC('aa:bb:cc:dd:ee:gg'), False)
		self.assertEqual(Utils.isValidMAC(''), False)
		self.assertEqual(Utils.isValidMAC(None), False)

	def test_ipv4InSubnets(self):
		self.assertEqual(
			Utils.ipv4InSubnets('192.168.0.1', ['192.168.0.0/16']), True)
		self.assertEqual(
			Utils.ipv4InSubnets('172.16.0.1', ['172.12.0.0/16']), False)

		self.assertRaises(Exception, Utils.ipv4InSubnets, 
			'abcdef', [])

	def test_ethAddr(self):
		self.assertRaises(Exception, Utils.ethAddr, -1)
		self.assertRaises(Exception, Utils.ethAddr, None)
		self.assertRaises(Exception, Utils.ethAddr, '')
		self.assertRaises(Exception, Utils.ethAddr, '\x11\x22\x33\x44\x55')

		mac = Utils.ethAddr('\x11\x22\x33\x44\x55\x66')
		print(mac)


if __name__ == '__main__':

	if not os.geteuid() == 0:
		sys.exit('This program requires root privileges to run')

	# Close stderr to avoid clobbering the output
	#sys.stderr = open(os.devnull, 'w')

	mySuit = unittest.TestSuite()
	mySuit.addTest((unittest.makeSuite(testInfoDB)))
	mySuit.addTest((unittest.makeSuite(testMACVendor)))
	mySuit.addTest((unittest.makeSuite(testTCPService)))
	mySuit.addTest((unittest.makeSuite(testSQLite)))
	mySuit.addTest((unittest.makeSuite(testLog)))
	mySuit.addTest((unittest.makeSuite(testNetNeighbors)))
	mySuit.addTest((unittest.makeSuite(testSniff)))
	mySuit.addTest((unittest.makeSuite(testUtils)))

	runner=unittest.TextTestRunner()
	runner.run(mySuit)

