#
# File: Log.py
# Author: Claes M Nyberg <cmn@fuzzpoint.com>
# Date: November 2016
# Desc: NetNeigbour program log module
#

from tkinter import *
import sys
import datetime
import logging
from Conf import *

class Log(object):

	''' Log lines to configured file and/or terminal '''
	class GUI(logging.Handler):
		''' Class for logging window '''

		def __init__(self, txt):
			logging.Handler.__init__(self)
			self.txt = txt
			self.txt.config(state='disabled', font=('Courier', 10))


		def line(self, line):
			self.txt.config(state='normal')
			self.txt.insert(END, line)
			self.txt.see(END)
			#self.txt.config(state='disabled')
			self.txt.update()


	def __init__(self, logFile, tag=''):
		''' Create the log object
			-logFile: The path to the logfile '''
		self.file = open(logFile, 'a+')
		self.tag=tag
		self.guilog = None


	def __dateStamp__(self):
		''' Generate date string '''
		now = datetime.datetime.now()
		stamp = now.strftime("%Y-%b-%d %H:%M:%S")
		stamp += ' '
		if self.tag != '':
			stamp += '[' + self.tag + '] '
		return stamp


	def setGuiLogger(self, guilog):
		''' Set the logger class for the GUI '''
		if type(guilog) is not Log.GUI:
			raise TypeError('Log class')
		self.guilog = guilog


	def line(self, level, line):
		''' Log one line to a log file prepending date 
			-level: The level of verboseness
			-line: The line to log '''

		if Conf.verbose < level:
			return

		if type(line) is not str:
			raise TypeError('the line to log must be a string')

		stamp = self.__dateStamp__()
		if self.guilog:
			self.guilog.line(stamp + line + '\n')
		else:
			print(stamp + line)

		self.file.write(stamp + line + '\n')


	def stdout(self, level, line):
		''' Just log the line to stdout 
			-level: The level of verboseness required 
			-line: The line to log '''

		if Conf.verbose < level:
			return

		if type(line) is not str:
			raise TypeError('the line to log must be a string')

		print(self.__dateStamp__() + line)




