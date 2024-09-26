#!/usr/bin/python
#
# File: InfoDB.py
# Author: Claes M Nyberg <cmn@fuzzpoint.com>
# Date: November 2016
# Desc: Main class for key-value lookups in a tex-file database
#


class InfoDB(object):
	''' The key-value text file should consist of lines with
		key and its value  on each line separated by a space character '''

	def __init__(self, file):
		''' Load the text file into memory '''
		self.infodb = {}
		self.__loadFile__(file)

	def __loadFile__(self, file):
		''' Load the file into memory line by line
			-file: The file containning key-value lines '''
		
		infodb = {}
		file = open(file, "r")

		for line in file:
			line = line.strip() # Leading and trailing white space

			# Filter out comments 	
			index = line.find('#')
			if index >= 0:
				line = line[0:index]
				line = line.strip()			

			# Add key/value to dictionary
			if len(line) > 0:
				lst = line.split(' ', 1)
				infodb[lst[0]] = lst[1]

		self.infodb = infodb
		file.close()


	def lookup(self, key):
		''' Lookup a value from the database 
			-key: The key '''

		if type(key) is not str:
			raise TypeError('lookup requires a string as key value')

		val = None
		try:
			val = self.infodb[key]
		except(KeyError):
			return None

		return val
