#
# File: EntryBox.py
# Author: Claes M Nyberg <cmn@fuzzpoint.com>
# Date: November 2016
# Desc: Display messagebox with an entry field
#

from tkinter import *


class EntryBox(object):

	def __init__(self, master, text=''):
		self.root = Toplevel(master)

		self.lbl = Label(self.root, text=text, width=40, height=2)
		self.lbl.pack()

		self.ent = Entry(self.root, width=30)
		self.ent.pack()

		self.lbl = Label(self.root, text='', height=1)
		self.lbl.pack()

		self.btn = Button(self.root, text='Ok', command=self.fini)
		self.btn.pack()

		self.lbl = Label(self.root, text='', height=1)
		self.lbl.pack()

		self.value=''

	def fini(self):
		self.value = self.ent.get()
		self.root.destroy()

	def getStr(self):
		return self.value
