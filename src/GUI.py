#
# File: GUI.py
# Author: Claes M Nyberg <cmn@fuzzpoint.com>
# Date: November 2016
# Desc: NetNeigbor program GUI module
#

from Conf import *
from EntryBox import *
from MACVendor import *
from TCPService import *
from SQLite import *

from tkinter import *
import tkinter.messagebox as tkMessageBox
import tkinter.ttk as ttk
import datetime
import sys


#COLOR_SERVER='#a01e10'
COLOR_SERVER='#ff0000'

class GUI(Frame):

	def __init__(self, log, iface='', master=None):
		''' Initialize the window '''

		# Load mac and TCP service databases into memory
		self.macv = MACVendor(Conf.macvendors)
		self.tcpsrv = TCPService(Conf.tcpservices)

		# Connect to database file
		self.sqlite = SQLite(Conf.sqlite, True)

		self.count = 0
		self.log = log

		if master == None:
			master = Tk()

		Frame.__init__(self, master)
		self.win = master

		if iface != '':
			iface = '(' + str(iface) + ')'

		# Name and initial size
		self.wintitle = "Network Neighbors " + iface
		self.win.title(self.wintitle)
		self.win.geometry("900x500")

		# Handle close button 
		self.win.protocol("WM_DELETE_WINDOW", self.__on_close__)
		
		# Create the tree view and scrollbars to go with it
		self.tree = ttk.Treeview(self)
		ysb = ttk.Scrollbar(self, orient=VERTICAL, command=self.tree.yview)
		xsb = ttk.Scrollbar(self, orient=HORIZONTAL, command=self.tree.xview)
	
		# Set scrollbars
		self.tree['yscroll'] = ysb.set
		self.tree['xscroll'] = xsb.set

		# First column
		self.tree.column('#0', stretch=NO, minwidth=0, width=200)
		self.tree.heading('#0', text='Host IPv4 Address', anchor='w')
		self.tree['columns'] = ('Data')

		# Second column
		self.tree.column('Data')
		self.tree.heading('Data', text='', anchor='w')

		# Treeview styles
		style = ttk.Style()
		style.configure(".", font=('Helvetica', 12), foreground="black")
		style.configure("Treeview", font=('Courier', 10), 
			foreground='black')
		style.configure("Treeview.Heading", foreground='black')

		# Add to grid and set the tree view to stick with the window size
		self.tree.grid(row=0, column=0, sticky='nsew')
		self.tree.columnconfigure(0, weight=1)
		ysb.grid(row=0, column=1, sticky='nse')
		xsb.grid(row=1, column=0, sticky='sew')
		self.grid(sticky='nesw')
		self.grid(sticky='nesw')

		# Configure rows and columns
		self.win.columnconfigure(0, weight=1)
		self.win.rowconfigure(0, weight=1)
		self.columnconfigure(0, weight=1)
		self.rowconfigure(0, weight=1)

		# Set up logging window
		self.loggscroll = Scrollbar(self)
		self.loggscroll.grid(row=2, column=1, sticky=('nse'))
		self.text = Text(self, height=10, yscrollcommand=self.loggscroll.set)
		self.text.grid(row=2, column=0, sticky=('nsew'))
		self.loggscroll.config(command=self.text.yview)

		self.log.setGuiLogger(log.GUI(self.text))

		# Create general popup
		self.popup = Menu(self.win, tearoff=0)

		self.popup.add_command(label="Copy",
			command= lambda: self.__popup_copy__())

		# Create popup menu for host
		self.hostPopup = Menu(self.win, tearoff=0)

		self.hostPopup.add_command(label="Copy", 
			command= lambda: self.__popup_copy__())

		self.hostPopup.add_command(label="Set host description", 
			command= lambda: self.__popup_set_desc__())

		self.hostPopup.add_command(label="Clear host description", 
			command= lambda: self.__popup_del_desc__())

		self.hostPopup.add_command(label="Remove and re-detect host", 
			command= lambda: self.__popup_remove__())

		self.hostPopup.add_command(label="Delete and ignore host", 
			command= lambda: self.__popup_ignore__())

		self.tree.bind("<Button-3>", 
			lambda e: self.__do_popup__(e))


	def __do_popup__(self, event):
		''' Display popup menu for treeview '''

		# Determine the selected row
		item = self.tree.focus()

		# The selected row is an IPv4 address
		# Display popup menue for host
		tag = self.tree.item(item, 'tags')[0]
		if tag in ['ipv4', 'servers']:
			self.hostPopup.tk_popup(event.x_root, event.y_root)
		else:
			self.popup.tk_popup(event.x_root, event.y_root)


	def __popup_copy__(self):
		''' Copy selected row to clipboard '''
		item = self.tree.selection()

		if item == '' or not item:
			return

		txt = self.tree.item(item, 'text')
		vals = self.tree.item(item, 'values')
		if vals:
			txt = txt + ' ' + vals[0]
	
		self.win.clipboard_clear()
		self.win.clipboard_append(txt)
	

	def __popup_remove__(self):
		''' Remove the selected host and detect it again '''
		item = self.tree.selection()
		ipv4 = self.tree.item(item, 'text')
		ipv4 = ipv4.split(' ')[1]
		if tkMessageBox.askokcancel("Network Neighbour - Remove", 
				"Do you really want to remove " + ipv4 + "?\n\n" +
				"It will be added as soon as it is detected again."):
			self.tree.delete(ipv4)
			self.sqlite.delHost(ipv4)


	def __popup_ignore__(self):
		''' Ignore the selected host by deleting it from the tree '''
		item = self.tree.selection()
		ipv4 = self.tree.item(item, 'text')
		ipv4 = ipv4.split(' ')[1]
		if tkMessageBox.askokcancel("Network Neighbour - Ignore", 
				"Do you really want to ignore " + ipv4 + "?\n\n" +
				"It will disapear from the list and never be seen again."):
			self.tree.delete(item[0])


	def __popup_del_desc__(self):
		''' Delete any existing description for the selected host '''
		if tkMessageBox.askokcancel("Network Neighbour - Clear desc", 
				"Are you sure that you want to clear description?"):
			item = self.tree.focus()
			ipv4 = self.tree.item(item, 'text')
			ipv4 = ipv4.split(' ')[1]
			self.tree.item(item, text=self.tree.item(item, 'text'), values=('',))
			self.sqlite.setDesc(ipv4, '')


	def __popup_set_desc__(self):
		''' Set a custom description for the selected host '''
		sel = self.tree.selection()[0]
		item = self.tree.focus()
		ipv4 = self.tree.item(item, 'text')
		ipv4 = ipv4.split(' ')[1]

		tb = EntryBox(self.win, text='Enter host description for ' + ipv4)
		self.win.wait_window(tb.root)
		desc = tb.getStr()
		if desc != '':
			self.tree.item(item, values=(desc,))
			self.sqlite.setDesc(ipv4, desc)


	def __on_close__(self):
		''' Handle window close button 
			Prompt for termination and exit the process '''
		if tkMessageBox.askokcancel("Network Neighbour - Quit", 
				"Do you want to quit?"):
			self.log.line(0, '*** Terminating')
			self.win.destroy()
			sys.exit(0)


	def run(self, sniff):
		''' Run the main window GUI loop '''
		self.sniff = sniff
		self.win.mainloop()


	def add(self, ipv4, mac, stamp=''):
		''' Add a new network neighbour '''

		if stamp == '':
			now = datetime.datetime.now()
			stamp = now.strftime('%d %b %Y %H:%M:%S')

		vendor = self.macv.lookup(mac)
		if vendor == None:
			vendor = 'Unknown vendor'
		
		self.log.line(0, '** Detected NEW host ' +
			'(' + vendor + ') ' + ipv4);

		# Root node
		sub = self.tree.insert('', 'end', iid=str(ipv4), 
			text='---- ' + ipv4, values=(''), tags=('ipv4'))

		self.tree.insert(sub, '0', iid=ipv4 + '-vendor', 
			text='Vendor', values=(vendor,), tags=('vendor'))

		self.tree.insert(sub, '1', iid=ipv4 + '-mac', 
			text='MAC', values=(mac,), tags=('mac'))

		self.tree.insert(sub, '2', iid=ipv4 + '-detected', 
			text='Detected', values=(stamp,), tags=('detected'))

		# Add to database
		self.sqlite.addHost(ipv4, mac, stamp)
		self.count += 1

		# Update window title to include host count
		self.win.title(self.wintitle + ' detected ' + 
			str(self.count))
		

	def warningMsg(self, msg):
		''' Display message box with warning message '''
		tkMessageBox.showerror(title="error",
			message=msg, parent=self.win)


	def exist(self, ipv4, mac=None):
		''' Check if host exist '''
		return self.sqlite.exist(ipv4, mac)


	def setGateway(self, ipv4):
		''' Set IPv4 address as gateway '''
		(G,S,I,A) = self.getHostFlags(ipv4)
		self.setHostFlags(ipv4, 'G' + S + I + A)


	def setServer(self, ipv4):
		''' Set IPv4 address as a server '''
		(G,S,I,A) = self.getHostFlags(ipv4)
		self.setHostFlags(ipv4, G + 'S' + I + A)


	def setInternet(self, ipv4):
		''' Set IPv4 address as connected to Internet '''
		(G,S,I,A) = self.getHostFlags(ipv4)
		self.setHostFlags(ipv4, G + S + 'I' + A)


	def getHostFlags(self, ipv4):
		''' Get flags for host '''
		txt = self.tree.item(ipv4, 'text')
		pfx = txt.split(' ')[0]
		return tuple(list(pfx))


	def setHostFlags(self, ipv4, flags):
		self.tree.item(ipv4, text=flags + ' ' + ipv4)


	def SetBrowserAgent(self, ipv4, agentOS):
		self.tree.insert(ipv4, '3', iid=ipv4 + '-agentOS', 
			text='User-Agent', values=(agentOS,), tags=('agentos'))
		(G,S,I,A) = self.getHostFlags(ipv4)
		self.setHostFlags(ipv4, G + S + I + 'A')


	def updateListeningPorts(self, ipv4, ports):
		''' Update the list of detected listening ports for this host '''

		# Create the ports tree if it does not already exist
		sub = ipv4 + '-tcp-ports'
		if not self.tree.exists(sub):
			sub = self.tree.insert(ipv4, '4', iid=ipv4 + '-tcp-ports',   
				text='TCP Ports', values=('',), tags=('tcp-ports'))

		# Update the listening port count
		self.tree.item(sub, values=(str(len(ports)),))

		# Insert the TCP port if it does not already exist
		# Use the port number itself as an index to keep the list sorted
		for port in ports:
			subp = ipv4 + '-tcp-ports-' + str(port)
			if not self.tree.exists(subp):
				srvc = self.tcpsrv.lookup(port)
				self.tree.insert(sub, port, subp, text=str(port),
					values=(srvc,), tags=('', ))

		# Set host as a server
		self.setServer(ipv4)
