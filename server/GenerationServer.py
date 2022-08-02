#!/usr/bin/python

# DCEPT
# James Bettke
# Dell SecureWorks 2016

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
import urlparse
import random
from datetime import datetime
import os
import sqlite3
import threading
import logging
from ConfigReader import config
import cgi
import cgitb

from Cracker import cracker
import dcept

# https://wiki.python.org/moin/BaseHttpServer


gsHandle = None

class GenerationServer:

	def __init__(self, hostname="", http_port=80, sqlite_path='/opt/dcept/var/honeytoken.db'):
		http_port = int(http_port)
		server_class = ThreadedHTTPServer #BaseHTTPServer.HTTPServer

		global gsHandle
		gsHandle = self

		self.sqlite_path = sqlite_path 
		self.conn = None
		self.initDatabase()

		# Only master node should run the generation server 
		if not config.master_node:

			logging.info("Database contains %d generated passwords" % self.getRecordCount())

			self.httpd = server_class((hostname, http_port), HttpHandler)

			# Start the webserver on it's own thread. Call to serve_forever() blocks
			thread = threading.Thread(target = self.httpd.serve_forever)
			thread.daemon = True
			logging.info("Starting honeytoken generation server HTTP daemon %s:%d" % (hostname,http_port))
			thread.start()


	# Initialize the sqlite database. Create the db and tables if it doesn't exist.
	def initDatabase(self):
		if not os.path.exists(self.sqlite_path):
			self.conn = sqlite3.connect(self.sqlite_path, check_same_thread=False)
			c = self.conn.cursor()
			c.execute('''CREATE TABLE db_version (major integer, minor integer)''')
			c.execute("INSERT INTO db_version VALUES (?,?)", (1,0))

			c.execute('''CREATE TABLE logs
				 (date text, domain text, username text, machine text, password text)''')

			# Add a test honeytoken to the database
			c.execute("INSERT INTO logs VALUES (?,?,?,?,?)", (datetime.now(), "ALLSAFE.LAN", "Administrator", "FAKE-PC", "dcepttest"))
			self.conn.commit()
		else:
			self.conn = sqlite3.connect(self.sqlite_path, check_same_thread=False)


	def genPass(self):
		alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		password = ""

		while True:
	 
			# Create a random password using the above alphabet
			for i in xrange(10):
				password += alpha[random.randrange(len(alpha))]

			print "Generated -",password

			# Does this password already exist?
			if self.findPass(password) == None:
				break
			else:
				print "Password collision, regenerating..."

		return password


	def findPass(self, password):
		c = self.conn.cursor()
		c.execute("SELECT * FROM logs WHERE password=?" , (password,))
		row = c.fetchone()

		return None if row is None else row


	def getPasswords(self):
		c = self.conn.cursor()
		c.execute("SELECT password FROM logs ORDER BY date DESC")

		return [i[0] for i in c.fetchall()]

	def getRecordCount(self):
		c = self.conn.cursor()
		c.execute("SELECT count(password) FROM logs")
		return c.fetchone()

class HttpHandler(BaseHTTPRequestHandler):

	# Generation requests from endpoints are always GET requests and must contain 
	# the honeytoken_param_name parameter.
	def do_GET(self):

		global gsHandle

		#if not s.path.startswith("/backup"):
		#	s.send_response(404)
		#	return

		self.send_response(200)
		self.send_header("Content-type", "text/json")
		self.end_headers()

		#print s.path
		qs = urlparse.urlparse(self.path).query
		qs = urlparse.parse_qs(qs)
		#print qs
		machine = ""
		try:
			machine = qs[config.honeytoken_param_name][0]
		except:
			return
		global gsHandle

		domain = config.domain
		username = config.honey_username

		password = gsHandle.genPass()
		jSONstring = "{'d':'%s','u':'%s',p:'%s'}" % (domain, username, password)
		self.wfile.write(jSONstring)
		global gsHandle
      # Log transaction
		c = gsHandle.conn.cursor()
		c.execute("INSERT INTO logs VALUES (?,?,?,?,?)", (datetime.now(), domain, username, machine, password))
		gsHandle.conn.commit()


	# DCEPT to DCEPT communication happens via POST requests.
	# Example for dcepttest: POST /notify
	# u=Administrator&d=ALLSAFE.LAN&t=64118a956797600c6e1239f1cf9c8db4ae780f0a1d0bc8b3a0e12de736a14792f17cb58671e42813fbd522e22e021c5d6924b7b114064889
	def do_POST(self):
		length = int(self.headers['content-length'])
		postvars = cgi.parse_qs(self.rfile.read(length), keep_blank_values=1)

		logging.debug(postvars)

		try:					
			username     = postvars['u'][0]
			domain		 = postvars['d'][0]
			encTimestamp = postvars['t'][0]
		except:
			self.send_response(500)
			self.end_headers()
			return		

		cracker.enqueueJob(username, domain, encTimestamp, dcept.passwordHit)		

		self.send_response(200)
		self.end_headers()

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

if __name__ == '__main__':
	gs = GenerationServer()
