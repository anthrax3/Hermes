


import sys
import os
import time
import imp
import inspect
import logging

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime, timedelta

from sulley import *
import PD_Creator.protocol

f_logger = logging.getLogger('Fuzzer_Lib_Logger')
f_logger.setLevel(logging.DEBUG)
f_fh = logging.FileHandler('Logs/fuzzer_lib.log', mode='w')
f_fh.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
f_fh.setFormatter(formatter)
f_logger.addHandler(f_fh)

# ----------------------------------------------------------------------------
# Custom Exception class - thrown them max responses or time limit reached
# ----------------------------------------------------------------------------
class StopServerException(Exception):
	pass


# ----------------------------------------------------------------------------
# Request handler class
# ----------------------------------------------------------------------------
class FuzzHTTPRequestHandler(BaseHTTPRequestHandler):

	def setup(self):
		BaseHTTPRequestHandler.setup(self)
		self.request.settimeout(10)

	def __init__(self, context, *args):

		f_logger.info('Request Hendler: New request handler generated.')

		self.context = context

		self.Max_Responses = self.context["MAX_R"]
		self.Max_Time_Mins = self.context["MAX_T"]
		self.Current_Response = self.context["CUR_R"]
		self.Start_Time = self.context["SRT_T"]
		self.Request = self.context["S_REQ"]

		BaseHTTPRequestHandler.__init__(self, *args)
		

	def do_HEAD(self):
		f_logger.info('Request Handler: do_HEAD')
		s.send_response(200)
		s.send_header('Content-type', 'text/html')
		s.end_headers()

	def do_GET(self):
		f_logger.info('Request Handler: do_GET')
		# Each request has x seconds to finish, else it times out
		self.rfile._sock.settimeout(10)
		self.wfile._sock.settimeout(10)

		self.send_response(200)
		self.send_header('Content-type', 'text/html')
		self.end_headers()

		mutation = self.Request.render()
		f_logger.info('Request Handler: Sending mutation #' + str(self.Current_Response))

		# Send the fuzzed html to the client
		self.wfile.write(mutation)
		self.Request.mutate()




# ----------------------------------------------------------------------------
# Main class - is the server for the fuzzer
# ----------------------------------------------------------------------------
class FuzzServer():


	def __init__(self, max_responses=9999, max_time_mins=30, prot_def_path="PD_Creator/protocol.py", module="PD_Creator.protocol"):

		params = {"max_responses": max_responses, "max_time_mins": max_time_mins, "prot_def_path": prot_def_path, "module": module}
		f_logger.info('Initializing Fuzz Server with params: ' + str(params))

		self.MAX_RESPONSES = max_responses
		self.MAX_TIME_MINS = max_time_mins

		self.CURRENT_RESPONSES = 0
		self.START_TIME = None
		self.END_TIME = None

		self.server_running = True
		self.Sulley_Request = None

		self.prot_def_module = None
		self.prot_def_path = prot_def_path

		# Try to load the existing protocol into sulley - if it fails, generate a new one on init
		try:
			f_logger.info('Attemtping to load specified module and protocol definition...')
			self.reloadSulleyRequest(self.prot_def_path, module)
			f_logger.info('Done.')
		except:
			f_logger.error('Reloading the Sulley request failed. Moving to new default protocol.')
			pd = PDef_Creator()
			prot = pd.genAdvancedHTML([1,1,1,1,1,1,1])
			pd.save_protocol(prot)
			self.reloadSulleyRequest()


	# Reload the sulley protocol definition (request) this will change so it needs to be reloaded
	def reloadSulleyRequest(self, path='PD_Creator/protocol.py', module='PD_Creator.protocol'):
		self.un_initialize_sulley_request('Protocol Definition')
		#imp.reload(PD_Creator.protocol)
		try:
			f_logger.info('Loading path: ' + str(path) + ', module: ' + str(module))
			self.prot_def_module = imp.load_source(module, path)
		except Exception as e:
			f_logger.error('Could not load path (' + str(path) + ') and module (' + module + '), ' + str(e))

		self.Sulley_Request = s_get('Protocol Definition')

		f_logger.info('Sulley request loaded. Number of possible mutations: ' + str(self.Sulley_Request.num_mutations()))


	# --------------------------------------------------------------------------------------------
	# Overriding function that wipes a given request from the sulley framework
	# Allows for the same request name to be re-initialized and used multiple times
	def un_initialize_sulley_request(self, name):
		f_logger.info('Uninitializing sulley requests....')
		try:
			if blocks.REQUESTS.has_key(name):
				del blocks.REQUESTS[name]
			if blocks.CURRENT.name == name:
				blocks.CURRENT = None
			f_logger.info('Done.')
		except Exception as e:
			f_logger.error('An unexpected error occurred while un-initializing the sulley request ' + str(name))



	# Start the server
	def run(self):
		print 'HTTP server is starting...'
		f_logger.info('HTTP server is starting.')

		host = '127.0.0.1'
		port = 80

		server_address = (host, port)
		self.httpd = HTTPServer(server_address, self.argHandler)
		# Timeout of each request thread
		self.httpd.timeout = 20
		# If no requests in "timeout" minutes then turn server off
		self.httpd.handle_timeout = self.server_off

		print 'http server is running on %s:%s ...\n\n' % (host, port)
		f_logger.info('HTTP server is running on ' + str(host) + ':' + str(port))

		try:
			self.START_TIME = datetime.now()

			while self.server_running:
				f_logger.info('Waiting To Handle Request...')
				self.httpd.handle_request()

		except KeyboardInterrupt:
			pass
		self.server_off()
		print 'Server stopped on %s:%s' % (host, port)
		f_logger.info('Server stopped.')


	def server_off(self):
		self.server_running = False
		self.END_TIME = datetime.now()
		self.httpd.server_close()
		f_logger.info('Server shutdown triggered by ' + str(inspect.stack()[1][3]))


	def reset(self):
		f_logger.info('Resetting Server.')
		self.server_running = True
		self.CURRENT_RESPONSES = 0
		self.END_TIME = None
		self.START_TIME = None


	def getStats(self):
		return (self.CURRENT_RESPONSES, self.START_TIME, self.END_TIME)


	def argHandler(self, *args):

		f_logger.info('Checking server status...')
		f_logger.info('Checking Time.')
		# Check if we should still be going (time and max requests)
		if self.START_TIME:
			endtime = self.START_TIME + timedelta(minutes=self.MAX_TIME_MINS)
			timed_out = (datetime.now() > endtime)
			f_logger.info('Time-check: (now() > endtime) = ' str(timed_out))
			if datetime.now() > endtime:
				self.server_running = False
				self.END_TIME = datetime.now()
				f_logger.info('Max Server Timeout Hit: Timeout = ' + \
						str(self.MAX_TIME_MINS) + ' minutes (Projected ' + \
						'end time: ' + str(endtime) + ')')

		else:
			self.START_TIME = datetime.now()

		f_logger.info('Checking response number...')
		if self.CURRENT_RESPONSES >= self.MAX_RESPONSES:
			self.server_running = False
			self.END_TIME = datetime.now()
			f_logger.info('Max Server Responses Hit: Max = ' + str(self.MAX_RESPONSES))

		if self.server_running:
			self.CURRENT_RESPONSES = self.CURRENT_RESPONSES + 1

			FuzzHTTPRequestHandler({
				"MAX_R": self.MAX_RESPONSES, 
				"MAX_T": self.MAX_TIME_MINS, 
				"CUR_R": self.CURRENT_RESPONSES, 
				"SRT_T": self.START_TIME,
				"S_REQ": self.Sulley_Request}, 
				*args)
		else:
			f_logger.info('Server no longer running. No request handled.')

		

# DEBUG
#f = FuzzServer(15)
#f.run()
