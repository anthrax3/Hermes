
#import fuzzer_grammar



# Example
'''
sess = sessions.session(session_filename="http_test.session")

myip = "localhost"
target = sessions.target(myip, 8080)
target.netmon = pedrpc.client(myip, 26001)
target.procmon = pedrpc.client(myip, 26002)

sess.add_target(target)
sess.connect(s_get("HTML"))

sess.fuzz()
'''

# TEST Outputs
'''
import time, sys

request = s_get("HTML")
mutations = request.num_mutations()
for count in range(mutations):
	if count > 100:
		sys.exit()
	print request.render()
	request.mutate()
'''


# startup server on localhost
# listen for crawler requests
# 

import sys, os, time, imp
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime, timedelta

from sulley import *
import PD_Creator.protocol



# load the auto-generated protocol definition
#prot = imp.load_source('*', '../PD_Creator/protocol.py')


#request = s_get('HTML Total')
#request = s_get('Protocol Definition')
#mutations = request.num_mutations()

#MAX_RESPONSES = 9999
#MAX_TIME_MINS = 30

#CURRENT_RESPONSES = 0
#START_TIME = datetime.now()

# ------------------------------------------------------------------------------------------------
# Custom Exception class - thrown them max responses or time limit reached
# ------------------------------------------------------------------------------------------------
class StopServerException(Exception):
	pass


# ------------------------------------------------------------------------------------------------
# Request handler class
# ------------------------------------------------------------------------------------------------
class FuzzHTTPRequestHandler(BaseHTTPRequestHandler):

	def __init__(self, context, *args):
		self.context = context

		self.Max_Responses = self.context["MAX_R"]
		self.Max_Time_Mins = self.context["MAX_T"]
		self.Current_Response = self.context["CUR_R"]
		self.Start_Time = self.context["SRT_T"]
		self.Request = self.context["S_REQ"]

		BaseHTTPRequestHandler.__init__(self, *args)


	def do_HEAD(self):
		s.send_response(200)
		s.send_header('Content-type', 'text/html')
		s.end_headers()

	def do_GET(self):

		# Check if we should still be going (time and max requests)
		'''
		if self.Start_Time:
			endtime = self.Start_Time + timedelta(minutes=self.Max_Time_Mins)
			if datetime.now() > endtime:
				raise StopServerException()
		else:
			self.Start_Time = datetime.now()

		if self.Current_Response >= self.Max_Responses:
			raise StopServerException()
		'''
			

		print '%s\tGET request received.' % (datetime.now())

		self.send_response(200)
		self.send_header('Content-type', 'text/html')
		self.end_headers()

		mutation = self.Request.render()

		#print '\n========================================================='
		#print 'Sending mutation: \n\n%s\n' % (mutation)
		print 'Sending mutation #' + str(self.Current_Response)
		#print '=========================================================\n'

		# Send the fuzzed html to the client
		self.wfile.write(mutation)
		self.Request.mutate()




# ------------------------------------------------------------------------------------------------
# Main class - is the server for the fuzzer
# ------------------------------------------------------------------------------------------------
class FuzzServer():


	def __init__(self, max_responses=9999, max_time_mins=30):
		self.MAX_RESPONSES = max_responses
		self.MAX_TIME_MINS = max_time_mins

		self.CURRENT_RESPONSES = 0
		self.START_TIME = None

		self.server_running = True
		self.Sulley_Request = None

		# Try to load the existing protocol into sulley - if it fails, generate a new one on init
		try:
			self.reloadSulleyRequest()
		except:
			pd = PDef_Creator()
			prot = pd.genAdvancedHTML([1,1,1,1,1,1,1])
			pd.save_protocol(prot)
			self.reloadSulleyRequest()


	# Reload the sulley protocol definition (request) this will change so it needs to be reloaded
	def reloadSulleyRequest(self, path='PD_Creator/protocol.py'):
		self.un_initialize_sulley_request('Protocol Definition')
		imp.reload(PD_Creator.protocol)
		self.Sulley_Request = s_get('Protocol Definition')


	# Overriding function that wipes a given request from the sulley framework
	# Allows for the same request name to be re-initialized and used multiple times
	def un_initialize_sulley_request(self, name):
		try:
			if blocks.REQUESTS.has_key(name):
				del blocks.REQUESTS[name]
			if blocks.CURRENT.name == name:
				blocks.CURRENT = None
		except Exception as e:
			print 'An unexpected error occurred while un-initializing the sulley request ' + str(name)



	# Start the server
	def run(self):
		print 'http server is starting...'

		host = '127.0.0.1'
		port = 80

		server_address = (host, port)
		httpd = HTTPServer(server_address, self.argHandler)

		print 'http server is running on %s:%s ...\n\n' % (host, port)

		try:
			START_TIME = datetime.now()

			while self.server_running:
				#httpd.serve_forever()
				httpd.handle_request()

		except KeyboardInterrupt:
			pass
		httpd.server_close()
		print 'Server stopped on %s:%s' % (host, port)


	def argHandler(self, *args):
		# Check if we should still be going (time and max requests)
		if self.START_TIME:
			endtime = self.START_TIME + timedelta(minutes=self.MAX_TIME_MINS)
			if datetime.now() > endtime:
				self.server_running = False
		else:
			self.START_TIME = datetime.now()

		if self.CURRENT_RESPONSES >= self.MAX_RESPONSES:
			self.server_running = False

		self.CURRENT_RESPONSES = self.CURRENT_RESPONSES + 1

		FuzzHTTPRequestHandler({
			"MAX_R": self.MAX_RESPONSES, 
			"MAX_T": self.MAX_TIME_MINS, 
			"CUR_R": self.CURRENT_RESPONSES, 
			"SRT_T": self.START_TIME,
			"S_REQ": self.Sulley_Request}, 
			*args)
		

# DEBUG
#f = FuzzServer(15)
#f.run()
