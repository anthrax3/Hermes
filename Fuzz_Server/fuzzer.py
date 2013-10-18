from sulley import *
import fuzzer_grammar


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

import sys, os, time
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer


#request = s_get('HTML Total')
request = s_get('HTML Anchors')
mutations = request.num_mutations()


# Request handler class
class FuzzHTTPRequestHandler(BaseHTTPRequestHandler):


	def do_HEAD(self):
		s.send_response(200)
		s.send_header('Content-type', 'text/html')
		s.end_headers()

	def do_GET(self):
		print '%s\tGET request received.' % (time.asctime())

		self.send_response(200)
		self.send_header('Content-type', 'text/html')
		self.end_headers()

		mutation = request.render()

		print '\n========================================================='
		print 'Sending mutation: \n\n%s\n' % (mutation)
		print '=========================================================\n'

		# Send the fuzzed html to the client
		self.wfile.write(mutation)
		request.mutate()





# Start the server
def run():
	print 'http server is starting...'

	host = '127.0.0.1'
	port = 80

	server_address = (host, port)
	httpd = HTTPServer(server_address, FuzzHTTPRequestHandler)

	print 'http server is running on %s:%s ...\n\n' % (host, port)

	try:
		httpd.serve_forever()
	except KeyboardInterrupt:
		pass
	httpd.server_close()
	print 'Server stopped on %s:%s' % (host, port)


if __name__ == '__main__':
	run()
