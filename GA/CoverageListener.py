


# sits in its own thread and listens on port 8080 for any incomming messages from the coverage reporter
# 		The received data will be a file string in JSON format as such:
#
#				{data:<file text>}
#
#
#	The recieved file text is the text from an XML document that was transmitted as is. Parsing for this 
#	file has already been half-coded in the CoverageWrapper.py file. It is currently commented out there.
#	Use that code to complete the parsing information.
#
#	Tie the coverage statistics in with the 'template' that is given to the fuzzer. Use this to modify the 
#	template in such a way to improve coverage via fuzzing. 
#
#	This folder is where the genetic algorithm, coverage listener, and template script definitions are
#
#	The files in this folder will be accessed by a batch (or shell) script from a higher directory


import imp, time
from CvgHelpers import EMMAXMLParser
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from urlparse import parse_qs

cvg = imp.load_source('DETAILS', '../Config/coverage.py')



class ListenerRequestHandler(BaseHTTPRequestHandler):

	def do_HEAD(self):
		pass

	def do_GET(self):
		pass

	def do_POST(self):
		try:
			length = int(self.headers.getheader('content-length'))
			print 'POST of length %s received.\n' %(str(length))
			postvars = parse_qs(self.rfile.read(length), keep_blank_values=1)

			# Write the data dump to a unique filename
			datafilename = '%sEMMA_dump_%s.xml' % (cvg.DETAILS.LIST_XML_DUMP_PATH, time.time())
			with open(datafilename, 'w') as f:
				f.write(postvars['data'][0])
			f.close()

			self.send_response(200)

		except Exception as e:
			print("An unexpected error occurred while processing POST: %s" % (e))

		try:
			# Parse the parameters
			parser = EMMAXMLParser()
			parser.extractEMMAData(postvars['data'][0])
			list_overallresults = parser.getOverallResults()
			list_stats = parser.getStatsResults()
		except Exception as e:
			print 'An unexpected error occurred while parsing POST data: %s' % (e)

		if list_stats and list_overallresults:
			print '\nStats:\t' + str(list_stats) + '\n'
			print 'Overall:\t' + str(list_overallresults) + '\n'







class Listener:

	def __init__(self):
		self.port = cvg.DETAILS.CVG_PORT
		self.address = cvg.DETAILS.CVG_ADDRESS


	def run(self):
		print("\nInitializing Server...")

		server_address = (self.address, self.port)
		httpd = HTTPServer(server_address, ListenerRequestHandler)

		print("Done.\n")
		print("Server Running on %s:%s" % (self.address, self.port))

		try:
			httpd.serve_forever()
		except KeyboardInterrupt:
			pass
		httpd.server_close()
		print 'Server stopped.'







if __name__ == "__main__":
	l = Listener()
	l.run()