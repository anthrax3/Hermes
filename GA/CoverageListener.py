


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


import imp
import time
import logging

from CvgHelpers import EMMAXMLParser
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from urlparse import parse_qs

#cvg = imp.load_source('DETAILS', '../Config/coverage.py')

from Config.coverage import DETAILS


logger = logging.getLogger('CVG_Listener_Logger')
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('Logs/CVG_Listener.log', mode='w')
fh.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)


class ListenerRequestHandler(BaseHTTPRequestHandler):

	def do_HEAD(self):
		self.send_response(200)
		self.end_headers()

	def do_GET(self):
		self.send_response(200)
		self.end_headers()

	def do_POST(self):
		try:
			length = int(self.headers.getheader('content-length'))
			print 'POST of length %s received.\n' %(str(length))
			logger.info('POST of length ' + str(length) + ' received.')
			postvars = parse_qs(self.rfile.read(length), keep_blank_values=1)

			# Write the data dump to a unique filename
			datafilename = 'EMMA_dump_%s' % (time.time())
			datafilepath = '%s%s.xml' % (DETAILS.LIST_XML_DUMP_PATH, datafilename)
			with open(datafilepath, 'w') as f:
				print 'Writing POST data to ' + str(datafilepath)
				logger.info('Writing POST data to ' + str(datafilepath) )
				f.write(postvars['data'][0])

			self.send_response(200)
			self.send_header("User-Agent", "Mozilla/5.0 (Windows NT 5.1; rv:10.0.1) Gecko/20100101 Firefox/10.0.1")
			self.send_header("Content-type", "text/xml")
			self.end_headers()

		except Exception as e:
			print("An unexpected error occurred while processing POST: %s" % (e))

		list_stats = None
		list_overallresults = None
		try:
			# Parse the parameters
			logger.info('Attempting to parse EMMA XML')
			parser = EMMAXMLParser()
			parser.extractEMMAData(postvars['data'][0])
			list_overallresults = parser.getOverallResults()
			list_stats = parser.getStatsResults()
		except Exception as e:
			print 'An unexpected error occurred while parsing POST data: %s' % (e)
			logger.error('An unexpected error has occurred while parsing POST data: ' + str(e))

		# Save the corresponding data file in the logs with the snapshot information / stats
		if list_stats and list_overallresults:
			logpath = '%s%s.txt' % (DETAILS.CVG_LOG_PATH, datafilename)
			logger.info('Saving log snapshop to ' + str(logpath))
			with open(logpath, 'w') as f:
				towrite = 'Stats:\t' + str(list_stats) + '\n\nOverall:\t' + str(list_overallresults)
				f.write(towrite)

			logger.info('Done.')
			print '\nStats:\t' + str(list_stats)
			print 'Overall:\t' + str(list_overallresults) + '\n'

		return







class Listener:

	def __init__(self):
		self.port = DETAILS.CVG_PORT
		self.address = DETAILS.CVG_ADDRESS


	def run(self):
		print("\nInitializing Server...")
		logger.info('Initializing Server...')

		server_address = (self.address, self.port)
		httpd = HTTPServer(server_address, ListenerRequestHandler)

		print("Done.\n")
		print("Server Running on %s:%s" % (self.address, self.port))
		logger.info('Done.')
		logger.info('Server running on ' + str( (self.address, self.port) ))

		try:
			httpd.serve_forever()
		except KeyboardInterrupt:
			pass
		httpd.server_close()
		print 'Server stopped.'
		logger.info('Server stopped.')






# DEBUG
#if __name__ == "__main__":
#	l = Listener()
#	l.run()