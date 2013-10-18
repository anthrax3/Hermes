# 
# Coverage Warpper
# 
# This program takes the output from the EMMA analysis and transmits it to the listening server.
# (This program will handle all the transmission of data)
# 

import sys, getopt, traceback
import xml.etree.cElementTree as et
import urllib, urllib2, json
import imp

#cvg = imp.load_source('DETAILS', '../Config/coverage.py')
cvg = imp.load_source('DETAILS', 'Config/coverage.py')


class Transmitter:


	


	def __init__(self, path):
		self.filepath = path
		self.receiver_address = 'http://' + cvg.DETAILS.CVG_ADDRESS + ":" + str(cvg.DETAILS.CVG_PORT)


	def setDestination(self, dest):
		self.receiver_address = dest


	def transmit(self):
		# attempt to open file
		# save file to variable
		# parse file information
		# open connection to REST receiver
		# send data
		# close connection

		f = None
		fileData = ""
		try:
			print 'Reading %s' % filepath
			f = open(self.filepath, 'r')
			fileData = f.read()
			print("Closing %s" % (filepath))
			f.close()
		except IOError as e:
			print 'I/O Error ({0}): {1}'.format(e.errno, e.strerror)
		except Exception as e:
			print 'An unexpected error occurred while trying to open file path: %s' % (e)
		else:
			print("Closing %s" % (filepath))
			f.close()


		if fileData:
			try:
				print("Encoding Data...")
				params = urllib.urlencode({
					'data': str(fileData)
					})

				print("Sending data...")
				urllib2.urlopen(self.receiver_address, params)
				print("Done.\n")

			except IOError as e:
				print 'An unepected exception has occurred: %s' % (e)



def usage(self):
	print('\n======================================================')
	print('					CoverageWrapper.py USAGE\n')
	print('CoverageWrapper.py -f <filename>\n')
	print('-f [--emmaoutputfile]')
	print('\tREQUIRED')
	print('\tProvides a path to the EMMA output file to be sent')



if __name__ == "__main__":

	filepath = ""
	arguments = sys.argv[1:]

	try:
		opts, args = getopt.getopt(arguments, "f:", ["emmaoutputfile"])
	except getopt.GetoptError:
		usage()
		sys.exit(2)

	for opt, arg in opts:
		if opt in ("-f", "--emmaoutputfile"):
			filepath = arg

	if filepath:
		# Run transmitter with file from specified filepath
		t = Transmitter(filepath)
		t.transmit()

	else:
		usage()
		sys.exit(2)







