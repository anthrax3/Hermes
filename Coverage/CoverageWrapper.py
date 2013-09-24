# 
# Coverage Warpper
# 
# This program takes the output from the EMMA analysis and transmits it to the listening server.
# (This program will handle all the transmission of data)
# 

import sys, getopt
import xml.etree.cElementTree as et
import urllib, urllib2



class Transmitter:


	


	def __init__(self, path):
		self.filepath = path
		self.receiver_address = "127.0.0.1:8080"


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
			f = open(self.filepath, 'r')
			fileData = f.read()
			f.close()
		except IOError as e:
			print 'I/O Error ({0}): {1}'.format(e.errno, e.strerror)
		except Exception as e:
			print 'An unexpected error occurred while trying to open file path: %s' % (e)
		else:
			f.close()


		if fileData:
			try:
				params = urllib.urlencode({
					'data': fileData
					})
				response = urllib2.urlopen(self.receiver_address, params).read()

				# DEBUG======================================================================
				print 'Response: ', response



			except Exception as e:
				print 'An unepected exception has occurred: %s' % (e)


			# Parsing data - this should be in the genetic algorithm 
			# part ... the transmitter will be simple and just x-mit
			# the entire xml file.
			'''
			xmltree = et.fromstring(fileData)

			# class %, method %, block %, line %, name
			listofoverallresults = []
			listofpackageresults = []

			# total packages, classes, methods, executable files, executable lines
			listofstatsresults = []
			for el in xmltree.findall('stats'):
				for ch in el.getchildren():
					listofstatsresults.append( ch.get("value") )


			# DEBUG============================================================
			print listofstatsresults, "\n"


			for el in xmltree.findall('data/all/coverage'):
				listofoverallresults.append( (el.get("type"), el.get("value")) )


			# DEBUG============================================================
			print listofoverallresults, "\n"


			for el in xmltree.findall('data/all/package'):
				print el.items()
				sys.exit(0)
			'''






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

		print 'opening %s' % filepath
		# Run transmitter with file from specified filepath
		t = Transmitter(filepath)
		t.transmit()

	else:
		usage()
		sys.exit(2)







