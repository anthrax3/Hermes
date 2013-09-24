# 
# Coverage Warpper
# 
# This program takes the output from the EMMA analysis and transmits it to the listening server.
# (This program will handle all the transmission of data)
# 

import sys, getopt



class Transmitter:


	REST_receiver_address = ""


	def __init__(self, path):
		self.filepath = path


	def setDestination(self, dest):
		self.REST_receiver_address = dest


	def transmit(self):
		# attempt to open file
		# save file to variable
		# open connection to REST receiver
		# send data
		# close connection

		f = None
		fileData = ""
		try:
			f = open(self.path, 'r')
		except IOError as e:
			print 'I/O Error ({0}): {1}'.format(e.errno, e.strerror)
		except:
			print 'An unexpected error occurred while trying to open file path'

		if f is not None:
			try:
				fileData = f.









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


	else:
		usage()
		sys.exit(2)







