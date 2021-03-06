

import xml.etree.cElementTree as et
import sys
import getopt
import pickle




class FBParser(object):

	FB_OutputFile = ''
	FB_DefDensityFile = ''

	PARSELOG = 'parse_log.txt'
	RESULTS = 'parse_results.txt'
	DENSITIES = 'parse_densities.txt'
	logfile = None
	fileXML_str = ""

	
	def __init__(self, tmpDD='defectdensity.txt', tmpB='fb_results.xml'):
		self.FB_OutputFile = tmpB
		self.FB_DefDensityFile = tmpDD


	def initialize(self):
		#self.parseDefectDensityFile()
		self.parseBugFile()



	def parseDefectDensityFile(self):

		density_list = []
		try:
			self.logThis('Opening FB defect density file...', False)
			with open(self.FB_DefDensityFile, 'r') as f:
				self.logThis('Reading FB defect density file...', False)
				for line in f:
					density_list.append(line.strip().split('\t'))
		except:
			print 'An unexpected error has occurred while opening and ' + \
					'reading the defect density file.'

		print '\n\n'
		self.saveThisList(density_list, self.DENSITIES)



	def parseBugFile(self):
		try:
			self.logThis("Opening FB result file...", False)
			f = open(self.FB_OutputFile, 'r')
			self.logThis("Reading FB result file...", False)
			self.fileXML_str = f.read()
			f.close()
			self.logThis("FB result file read", False)
		except IOError as e:
			print 'I/O error ({0}): {1}'.format(e.errno, e.strerror)
			self.logThis(
				'I/O error ({0}): {1}'.format(e.errno, e.strerror), 
				True)
		except:
			print 'An Unexpected error occurred while opening and ' + \
					'reading: {0}'.format(self.FB_OutputFile)
			self.logThis('An Unexpected error occurred while opening ' + \
					'and reading: {0}'.format(self.FB_OutputFile), True)

		if self.fileXML_str:
			xmltree = et.fromstring(self.fileXML_str)

			listOfResults = []
			for el in xmltree.findall('BugInstance'):
				tempList = []
				list_items = el.items()
				list_items.append( ('tag', el.tag) )

				tempList.append(list_items)

				for ch in el.getchildren():
					tmp = ch.items()
					tmp.append( ('tag', ch.tag) )

					tempList.append(tmp)

				listOfResults.append(tempList)

			self.saveThisList(listOfResults, self.RESULTS)
			
		else:
			print "No XML found"
			self.logThis("No XML Found", True)


	# ---------------------- HELPER FUNCTIONS --------------------------------


	def logThis(self, data, error):
		if self.logfile is None:
			try:
				self.logfile = open(self.PARSELOG, 'w')
			except IOError as e:
				print 'I/O error ({0}): {1}'.format(e.errno, e.strerror)
			except:
				print "Unexpected error opening log file."

		if(error is True):
			self.logfile.write('[ERROR]\t{0}\n'.format(data))
		else:
			self.logfile.write('[INFO]\t{0}\n'.format(data))



	def saveThisList(self, data, filename):
		try:
			f = self.savefile = open(filename, 'wb')
			pickle.dump(data, f)
			f.close()
		except IOError as e:
			print 'I/O error ({0}): {1}'.format(e.errno, e.strerror)
		except:
			print "Unexpected error opening file to save results."



	#Clean up: close file handlers
	def cleanup(self):
		self.logThis("Cleaning Up", False)
		if self.logfile is not None:
			try:
				self.logfile.close()
			except:
				print 'An Unexpected error occurred while closing log ' + \
						'file: %s' % self.PARSELOG




def usage():
	print "\n"
	print "======================================================"
	print "                    parser.py USAGE"
	print ""
	print "-d [--defectdensityfile]"
	print "\tREQUIRED"
	print "\tPath to the defect density file created by the init script"
	print "\n"
	print "-b [--bugfile]"
	print "\tREQUIRED (XML file)"
	print "\tPath the the generated bug file from findbugs via init script"
	print "\n"
	return



if __name__ == "__main__":

	tmpDD = ""
	tmpB = ""

	arguments = sys.argv[1:]
	try:
		opts, args = getopt.getopt(
						arguments, 
						"d:b:", 
						["defectdensityfile", "bugfile"])

	except getopt.GetoptError:
		usage()
		sys.exit(2)
	
	for opt, arg in opts:
		if opt in ("-d", "--defectdensityfile"):
			tmpDD = arg
		elif opt in ("-b", "--bugfile"):
			tmpB = arg

	# if both params provided, continue
	if tmpDD and tmpB:
		p = FBParser(tmpDD, tmpB)
		p.initialize()
		p.cleanup()
	else:
		usage()
		sys.exit(2)


