



"""

		try:
			# Parse the parameters
			parser = EMMAXMLParser()
			parser.extractEMMAData(postvars['data'][0])
			list_overallresults = parser.getOverallResults()
			list_stats = parser.getStatsResults()
		except Exception as e:
			print 'An unexpected error occurred while parsing POST data: %s' % (e)

		# Save the corresponding data file in the logs with the snapshot information / stats
		if list_stats and list_overallresults:
			logpath = '%s%s.txt' % (DETAILS.CVG_LOG_PATH, datafilename)
			with open(logpath, 'w') as f:
				towrite = 'Stats:\t' + str(list_stats) + '\n\nOverall:\t' + str(list_overallresults)
				f.write(towrite)

			print '\nStats:\t' + str(list_stats)
			print 'Overall:\t' + str(list_overallresults) + '\n'

"""



# load specified file and generate the report from it. save it in spedified file.


import sys
import getopt
import logging

from CvgHelpers import EMMAXMLParser


class XML_Report_Parser():

	def __init__(self, filepath, outputpath):
		self.logger = logging.getLogger('XML_Report_Parser_Logger')
		self.logger.setLevel(logging.DEBUG)
		fh = logging.FileHandler('Report_Parser.log', mode='w')
		fh.setLevel(logging.DEBUG)
		formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
		fh.setFormatter(formatter)
		self.logger.addHandler(fh)

		self.list_overallresults = []
		self.list_stats = []

		data = self.load_xml_file(filepath)
		self.parse_report(data)
		self.save_report(outputpath)


	def load_xml_file(self, filepath):

		file_data = ""
		f = None
		try:
			self.logger.info('Opening file: ' + str(filepath))
			f = open(filepath, 'r')
			self.logger.info('Reading File...')
			file_data = f.read()
			self.logger.info('Done.')
			f.close()

		except IOError as e:
			self.logger.error('An IO Error has occurred while opening file: ' + str(filepath))
			self.logger.error('Exception: ' + str(e))
		except Exception as e:
			self.logger.error('An unexpected error has occurred: ' + str(e))
		else:
			f.close()

		return file_data


	def parse_report(self, raw_report):
		try:
			parser = EMMAXMLParser()
			parser.extractEMMAData(raw_report)

			self.list_overallresults = parser.getOverallResults()
			self.list_stats = parser.getStatsResults()
		except Exception as e:
			self.logger.error('An unexpected error has occurred: ' + str(e))


	def save_report(self, outputpath):
		if self.list_stats and self.list_overallresults:
			self.logger.info('Saving report.')
			with open(outputpath, 'w') as f:
				towrite = 'Stats:\t' + str(self.list_stats) + '\n\nOverall:\t' + str(self.list_overallresults)
				f.write(towrite)

			self.logger.info('Done.')




def usage(self):
	print('\n======================================================')
	print('					External_Report_Parser.py USAGE\n')
	print('External_Report_Parser.py -r <reportfile> -o <outputfile>\n')
	print('-r [--reportfile]')
	print('\tREQUIRED')
	print('\tProvides a path to the report file to be parsed. MUST be XML.')
	print('\n')
	print('-o [--outputfile]')
	print('\tREQUIRED')
	print('\tProvides a path to an output file the parsed results will be saved to.')
	



if __name__ == "__main__":

	filepath = ""
	outputpath = ""
	arguments = sys.argv[1:]

	try:
		opts, args = getopt.getopt(arguments, "r:o:", ["reportfile", "outputfile"])
	except getopt.GetoptError:
		usage()
		sys.exit(2)

	for opt, arg in opts:
		if opt in ("-r", "--reportfile"):
			filepath = arg
		elif opt in ("-o", "--outputfile"):
			outputpath = arg

	if filepath and outputpath:
		parser = XML_Report_Parser(filepath, outputpath)

	else:
		usage()
		sys.exit(2)






