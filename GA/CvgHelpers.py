
#
#	CvgHelpers.py
#	
#	Coverage Helpers: Some helper classes for the coverage listener. Includes parsers, etc.
#	
#	Author: 	Caleb Shortt
#	Date:		October 2, 2013

import xml.etree.cElementTree as et
import sys


class EMMAXMLParser:

	def __init__(self):
		pass


	def extractEMMAData(self, xmlfile):

		if not xmlfile:
			print 'Error:\tXML file passed to EMMAXMLParser is not defined.'
			return ''

		xmltree = et.fromstring(xmlfile)

		# class %, method %, block %, line %, name
		self.listofoverallresults = []
		self.listofpackageresults = []

		# total packages, classes, methods, executable files, executable lines
		self.listofstatsresults = []
		for el in xmltree.findall('stats'):
			for ch in el.getchildren():
				self.listofstatsresults.append( ch.get("value") )


		# DEBUG============================================================
		# total packages, classes, methods, executable files, executable lines
		print "Stats Results:\n", self.listofstatsresults, "\n"


		for el in xmltree.findall('data/all/coverage'):
			self.listofoverallresults.append( (el.get("type"), el.get("value")) )


		# DEBUG============================================================
		print "Overall Results:\n", self.listofoverallresults, "\n"


		for el in xmltree.findall('data/all/package'):
			print el.items()



	def getOverallResults(self):
		return self.listofoverallresults

	def getStatsResults(self):
		return self.listofstatsresults










