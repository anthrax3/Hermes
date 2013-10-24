
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

		# total packages, classes, methods, executable files, executable lines
		self.listofstatsresults = []
		for el in xmltree.findall('stats'):
			for ch in el.getchildren():
				self.listofstatsresults.append( ch.get("value") )


		# DEBUG============================================================
		# total packages, classes, methods, executable files, executable lines
		#print "Stats Results:\n", self.listofstatsresults, "\n"


		self.listofoverallresults = [(item.get("type"), item.get("value")) for item in xmltree.findall('data/all/coverage')]


		# DEBUG============================================================
		#print "Overall Results:\n", self.listofoverallresults, "\n"

		# class %, method %, block %, line %, name
		self.listofpackageresults = [item.get("name") for item in xmltree.findall('data/all/package')]

		for item in self.listofpackageresults:
			print "Package: " + str(item)





	def getOverallResults(self):
		return self.listofoverallresults

	def getStatsResults(self):
		return self.listofstatsresults










