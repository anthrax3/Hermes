
#
#	CvgHelpers.py
#	
#	Coverage Helpers: Some helper classes for the coverage listener. Includes parsers, etc.
#	
#	Author: 	Caleb Shortt
#	Date:		October 2, 2013

import xml.etree.cElementTree as et
import sys, re



class TargetData(object):

	def __init__(self):
		self.name = ""
		self.type = ""

		self.class_coverage = 0.0
		self.method_coverage = 0.0
		self.block_coverage = 0.0
		self.line_coverage = 0.0

		self.children = []


	def addChild(self, child):
		if child:
			self.children.append(child)
			return True
		return False


	def removeChild(self, child_to_remove):
		#for child in self.children:
		#	if child.name == child_to_remove.name:
		# look into:
		#
		#	http://stackoverflow.com/questions/2793324/is-there-a-simple-way-to-delete-a-list-element-by-value-in-python
		#	http://stackoverflow.com/questions/627435/how-to-remove-an-element-from-a-list-by-index-in-python
		try:
			self.children.remove(child_to_remove)
			return True
		except:
			print 'An unexpected exception has occurred while removing ' + str(child_to_remove.name)
		return False






class EMMAXMLParser:


	# ---------------------------------------------------------------------------------------------------
	def __init__(self, targets=[]):
		# Stores the overall coverage for the entire project (all packages)
		self.listofoverallresults = []

		# Stores the statistics (num pkgs, lines, classes, etc) for the project
		self.listofstatsresults = []

		# Stores the XML structure of ONLY the packages of our targets
		self.listoftargetresults = []

		self.target_list = targets



	# ---------------------------------------------------------------------------------------------------
	# Takes an xml file (generated from EMMA) as a string then parses and extracts the required information
	# that pertains to the targets specified in self.target_list (All of the coverage data for only the 
	# targets)
	#
	# Returns the success of the process: True, False
	def extractEMMAData(self, xmlfile):

		
		self.listofoverallresults = []
		self.listofstatsresults = []
		self.listoftargetresults = []
		self.list_target_complement = []

		if not xmlfile:
			print 'Error:\tXML file passed to EMMAXMLParser is not defined.'
			return False

		xmltree = et.fromstring(xmlfile)

		# -----------------------------------------------------------------------------------------------
		# 	Get Overall Results
		# -----------------------------------------------------------------------------------------------
		# total packages, classes, methods, executable files, executable lines
		for el in xmltree.findall('stats'):
			for ch in el.getchildren():
				self.listofstatsresults.append( ch.get("value") )

		self.listofoverallresults = [(item.get("type"), item.get("value")) for item in xmltree.findall('data/all/coverage')]

		# -----------------------------------------------------------------------------------------------
		# 	Get Package Results
		# -----------------------------------------------------------------------------------------------
		# class %, method %, block %, line %, name
		#self.listofpackageresults = [item.get("name") for item in xmltree.findall('data/all/package')]

		#for item in self.listofpackageresults:
		#	print "Package: " + str(item)



		# -----------------------------------------------------------------------------------------------
		# 	Get target's results (Only if a target list has been specified)
		# -----------------------------------------------------------------------------------------------
		'''
			Gets class cvg, mthd cvg, line cvg, and block cvg for the 
			target (at the method level - class cvg is one level up)
		'''

		'''
		if self.target_list:
			

			for bug in self.target_list:
				pkg = bug.classname.rsplit('.', 1)[0]
				match_str = "data/all/package[@name='" + str(pkg) + \
								"']/srcfile[@name='" + str(bug.src_file) + \
								"']/class[@name='" + str(bug.getClass()) + \
								"']"

				targetdata = TargetData()
				targetdata.name = str(bug.classname) + " -> " + str(bug.methodname) + "()"
				targetdata.type = str(bug.bugtype)

				class_el = xmltree.find(match_str)
				if class_el:
					cc_el = class_el.find("coverage[@type='class, %']")
					match = re.findall(r'[0-9]+', cc_el.get("value"))
					targetdata.class_coverage = float(match[0]) / 100


				for mthd_el in xmltree.findall(match_str + "/method"):
					if mthd_el.get("name").startswith(bug.methodname):
						for cvg_el in mthd_el.findall('coverage'):
							match = re.findall(r'[0-9]+', cvg_el.get("value"))
							if cvg_el.get("type") == "class, %":
								targetdata.class_coverage = float(match[0]) / 100
							elif cvg_el.get("type") == "method, %":
								targetdata.method_coverage = float(match[0]) / 100
							elif cvg_el.get("type") == "block, %":
								targetdata.block_coverage = float(match[0]) / 100
							elif cvg_el.get("type") == "line, %":
								targetdata.line_coverage = float(match[0]) / 100


				self.listoftargetresults.append(targetdata)
		'''

		self.extract_coverage_values(xmltree)

		return True



	def extract_coverage_values(self, xmltree):
		'''
			Traverses the xml structure and populates the 
			'listoftargetresults' and 'list_target_complement' variables
		'''

		if not xmltree:
			return False

		for pkg in xmltree.findall("data/all/package"):
			for src_file in pkg.findall("srcfile"):
				for clss in src_file.findall("class"):
					for mthd in clss.findall("method"):

						data = TargetData()
						data.name = clss.get("name") + "->" + mthd.get("name")
						data.class_coverage = self.get_class_coverage(clss)
						self.extract_coverage_values(mthd, data)

						bug = get_associated_bug(src_file, clss, mthd)
						if bug:
							data.type = bug.bugtype
							self.listoftargetresults.append(data)
						else:
							self.list_target_complement.append(data)
						

	def get_associated_bug(self, src_file, clss, mthd):
		'''
			Returns the bug associated with the path specified (xml nodes).
			If no bug exists, None is returned
		'''

		str_src = src_file.get("name")
		str_class = clss.get("name")
		str_mthd = mthd.get("name")

		for bug in self.target_list:
			if (str_src == bug.src_file and str_class == bug.classname and 
				str_mthd == bug.methodname):
				return bug
		return None


	def get_class_coverage(self, xml_node):
		el = xml_node.find("coverage[@type='class, %']")
		match = re.findall(r'[0-9]+', el.get("value"))
		if match:
			return float(match[0]) / 100
		else:
			return 0.0


	def extract_coverage_values(self, xml_node, data):
		'''
			Get all coverage values from the specified xml_node.
			Store the values in the specified data element (TargetData)
		'''

		for cvg_el in xml_node.findall('coverage'):
			match = re.findall(r'[0-9]+', cvg_el.get("value"))
			if cvg_el.get("type") == "class, %":
				data.class_coverage = float(match[0]) / 100
			elif cvg_el.get("type") == "method, %":
				data.method_coverage = float(match[0]) / 100
			elif cvg_el.get("type") == "block, %":
				data.block_coverage = float(match[0]) / 100
			elif cvg_el.get("type") == "line, %":
				data.line_coverage = float(match[0]) / 100








	# ---------------------------------------------------------------------------------------------------
	# Recursive function that iterates through the xml structure and generates a target data tree
	# assumes that the given list of xml item is the target xml structure
	def constructTargetTree(self, target_item):

		target_data = TargetData()
		target_data.name = target_item.get("name")
		target_data.type = target_item.tag

		for child in target_item.getchildren():

			# If the tag is a coverage tag, extract the coverage information
			if child.tag == "coverage":
				match = re.findall(r'[0-9]+', child.get("value"))

				# DEBUG-------------------------------------------------------------
				#print "Matches (" + str(target_data.name) + " -> " + str(target_data.type) + "): " + str(match)

				if child.get("type") == "class, %":
					target_data.class_coverage = float(match[0]) / 100
				if child.get("type") == "method, %":
					target_data.method_coverage = float(match[0]) / 100
				if child.get("type") == "block, %":
					target_data.block_coverage = float(match[0]) / 100
				if child.get("type") == "line, %":
					target_data.line_coverage = float(match[0]) / 100

			# If the tag is a package, srcfile, class, or methd, recursively call the function
			else:
				target_data.addChild( self.constructTargetTree( child ) )


		return target_data




	def getOverallResults(self):
		return self.listofoverallresults


	def getStatsResults(self):
		return self.listofstatsresults


	def getTargetResults(self):
		return self.listoftargetresults


	def getTargetComplement(self):
		return self.list_target_complement


	def getTargets(self):
		return self.target_list










