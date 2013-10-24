
#
#	Protocol Definition Creator for the sulley framework.
#	
#	This program takes the output from the genetic algorithm analysis, and the 
#	target information from the analyzer, and attempts to dynamically create a
#	protocol definition (for the Sulley framework) that maximizes coverage of the
#	target code within a target java application.
#	
#	Template -----------> 
#	Target Information ->	Protocol Definition Creator.py
#	GA Analysiz Data --->


from PD_Helpers import SulleyHelpers, HelperFunctions

import imp, os

aconf = imp.load_source('DETAILS', '../Config/analysis.py')
Bug = imp.load_source('FB_Bug', '../Analyzer/analyzer_helpers.py')
FB_DD = imp.load_source('FB_PackageDefectDensity', '../Analyzer/analyzer_helpers.py')



class PDef_Creator(object):

	def __init__(self):
		self.generator = SulleyHelpers("Protocol Definition")
		self.helper_functions = HelperFunctions()
		self.target_list = self.helper_functions.loadPickledFile(
							".." + str(os.sep) + aconf.DETAILS.PATH_TO_ANALYZER + aconf.DETAILS.TARGET_FILENAME
							)

		# Flow:
		#	
		#	Initialize GA
		#	Initialize Template Protocol Definition
		#	Load targets
		#	
		#	
		#	





		#-----------------------------------------------------------------------------------------------------
		# DEBUG
		#-----------------------------------------------------------------------------------------------------
		for item in self.target_list:
			item.printNicely()



	def genHTMLAnchors(self):
		html_init = self.generator.addSulleyStatic("<html><head><title>Sulley Says Hello!</title></head><body>", 1)

		anchors = self.generator.addBlock("anchors", 
			self.generator.addHTMLAnchor("http://127.0.0.1/", "test 1", 2) + \
			self.generator.addHTMLAnchor("http://127.0.0.1/", "test 2", 2) + \
			self.generator.addHTMLAnchor("http://127.0.0.1/", "test 4", 2), 
			1)

		img = self.generator.addHTMLImg("http://127.0.0.1/", "alt img text", 1)

		anchors_checksum_line = self.generator.addSulleyStatic("<a href=\\\"http://127.0.0.1/", 1) + \
								self.generator.addSulleyChecksum("sha1", "anchors", 1) + \
								self.generator.addSulleyStatic("\\\">internal checksum anchor</a>", 1)

		all_html_block = self.generator.addBlock("All HTML", 
			html_init + anchors + img + anchors_checksum_line,
			0)

		html_checksum_line = 	self.generator.addSulleyStatic("<a href=\\\"http://127.0.0.1/", 0) + \
								self.generator.addSulleyChecksum("sha1", "All HTML", 0) + \
								self.generator.addSulleyStatic("\\\">external checksum anchor</a>", 0)

		html_end = self.generator.addSulleyStatic("</body></html>")

		return self.generator.addToDefinition(all_html_block + html_checksum_line + html_end)



if __name__ == "__main__":
	d = PDef_Creator()
	code = d.genHTMLAnchors()
	filename = "protocol.py"

	with open(filename, "w") as f:
		f.write(code)

	print "Protocol written to " + filename












