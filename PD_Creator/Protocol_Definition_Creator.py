
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

from Config.analysis import DETAILS
#from Analyzer.analyzer_helpers import FB_Bug, FB_PackageDefectDensity

'''
aconf = imp.load_source('DETAILS', '../Config/analysis.py')
Bug = imp.load_source('FB_Bug', '../Analyzer/analyzer_helpers.py')
FB_DD = imp.load_source('FB_PackageDefectDensity', '../Analyzer/analyzer_helpers.py')
'''


class PDef_Creator(object):


	# ------------------------------------------------------------------------------------------------------------------------
	def __init__(self):
		self.generator = SulleyHelpers("Protocol Definition")
		self.helper_functions = HelperFunctions()
		self.target_list = self.helper_functions.loadPickledFile(DETAILS.PATH_TO_ANALYZER + DETAILS.TARGET_FILENAME)




	# ------------------------------------------------------------------------------------------------------------------------
	def reset(self):
		self.generator = SulleyHelpers("Protocol Definition")
		self.helper_functions = HelperFunctions()



	# ------------------------------------------------------------------------------------------------------------------------
	# 'Smart Generator'
	# ------------------------------------------------------------------------------------------------------------------------
	# (Links Enabled, imgs enabled, divs enabled, iframes enabled, objects enabled, js enabled, applets enabled)
	# 1=on, 0=off
	# [1,1,1,1,1,1,1] = all on
	# [0,0,0,0,0,0,0] = all off

	# Parameter is a binary number (in int form) representing flags for each of the options listed above - in that order
	def genAdvancedHTML(self, chromosome=[1, 1, 1, 1, 1, 1, 1]):

		has_links 	= (chromosome[0] == 1)
		has_imgs	= (chromosome[1] == 1)
		has_divs	= (chromosome[2] == 1)
		has_iframes	= (chromosome[3] == 1)
		has_objects	= (chromosome[4] == 1)
		has_js		= (chromosome[5] == 1)
		has_applets	= (chromosome[6] == 1)

		html_init = self.generator.addSulleyStatic("<html><head><title>Sulley Says Hello!</title></head><body>", 1)

		# Add exterior link and img (Will be checksummed in a block, so indent)
		t1 = ""
		if has_links:
			t1 = t1 + self.generator.addHTMLAnchor("http://127.0.0.1/", "test 1", 2)
		if has_imgs:
			t1 = t1 + self.generator.addHTMLImg("http://127.0.0.1/", "alt img text", 2)

		# If links or imgs are enabled, generate the block to contain them
		t1_block = ""
		t1_csum = ""
		if has_links or has_imgs:
			t1_block = self.generator.addBlock("t1_block", t1, 1)
			t1_csum = self.genSelfPointingChecksumLink("t1_block", 1)


		lnk_and_img = ""
		if has_links:
			lnk_and_img = lnk_and_img + self.generator.addHTMLAnchor("http://127.0.0.1/", "test 1", 1)
		if has_imgs:
			lnk_and_img = lnk_and_img + self.generator.addHTMLImg("http://127.0.0.1/", "alt img text", 1)

		t2_iframe = ""
		if has_iframes:
			t2_iframe = self.generator.addHTMLIFrame(
				frame_name="test 2", 
				frame_src="test 2 source", 
				onload="test", 
				frame_content=lnk_and_img, 
				indent_level=1
				)

		t3_object = ""
		if has_objects:
			t3_object = self.generator.addHTMLObject(
				data="test", 
				name="test object", 
				indent_level=1, 
				obj_contents=lnk_and_img
				)

		t4_js = ""
		if has_js:
			t4_js = self.generator.addHTMLJScript(indent_level=1)

		t5_applet = ""
		if has_applets:
			t5_applet = self.generator.addHTMLApplet(
				contents=lnk_and_img,
				indent_level=1
				)

		t6_div_t1 = ""
		t6_div_t2 = ""
		t6_div_t3 = ""
		t6_div_t4 = ""
		t6_div_t5 = ""
		if has_divs:
			t6_div_t1 = self.generator.addHTMLDivBlock(
				div_class="lnk_and_img", 
				div_id="lnk_and_img div", 
				div_content=lnk_and_img, 
				indent_level=1
				)

			t6_div_t2 = self.generator.addHTMLDivBlock(
				div_class="t2_iframe", 
				div_id="t2_iframe div", 
				div_content=t2_iframe, 
				indent_level=1
				)

			t6_div_t3 = self.generator.addHTMLDivBlock(
				div_class="t3_object", 
				div_id="t3_object div", 
				div_content=t3_object, 
				indent_level=1
				)

			t6_div_t4 = self.generator.addHTMLDivBlock(
				div_class="t4_js", 
				div_id="t4_js div", 
				div_content=t4_js, 
				indent_level=1
				)

			t6_div_t5 = self.generator.addHTMLDivBlock(
				div_class="t5_applet", 
				div_id="t5_applet div", 
				div_content=t5_applet, 
				indent_level=1
				)

		# Combine all of the created html nice and readably
		bulk_html = html_init + \
					t1_block + \
					t1_csum + \
					t2_iframe + \
					t3_object + \
					t4_js + \
					t5_applet + \
					t6_div_t1 + \
					t6_div_t2 + \
					t6_div_t3 + \
					t6_div_t4 + \
					t6_div_t5

		# Add everything created into a block so that it can be checksummed
		all_html_block = self.generator.addBlock(
			"All HTML", 
			bulk_html, 
			0
			)

		bulk_csum = self.genSelfPointingChecksumLink("All HTML", 0)

		html_end = self.generator.addSulleyStatic("</body></html>")

		return self.generator.addToDefinition(all_html_block + bulk_csum + html_end)





	# ------------------------------------------------------------------------------------------------------------------------
	# TODO: Should this function be in the helper classes?
	def genSelfPointingChecksumLink(self, block_name="test_block", indent_level=0):
		return self.generator.addSulleyStatic("<a href=\\\"http://127.0.0.1/", indent_level) + \
			self.generator.addSulleyChecksum("sha1", block_name, indent_level) + \
			self.generator.addSulleyStatic("\\\">", indent_level) + \
			self.generator.addSulleyChecksum("sha1", block_name, indent_level) + \
			self.generator.addSulleyStatic("</a>", indent_level)



	# Saves the given protocol to the protocol.py file for use by the fuzzer
	def save_protocol(self, protocol, filename="PD_Creator/protocol.py"):
		try:
			with open(filename, "w") as f:
				f.write(protocol)
		except IOError as ioe:
			print 'There was an I/O Error when saving the protocol to ' + str(filename)
		except:
			print 'An Unexpected exception has occurred while saving the protocol definition to ' + str(filename)






	# ------------------------------------------------------------------------------------------------------------------------
	# 'Dumb' Generators (No special specification)
	# ------------------------------------------------------------------------------------------------------------------------

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




	# ------------------------------------------------------------------------------------------------------------------------
	# TODO: Possible improvement: make this a tree structure - this would allow for better dynamic construction (nesting too)
	def genAdvancedHTMLAnchors(self):
		html_init = self.generator.addSulleyStatic("<html><head><title>Sulley Says Hello!</title></head><body>", 1)

		t1 = self.generator.addHTMLAnchor("http://127.0.0.1/", "test 1", 2)
		t1 = t1 + self.generator.addHTMLImg("http://127.0.0.1/", "alt img text", 2)

		t1_block = self.generator.addBlock("t1_block", t1, 1)

		t1_csum = self.generator.addSulleyStatic("<a href=\\\"http://127.0.0.1/", 1) + \
					self.generator.addSulleyChecksum("sha1", "t1_block", 1) + \
					self.generator.addSulleyStatic("\\\">", 1) + \
					self.generator.addSulleyChecksum("sha1", "t1_block", 1) + \
					self.generator.addSulleyStatic("</a>", 1)

		t2 = self.generator.addHTMLAnchor("http://127.0.0.1/", "test 1", 1)
		t2 = t2 + self.generator.addHTMLImg("http://127.0.0.1/", "alt img text", 1)

		t2 = self.generator.addHTMLIFrame(frame_name="test 2", frame_src="test 2 source", onload="test", frame_content=t2, indent_level=1)
		div_t2 = self.generator.addHTMLDivBlock(div_class="test 2", div_id="iframe div", div_content=t2, indent_level=1)

		t3 = self.generator.addHTMLObject(data="test", name="test object", indent_level=1, obj_contents=t2)
		div_t3 = self.generator.addHTMLDivBlock(div_class="test 3", div_id="object div", div_content=t3, indent_level=1)

		all_html_block = self.generator.addBlock(
			"All HTML", 
			html_init + t1_block + t1_csum + div_t2 + div_t3 + self.generator.addHTMLJScript(indent_level=1), 
			0)

		html_checksum_line = self.generator.addSulleyStatic("<a href=\\\"http://127.0.0.1/") + \
							self.generator.addSulleyChecksum("sha1", "All HTML") + \
							self.generator.addSulleyStatic("\\\">") + \
							self.generator.addSulleyChecksum("sha1", "All HTML") + \
							self.generator.addSulleyStatic("</a>")

		html_end = self.generator.addSulleyStatic("</body></html>")

		return self.generator.addToDefinition(all_html_block + html_checksum_line + html_end)


# DEBUG
'''
if __name__ == "__main__":
	d = PDef_Creator()
	#code = d.genHTMLAnchors()
	#code = d.genAdvancedHTMLAnchors()
	code = d.genAdvancedHTML([1,1,1,1,1,1,1])
	filename = "protocol.py"

	with open(filename, "w") as f:
		f.write(code)

	print "Protocol written to " + filename
'''












