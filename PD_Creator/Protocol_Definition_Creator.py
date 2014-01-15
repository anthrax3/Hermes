'''

	Author:	Caleb Shortt

	Protocol Definition Creator for the sulley framework.
	
	This program takes the output from the genetic algorithm analysis, and the 
	target information from the analyzer, and attempts to dynamically create a
	protocol definition (for the Sulley framework) that maximizes coverage of the
	target code within a target java application.
	
	Template -----------> 
	Target Information ->	Protocol Definition Creator.py
	GA Analysiz Data --->

'''



import imp
import os

from Config.analysis import DETAILS
from PD_Helpers import SulleyHelpers, HelperFunctions, HTMLTreeConstructor


class PDef_Creator(object):

	def __init__(self):
		self.generator = SulleyHelpers("Protocol Definition")
		self.html_tree = HTMLTreeConstructor("Protocol Definition")
		#self.helper_functions = HelperFunctions()
		#self.target_list = self.helper_functions.loadPickledFile(DETAILS.PATH_TO_ANALYZER + DETAILS.TARGET_FILENAME)


	def reset(self):
		self.generator = SulleyHelpers("Protocol Definition")
		self.html_tree = HTMLTreeConstructor("Protocol Definition")
		#self.helper_functions = HelperFunctions()



	def generate_html(self, chromosome=[1, 1, 1, 1, 1, 1, 1], nesting_levels=3):
		'''

			Generate the structure of the tree based on the given chromosome

			The HTML tree is already initialized with a basic html structure: 
			html, head, title, and body nodes. Child nodes are added to these
			to create a protocol definition.

			Once the tree structure is created, a call to the traverse 
			function returns the protocol definition in string format (in 
			Sulley notation)

		'''

		#self.add_checksum_anchor_node("first_cs_a", "body", "checksumthis!")

		# <img> nested in a <a> nested in a <div>
		#self.add_div_node("first_div", "body")
		#self.add_anchor_node("first_a", "first_div")
		#self.add_img_node("first_img", "first_a")

		# <img> nested in an <a>
		#self.add_anchor_node("another_a", "body")
		#self.add_text_node("first_txt", "another_a", "This is just text")

		#self.add_div_node("io_div", "body")
		#self.add_iframe_node("first_iframe", "io_div")
		#self.add_object_node("first_object", "first_iframe")
		#self.add_script_node("first_script", "body")
		#self.add_applet_node("first_applet", "body")

		# Define what is allowed - and what is not
		self.html_tree.set_chromosome(chromosome)

		self.html_tree.add_script_node("basic_js", "head")

		# Create a Sulley block with checksum to put all content
		self.html_tree.add_block_node("body_block", "body")
		self.html_tree.add_checksum_anchor_node(
			"body_block_cs", 
			"body", 
			"body_block")

		curr_p = "body_block"

		for i in range(nesting_levels):

			# Create an <img> tag inside an <a> tag - wrap in block + checksum
			self.html_tree.add_block_node(curr_p + "_a1_block", curr_p)
			self.html_tree.add_anchor_node(curr_p + "_a1", curr_p + "_a1_block")
			self.html_tree.add_img_node(curr_p + "_img1", curr_p + "_a1")
			self.html_tree.add_checksum_anchor_node(
				curr_p + "_a1_block_cs", 
				curr_p, 
				curr_p + "_a1_block")

			# Create nested <a><img></img></a> in an iframe
			self.html_tree.add_iframe_node(curr_p + "_if1", curr_p)
			self.html_tree.add_anchor_node(curr_p + "_if1_a1", curr_p + "_if1")
			self.html_tree.add_img_node(curr_p + "_if1_img1", curr_p + "_if1_a1")

			self.html_tree.add_object_node(curr_p + "_obj1", curr_p)
			self.html_tree.add_anchor_node(curr_p + "_obj1_a1", curr_p + "_obj1")
			self.html_tree.add_img_node(curr_p + "_obj1_img1", curr_p + "_obj1")

			self.html_tree.add_applet_node(curr_p + "_app1", curr_p)
			self.html_tree.add_anchor_node(curr_p + "_app1_a1", curr_p + "_app1")
			self.html_tree.add_img_node(curr_p + "_app1_img1", curr_p + "_app1")

			self.html_tree.add_div_node(curr_p + "_div", curr_p)
			curr_p = curr_p + "_div"

		return self.html_tree.getTraversal()



















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
			self.generator.addSulleyStatic("\\\">SP CS ", indent_level) + \
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



	# ------------------------------------------------------------------------------------------------------------------------
	def genStaticHTMLPage(self):
		#	<html>
		#	<head><title></title></head>
		#	<body>
		#	</body>
		#	</html>

		html = self.generator.addSulleyStatic("<html><head><title></title></head><body></body></html>", 0)
		return self.generator.addToDefinition(html)


	# ------------------------------------------------------------------------------------------------------------------------
	def genStaticHTMLPageWithOneAnchor(self):
		str_html = "<html><head><title></title></head><body><a href=\\\"http://127.0.0.1/test\\\"></a></body></html>"
		html = self.generator.addSulleyStatic(str_html, 0)
		return self.generator.addToDefinition(html)






# DEBUG
'''
if __name__ == "__main__":
	d = PDef_Creator()
	#code = d.genHTMLAnchors()
	#code = d.genAdvancedHTMLAnchors()
	#code = d.genAdvancedHTML([1,1,1,1,1,1,1])

	code = d.generate_html()
	filename = "protocol.py"

	with open(filename, "w") as f:
		f.write(code)

	print "Protocol written to " + filename
'''












