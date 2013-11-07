



#	
#	"Smart" sulley definition creator
#	
#	
#	

import sys, random
import pickle, os, imp
import traceback


# Add the analyzer to the path - so that pickle can import the correct classes to reconstruct the file
#sys.path.append('../Analyzer')

from Analyzer import analyzer_helpers


class SulleyHelpers(object):

	def __init__(self, def_name=str(random.random())):
		self.TAB_SPACE = "    "
		self.NEW_LINE = "\r\n"

		# Initialize the definition to include the proper import statements, comments, and given init name
		self.DEFINITION = 	self.NEW_LINE + self.NEW_LINE + "# Auto Generated Protocol Definition" + self.NEW_LINE + \
							"# SulleyHelpers.py" + self.NEW_LINE + self.NEW_LINE + self.NEW_LINE + \
							"from sulley import *" + self.NEW_LINE + "import random" + self.NEW_LINE + self.NEW_LINE + \
							"s_initialize(\"" + def_name + "\")" + self.NEW_LINE + self.NEW_LINE



	def getIndent(self, indent_level=0):
		return indent_level * self.TAB_SPACE


	def getDefinition(self):
		return self.DEFINITION

	def addToDefinition(self, code=""):
		self.DEFINITION = self.DEFINITION + str(code)
		return self.DEFINITION



	# takes the url, text, and indent level of the anchor html tag
	# url in the format http://www.url.com/
	# produces an anchor that links to the url with a random path attached to it, and with the specified text
	def addHTMLAnchor(self, url="", text="", indent_level=0):
		local_indentation = self.getIndent(indent_level)

		# s_static("<a href=\"url")
		# s_string("<random float here>")
		# s_static("\">text</a>")

		anchor_code = local_indentation + "# Start of html anchor code" + self.NEW_LINE
		anchor_code = anchor_code + local_indentation + "s_static(\"<a href=\\\"" + str(url) + "\")" + self.NEW_LINE
		anchor_code = anchor_code + local_indentation + "s_string(\"" + str(random.random()) + "\")" + self.NEW_LINE
		anchor_code = anchor_code + local_indentation + "s_static(\"\\\">" + str(text) + "</a>\")" + self.NEW_LINE
		anchor_code = anchor_code + local_indentation + "# End of html anchor code" + self.NEW_LINE + self.NEW_LINE
		return anchor_code


	# creates an img tag in Sulley format to be fuzzed
	# url in the format http://www.url.com/
	def addHTMLImg(self, url="", alt_text="", indent_level=0):
		local_indentation = self.getIndent(indent_level)

		# s_static("<img src=\"url")
		# s_string("<random float here>")
		# s_static("\" alt=\"")
		# s_string("alt img text")
		# s_static("\" />")

		img_code = local_indentation + "# Start of html img code" + self.NEW_LINE
		img_code = img_code + local_indentation + "s_static(\"<img src=\\\"" + url + "\")" + self.NEW_LINE
		img_code = img_code + local_indentation + "s_string(\"" + str(random.random()) + "\")" + self.NEW_LINE
		img_code = img_code + local_indentation + "s_static(\"\\\" alt=\\\"\")" + self.NEW_LINE
		img_code = img_code + local_indentation + "s_string(\"" + alt_text + "\")" + self.NEW_LINE
		img_code = img_code + local_indentation + "s_static(\"\\\" />\")" + self.NEW_LINE
		img_code = img_code + local_indentation + "# End of html img code" + self.NEW_LINE + self.NEW_LINE
		return img_code


	# Creates am html div block in Sulley format to be fuzzed
	def addHTMLDivBlock(self, accesskey="", div_class="", div_id="", style="", onload="", div_content="", indent_level=0):
		local_indentation = self.getIndent(indent_level)

		# HTML:
		# 
		# <div accesskey="" class="" id="" style="" onload="">
		# 	<content>
		# </div>
		#
		# SULLEY:
		# 
		# s_static("<div")
		# s_static(" class=\"")
		# s_string(class)
		# s_static("\"")
		# 
		# ...
		# 
		# s_static(">")
		# 
		# [content]
		# 
		# s_static("</div>")

		div_code = local_indentation + "# Start of html div " + str(div_id) + self.NEW_LINE
		div_code = div_code + local_indentation + "s_static(\"<div\")" + self.NEW_LINE

		if accesskey:
			div_code = div_code + local_indentation + "s_static(\" accesskey=\\\"\")" + self.NEW_LINE + \
						local_indentation + "s_string(\"" + accesskey + "\")" + self.NEW_LINE + \
						local_indentation + "s_static(\"\\\"\")" + self.NEW_LINE
		if div_class:
			div_code = div_code + local_indentation + "s_static(\" class=\\\"\")" + self.NEW_LINE + \
						local_indentation + "s_string(\"" + div_class + "\")" + self.NEW_LINE + \
						local_indentation + "s_static(\"\\\"\")" + self.NEW_LINE
		if div_id:
			div_code = div_code + local_indentation + "s_static(\" id=\\\"\")" + self.NEW_LINE + \
						local_indentation + "s_string(\"" + div_id + "\")" + self.NEW_LINE + \
						local_indentation + "s_static(\"\\\"\")" + self.NEW_LINE
		if style:
			div_code = div_code + local_indentation + "s_static(\" style=\\\"\")" + self.NEW_LINE + \
						local_indentation + "s_string(\"" + style + "\")" + self.NEW_LINE + \
						local_indentation + "s_static(\"\\\"\")" + self.NEW_LINE
		if onload:
			div_code = div_code + local_indentation + "s_static(\" onload=\\\"\")" + self.NEW_LINE + \
						local_indentation + "s_string(\"" + onload + "\")" + self.NEW_LINE + \
						local_indentation + "s_static(\"\\\"\")" + self.NEW_LINE

		div_code = div_code + local_indentation + "s_static(\">\")" + self.NEW_LINE
		div_code = div_code + div_content + self.NEW_LINE
		div_code = div_code + local_indentation + "s_static(\"</div>\")" + self.NEW_LINE
		div_code = div_code + local_indentation + "# End of html div " + str(div_id) + self.NEW_LINE + self.NEW_LINE
		return div_code


	# Generate a basic HTML IFrame in Sulley notation
	def addHTMLIFrame(self, frame_name="", frame_src="", onload="", frame_content="", indent_level=0):
		local_indentation = self.getIndent(indent_level)

		# HTML:
		# <iframe name="" src="" onload=""></iframe>
		# 
		# SULLEY:
		# s_static("<iframe")
		# s_static(" name=\"")
		# s_string("[frame_name]")
		# s_static("\"")
		# ...
		# s_static(">")
		# [frame_content]
		# s_static("</iframe>")

		frame_code = local_indentation + "# Start of html iFrame " + str(frame_name) + self.NEW_LINE
		frame_code = frame_code + local_indentation + "s_static(\"<iframe\")" + self.NEW_LINE

		if frame_name:
			frame_code = frame_code + local_indentation + "s_static(\" name=\\\"\")" + self.NEW_LINE + \
						local_indentation + "s_string(\"" + frame_name + "\")" + self.NEW_LINE + \
						local_indentation + "s_static(\"\\\"\")" + self.NEW_LINE
		if frame_src:
			frame_code = frame_code + local_indentation + "s_static(\" src=\\\"\")" + self.NEW_LINE + \
						local_indentation + "s_string(\"" + frame_src + "\")" + self.NEW_LINE + \
						local_indentation + "s_static(\"\\\"\")" + self.NEW_LINE
		if onload:
			frame_code = frame_code + local_indentation + "s_static(\" onload=\\\"\")" + self.NEW_LINE + \
						local_indentation + "s_string(\"" + onload + "\")" + self.NEW_LINE + \
						local_indentation + "s_static(\"\\\"\")" + self.NEW_LINE

		frame_code = frame_code + local_indentation + "s_static(\">\")" + self.NEW_LINE
		frame_code = frame_code + frame_content + self.NEW_LINE
		frame_code = frame_code + local_indentation + "s_static(\"</iframe>\")" + self.NEW_LINE
		frame_code = frame_code + local_indentation + "# End of html iFrame " + str(frame_name) + self.NEW_LINE + self.NEW_LINE
		return frame_code



	def addHTMLObject(self, data="", name="", obj_contents="", indent_level=0):
		local_indentation = self.getIndent(indent_level)

		# HTML:
		# <object data="" name=""></object>
		# 
		# SULLEY:
		# s_static("<object")
		# s_static(" data=\")
		# s_string("[data]")
		# s_static("\"")
		# ...
		# s_static(">")
		# [obj_contents]
		# s_static("</object>")

		obj_code = local_indentation + "# Start of html object code" + self.NEW_LINE
		obj_code = obj_code + local_indentation + "s_static(\"<object\")" + self.NEW_LINE

		if data:
			obj_code = obj_code + local_indentation + "s_static(\" data=\\\"\")" + self.NEW_LINE + \
						local_indentation + "s_string(\"" + data + "\")" + self.NEW_LINE + \
						local_indentation + "s_static(\"\\\"\")" + self.NEW_LINE
		if name:
			obj_code = obj_code + local_indentation + "s_static(\" name=\\\"\")" + self.NEW_LINE + \
						local_indentation + "s_string(\"" + name + "\")" + self.NEW_LINE + \
						local_indentation + "s_static(\"\\\"\")" + self.NEW_LINE

		obj_code = obj_code + local_indentation + "s_static(\">\")" + self.NEW_LINE
		obj_code = obj_code + obj_contents + self.NEW_LINE
		obj_code = obj_code + local_indentation + "s_static(\"</object>\")" + self.NEW_LINE
		obj_code = obj_code + local_indentation + "# End of html object code" + self.NEW_LINE + self.NEW_LINE
		return obj_code


	def addHTMLJScript(self, script_src="test", indent_level=0):
		local_indentation = self.getIndent(indent_level)

		# HTML:
		# <script src="[fuzz]">
		# document.getElementById("[fuzz]").innerHTML="[fuzz]"
		# </script>
		# 
		# SULLEY:
		# s_static("<script")
		# s_static(" src=\"")
		# s_string("[random]")
		# s_static("\"")
		# s_static(">")
		# s_static("document.getElementById(\"")
		# s_string("[random]")
		# s_static("\").innerHTML=\"")
		# s_string("[random]")
		# s_static("\"")
		# s_static("</script>")

		js_code = local_indentation + "# Start of JavaScript code" + self.NEW_LINE
		js_code = js_code + local_indentation + "s_static(\"<script\")" + self.NEW_LINE

		if script_src:
			js_code = js_code + local_indentation + "s_static(\" src=\\\"\")" + self.NEW_LINE + \
						local_indentation + "s_string(\"" + script_src + "\")" + self.NEW_LINE + \
						local_indentation + "s_static(\"\\\"\")" + self.NEW_LINE

		js_code = js_code + local_indentation + "s_static(\">\")" + self.NEW_LINE + \
						local_indentation + "s_static(\"document.getElementById(\\\"\")" + self.NEW_LINE + \
						local_indentation + "s_string(\"" + str(random.random()) + "\")" + self.NEW_LINE + \
						local_indentation + "s_static(\"\\\").innerHTML=\\\"\")" + self.NEW_LINE + \
						local_indentation + "s_string(\"" + str(random.random()) + "\")" + self.NEW_LINE + \
						local_indentation + "s_static(\"\\\"\")" + self.NEW_LINE + \
						local_indentation + "s_static(\"</script>\")" + self.NEW_LINE + self.NEW_LINE

		js_code = js_code + local_indentation + "s_static(\"document.location=\\\"\")" + self.NEW_LINE + \
						local_indentation + "s_string(\"127.0.0.1\")" + self.NEW_LINE + \
						local_indentation + "s_static(\"\\\"\")" + self.NEW_LINE

		js_code = js_code + local_indentation + "# End of JavaScript code" + self.NEW_LINE + self.NEW_LINE

		return js_code



	def addHTMLApplet(self, contents="", indent_level=0):
		local_indentation = self.getIndent(indent_level)

		# HTML:
		# <applet code="[random]">[contents]</applet>
		# 
		# SULLEY:
		# s_static("<applet code=\"")
		# s_string(str(random.random()))
		# s_static("\">")
		# [contents]
		# s_static("</applet>")

		a_code = local_indentation + "s_static(\"<applet code=\\\"\")" + self.NEW_LINE + \
					local_indentation + "s_string(\"" + str(random.random()) + "\")" + self.NEW_LINE + \
					local_indentation + "s_static(\"\\\">\")" + self.NEW_LINE
		
		a_code = a_code + contents

		a_code = a_code + local_indentation + "s_static(\"</applet>\")" + self.NEW_LINE
		return a_code






	# ---------------------------------------------------------------------------------------------------------
	#	Sulley Functions That Aren't Related To HTML
	# ---------------------------------------------------------------------------------------------------------

	# params: block name (string), contents of block (string), indent_level (int)
	# returns a string with the correct indentation and block information
	# NOTE: Assumes that the contents is correctly indented!!!!
	def addBlock(self, b_name="block" + str(random.random()), contents="", indent_level=0):
		local_indentation = self.getIndent(indent_level)

		# if s_block_start("block name"):
		#	[contents]
		# s_block_end("block name")

		block_code = local_indentation + "if s_block_start(\"" + str(b_name) + "\"):" + self.NEW_LINE
		block_code = block_code + str(contents) + self.NEW_LINE
		block_code = block_code + local_indentation + "s_block_end(\"" + str(b_name) + "\")" + self.NEW_LINE + self.NEW_LINE
		return block_code


	def addSulleyChecksum(self, alg='sha1', init_text=str(random.random()), indent_level=0):

		local_indentation = self.getIndent(indent_level)

		if alg in ['sha1', 'md5', 'crc32', 'adler32']:
			return local_indentation + "s_checksum(\"" + init_text + "\", algorithm=\"" + alg + "\")"  + self.NEW_LINE
		else:
			return local_indentation + "s_checksum(\"" + init_text + "\", algorithm=\"sha1\")" + self.NEW_LINE


	def addSulleyStatic(self, static_str="", indent_level=0):
		local_indentation = self.getIndent(indent_level)
		return local_indentation + "s_static(\"" + str(static_str) + "\")" + self.NEW_LINE




# Helper functions that don't generate Sulley protocol definitions, but help with their analysis and processing
class HelperFunctions(object):

	# Load the given pickled file and return the contents
	def loadPickledFile(self, pfile):
		f = None
		thislist = []
		try:
			f = open(pfile, 'rb')
		except IOError as e:
			print 'I/O error ({0}): {1}'.format(e.errno, e.strerror)
			print 'Could not load pickeled file PD_Helper -> HelperFunctions'
		except:
			print 'An unexpected error occurred while trying to open parser defect density file: %s' % (pfile)

		if f is not None:
			try:
				thislist = pickle.load(f)
				f.close()
				return thislist
			except IOError as e:
				print 'An error occurred while trying to close parser results file: %s' % (pfile)
			except Exception as ex:
				print 'An unexpected error occurred while loading data from the parser results file: %s' % (pfile)
				traceback.print_exc()
		else:
			sys.exit()

		return thislist



if __name__ == "__main__":
	'''
	s = SulleyHelpers("HTML Anchors")
	print ""

	'''

	# BASIC HTML PAGE (BELOW)
	'''
	html_init = s.addSulleyStatic("<html><head><title>Sulley Says Hello!</title></head><body>", 1)

	anchors = s.addBlock("anchors", 
		s.addHTMLAnchor("http://127.0.0.1/", "test 1", 2) + \
		s.addHTMLAnchor("http://127.0.0.1/", "test 2", 2) + \
		s.addHTMLAnchor("http://127.0.0.1/", "test 4", 2), 
		1)

	img = s.addHTMLImg("http://127.0.0.1/", "alt img text", 1)

	anchors_checksum_line = s.addSulleyStatic("<a href=\\\"http://127.0.0.1/", 1) + \
							s.addSulleyChecksum("sha1", "anchors", 1) + \
							s.addSulleyStatic("\\\">internal checksum anchor</a>", 1)

	all_html_block = s.addBlock("All HTML", 
		html_init + anchors + img + anchors_checksum_line,
		0)

	html_checksum_line = 	s.addSulleyStatic("<a href=\\\"http://127.0.0.1/", 0) + \
							s.addSulleyChecksum("sha1", "All HTML", 0) + \
							s.addSulleyStatic("\\\">external checksum anchor</a>", 0)

	html_end = s.addSulleyStatic("</body></html>")

	print s.addToDefinition(all_html_block + html_checksum_line + html_end)
	'''


	# Advanced HTML page (Divs, iframes, objects, links, scripts, and imgs)
	'''
	html_init = s.addSulleyStatic("<html><head><title>Sulley Says Hello!</title></head><body>", 1)

	t1 = s.addHTMLAnchor("http://127.0.0.1/", "test 1", 1)
	t1 = t1 + s.addHTMLImg("http://127.0.0.1/", "alt img text", 1)

	#def addHTMLDivBlock(self, accesskey="", div_class="", div_id="", style="", onload="", div_content="", indent_level=0):
	#div_t1 = s.addHTMLDivBlock(div_class="test 1", div_id="anchors_div", div_content=t1, indent_level=1)

	#def addHTMLIFrame(self, frame_name="", frame_src="", onload="", frame_content="", indent_level=0):
	t2 = s.addHTMLIFrame(frame_name="test 2", frame_src="test 2 source", onload="test", frame_content=t1, indent_level=1)
	div_t2 = s.addHTMLDivBlock(div_class="test 2", div_id="iframe div", div_content=t2, indent_level=1)

	#def addHTMLObject(self, data="", name="", obj_contents="", indent_level=0):
	t3 = s.addHTMLObject(data="test", name="test object", indent_level=1, obj_contents=t1)
	div_t3 = s.addHTMLDivBlock(div_class="test 3", div_id="object div", div_content=t3, indent_level=1)

	all_html_block = s.addBlock("All HTML",	html_init + t1 + div_t2 + div_t3 + s.addHTMLJScript(indent_level=1), 0)
	html_checksum_line = s.addSulleyStatic("<a href=\\\"http://127.0.0.1/") + \
						s.addSulleyChecksum("sha1", "All HTML") + \
						s.addSulleyStatic("\\\">") + \
						s.addSulleyChecksum("sha1", "All HTML") + \
						s.addSulleyStatic("</a>")

	html_end = s.addSulleyStatic("</body></html>")

	print s.addToDefinition(all_html_block + html_checksum_line + html_end)
	'''


	'''
	<html>
	<head><title></title>

	<script src="[fuzz]">
	document.getElementById("[fuzz]").innerHTML="[fuzz]"
	</script>

	</head>
	<body>
		<div class="test 1" name="anchors">
			<a href="">test 1</a>
			<a href="">
				<img src="" alt="" />
			</a>
		</div>
		<div class="test 2" name="iframe">
			<iframe name="" src="" onload="">
				<a href="">iframe test 1</a>
				<a href="">
					<img src="" alt="" />
				</a>
			</iframe>
		</div>
		<div class="test 3" name="obj">
			<object data="" name="">
				<a href=""><obj test 1</a>
				<a href="">
					<img src="" alt="" />
				</a>
			</object>
		</div>
	</body>
	</html>
	'''









