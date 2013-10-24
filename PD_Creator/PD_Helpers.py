



#	
#	"Smart" sulley definition creator
#	
#	
#	

import sys, random
import pickle, os, imp


# Add the analyzer to the path - so that pickle can import the correct classes to reconstruct the file
sys.path.append('../Analyzer')


class SulleyHelpers(object):

	def __init__(self, def_name=str(random.random())):
		self.TAB_SPACE = "    "
		self.NEW_LINE = "\r\n"

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
		block_code = block_code + local_indentation + "s_block_end(\"" + str(b_name) + "\")" + self.NEW_LINE
		return block_code


	# takes the url, text, and indent level of the anchor html tag
	# url in the format http://www.url.com/
	# produces an anchor that links to the url with a random path attached to it, and with the specified text
	def addHTMLAnchor(self, url="", text="", indent_level=0):
		local_indentation = self.getIndent(indent_level)

		# s_static("<a href=\"url")
    	# s_string("<random float here>")
    	# s_static("\">text</a>")

		anchor_code = local_indentation + "s_static(\"<a href=\\\"" + str(url) + "\")" + self.NEW_LINE
		anchor_code = anchor_code + local_indentation + "s_string(\"" + str(random.random()) + "\")" + self.NEW_LINE
		anchor_code = anchor_code + local_indentation + "s_static(\"\\\">" + str(text) + "</a>\")" + self.NEW_LINE + self.NEW_LINE
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

		img_code = local_indentation + "s_static(\"<img src=\\\"" + url + "\")" + self.NEW_LINE
		img_code = img_code + local_indentation + "s_string(\"" + str(random.random()) + "\")" + self.NEW_LINE
		img_code = img_code + local_indentation + "s_static(\"\\\" alt=\\\"\")" + self.NEW_LINE
		img_code = img_code + local_indentation + "s_string(\"" + alt_text + "\")" + self.NEW_LINE
		img_code = img_code + local_indentation + "s_static(\"\\\" />\")" + self.NEW_LINE
		return img_code


	def addSulleyChecksum(self, alg='sha1', init_text=str(random.random()), indent_level=0):

		local_indentation = self.getIndent(indent_level)

		if alg in ['sha1', 'md5', 'crc32', 'adler32']:
			return local_indentation + "s_checksum(\"" + init_text + "\", algorithm=\"" + alg + "\")"  + self.NEW_LINE
		else:
			return local_indentation + "s_checksum(\"" + init_text + "\", algorithm=\"sha1\")" + self.NEW_LINE


	def addSulleyStatic(self, static_str="", indent_level=0):
		local_indentation = self.getIndent(indent_level)
		return local_indentation + "s_static(\"" + str(static_str) + "\")" + self.NEW_LINE




class HelperFunctions(object):

	# Load the given pickled file and return the contents
	def loadPickledFile(self, pfile):
		f = None
		thislist = []
		try:
			f = open(pfile, 'rb')
		except IOError as e:
			print 'I/O error ({0}): {1}'.format(e.errno, e.strerror)
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
				print str(sys.exc_info()[0])
		else:
			sys.exit()

		return thislist



if __name__ == "__main__":
	s = SulleyHelpers("HTML Anchors")
	print ""

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









