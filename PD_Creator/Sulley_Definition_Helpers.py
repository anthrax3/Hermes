
'''
	
	Author:	Caleb Shortt
	Date:	January 2014

	Description:
		This module contains helpers that are Sulley-specific and for the
		creation of a protocol definition.

'''


import random
import os


class Sulley_Code_Helper(object):
	'''
		This class contains code creation methods specific to Sulley
	'''

	def __init__(self):
		self.TAB = "    "


	def generateInitCode(self, defn_name, author, description="", source=""):
		code = "'''" + 2*os.linesep + \
			self.TAB + "Author: " + str(author) + os.linesep + \
			os.linesep + \
			self.TAB + "Description:" + os.linesep + \
			2*self.TAB + str(description) + \
			os.linesep + \
			2*self.TAB + "Source: " + str(source) + 2*os.linesep + \
			"'''" + 3*os.linesep + \
			"from sulley import *" + os.linesep + \
			"import random" + 2*os.linesep + \
			"s_initialize(\"" + defn_name + "\")" + \
			2*os.linesep

		return code


	def addBlock(self, 
				b_name="block" + str(random.random()), 
				contents="", 
				indent_level=0):
		'''
			Creates a Sulley block with the given name at the indent level
		'''
		indent = self.TAB*indent_level

		code = indent + "if s_block_start(\"" + str(b_name) + "\"):" + \
				os.linesep + str(contents) + os.linesep + \
				indent + "s_block_end(\"" + str(b_name) + "\")" + \
				os.linesep + os.linesep

		return code



	def addChecksum(self, 
				alg='sha1', 
				init_text=str(random.random()), 
				indent_level=0):
		'''
			Creates a checksum in Sulley Protocol Definition Notation
		'''

		indent = self.TAB*indent_level

		if alg in ['md5', 'crc32', 'adler32']:
			return indent + "s_checksum(\"" + init_text + \
				"\", algorithm=\"" + alg + "\")"  + os.linesep
		else:
			return indent + "s_checksum(\"" + init_text + \
				"\", algorithm=\"sha1\")" + os.linesep
	


	def addStatic(self, 
				static_str="", 
				indent_level=0):
		'''
			Creates a static string in Sulley Notation.
			A static string will not be fuzzed.
		'''

		indent = self.TAB*indent_level
		return indent + "s_static(\"" + str(static_str) + "\")" + os.linesep



	def addString(self, in_str="", indent_level=0):
		'''
			Creates a string in Sulley Notation.
			A string will be fuzzed.
		'''

		indent = self.TAB*indent_level
		return indent + "s_string(\"" + str(in_str) + "\")" + os.linesep



	def addJavascript(self, indent_level=0):
		indent = self.TAB*indent_level

		js = os.linesep + indent + "# JavaScript Code" + 2*os.linesep + \
			self.addStatic("document.getElementById(\\\"", indent_level) + \
			self.addString("test", indent_level) + \
			self.addStatic("\\\").innerHTML=\\\"", indent_level) + \
			self.addString("test", indent_level) + \
			self.addStatic("\\\"", indent_level)

		return js








'''
if __name__ == "__main__":
	s = Sulley_Code_Helper()

	print s.addBlock(contents="Contents here!!!")
	print s.addChecksum()
	print s.addStatic("test static")
'''


