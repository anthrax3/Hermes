
'''

	Author:	Caleb Shortt

	Description:
		This module contains class definitions and Sulley notation for HTML.
		Each 'tag class' will contain a 'getPrefix()' and getPostfix() method.
		These classes will be used by HTML Tree Constructor to generate an 
		HTML protocol dynamically.

		These definitions are formatted using the Sulley protocol definition 
		(request) notation.

		All tags must inherit from the 'Generic_HTML_Tag' class

		More advanced tags will require an attributes dictionary that will 
		be accessed during the prefix generation.

		Included as of January 13, 2014:

		Generic_HTML_Tag,	HTML_Empty_tag, 	HTML_tag, 	HEAD_tag, 
		TITLE_tag,			BODY_tag, 			P_tag, 		A_tag, 
		IMG_tag,			DIV_tag				IFRAME_tag,	OBJECT_tag
		SCRIPT_tag			APPLET_tag

'''

import random
import os

from Sulley_Definition_Helpers import Sulley_Code_Helper



class Generic_HTML_Tag(object):
	'''
		A Generic HTML tag class

		This class should not be called directly, but contains the 
		information needed to create HTML tag subclasses
	'''

	STRING = "string"
	STATIC = "static"
	CHECKSUM = "checksum"


	def __init__(self):
		self.prefix = ""
		self.postfix = ""
		self.indent = 0
		self.TAB = "    "
		self.attributes = {}
		self.sulley_helper = Sulley_Code_Helper()


	def formatAttributes(self):
		'''
			Attributes in the form of a dict with a string as the key and 
			a tuple of size 3 as the value. 

			{attribute: (value, type, prefix), ...}

			Ex: {href: ("index.html", "static|string|checksum", "127.0.0.1/"), ...}

			The key is the html tag attribute
			The value is a tuple of size 3 that contains:
				the value of the attribute, 
				the type of sulley string it is, and
				any prefix that will be appended to the string unchanged
		'''
		attr_string = ""
		if self.attributes is not None:
			for key, (attr_value, sulley_type, prefix) in self.attributes.items():

				# Make the attribute static. Ex: s_static("href=\"127.0.0.1/")
				attr_string += self.sulley_helper.addStatic(
									str(key) + "=\\\"" + str(prefix), 
									self.indent
									)

				# Get the value and make it static, string or a checksum
				#	Ex: s_string("123453465456")
				#if sulley_type == "static":
				if sulley_type == self.STATIC:
					attr_string += self.sulley_helper.addStatic(
									attr_value, 
									self.indent
									)

				#elif sulley_type == "string":
				elif sulley_type == self.STRING:
					attr_string += self.sulley_helper.addString(
									attr_value,
									self.indent
									)

				#elif sulley_type == "checksum":
				elif sulley_type == self.CHECKSUM:
					attr_string += self.sulley_helper.addChecksum(
									init_text=attr_value,
									indent_level=self.indent
									)

				# Close the attribute quote.
				attr_string += self.sulley_helper.addStatic(
									"\\\" ", 
									self.indent
									)

		return attr_string


	def getIndent(self):
		return self.indent

	def getPrefix(self):
		return self.prefix

	def getPostfix(self):
		return self.postfix

	def setPrefix(self, prefix):
		self.prefix = prefix

	def setPostfix(self, postfix):
		self.postfix = postfix



class HTML_Empty_tag(Generic_HTML_Tag):
	'''
		An Empty HTML tag.

		This class will not add any prefix or postfix, but will contain the 
		necessary fulctions to act like a, HTML tag class

		Useful for initialization (See PD_Helpers.HTMLTreeConstructor)
	'''
	def __init__(self, indent_level=0):
		Generic_HTML_Tag.__init__(self)
		self.indent = indent_level
		self.generateHTMLPrefix()
		self.generateHTMLPostfix()
		


	def generateHTMLPrefix(self):
		self.prefix = ""


	def generateHTMLPostfix(self):
		self.postfix = ""



class HTML_tag(Generic_HTML_Tag):
	def __init__(self, indent_level=0):
		Generic_HTML_Tag.__init__(self)
		self.indent = indent_level
		self.generateHTMLPrefix()
		self.generateHTMLPostfix()
		

	def generateHTMLPrefix(self):
		self.prefix = self.sulley_helper.addStatic("<html>", self.indent)


	def generateHTMLPostfix(self):
		self.postfix = self.sulley_helper.addStatic("</html>", self.indent)



class HEAD_tag(Generic_HTML_Tag):
	def __init__(self, indent_level=0):
		Generic_HTML_Tag.__init__(self)
		self.indent = indent_level
		self.generateHTMLPrefix()
		self.generateHTMLPostfix()


	def generateHTMLPrefix(self):
		self.prefix = self.sulley_helper.addStatic("<head>", self.indent)


	def generateHTMLPostfix(self):
		self.postfix = self.sulley_helper.addStatic("</head>", self.indent)



class TITLE_tag(Generic_HTML_Tag):
	def __init__(self, indent_level=0):
		Generic_HTML_Tag.__init__(self)
		self.indent = indent_level
		self.generateHTMLPrefix()
		self.generateHTMLPostfix()


	def generateHTMLPrefix(self):
		self.prefix = self.sulley_helper.addStatic("<title>", self.indent)


	def generateHTMLPostfix(self):
		self.postfix = self.sulley_helper.addStatic("</title>", self.indent)



class BODY_tag(Generic_HTML_Tag):
	def __init__(self, indent_level=0, attributes=None):
		Generic_HTML_Tag.__init__(self)

		if attributes is not None:
			self.attributes = attributes

		self.indent = indent_level
		self.generateHTMLPrefix()
		self.generateHTMLPostfix()


	def generateHTMLPrefix(self):
		if self.attributes:
			self.prefix = self.sulley_helper.addStatic(
								"<body ", self.indent) + \
					self.formatAttributes() + \
					self.sulley_helper.addStatic(">", self.indent)
		else:
			self.prefix = self.sulley_helper.addStatic("<body>", self.indent)


	def generateHTMLPostfix(self):
		self.postfix = self.sulley_helper.addStatic("</body>", self.indent)



class P_tag(Generic_HTML_Tag):
	def __init__(self, indent_level=0):
		Generic_HTML_Tag.__init__(self)
		self.indent = indent_level
		self.generateHTMLPrefix()
		self.generateHTMLPostfix()


	def generateHTMLPrefix(self):
		self.prefix = self.sulley_helper.addStatic("<p>", self.indent)


	def generateHTMLPostfix(self):
		self.postfix = self.sulley_helper.addStatic("</p>", self.indent)



class A_tag(Generic_HTML_Tag):
	def __init__(self, indent_level=0, attributes=None):

		Generic_HTML_Tag.__init__(self)

		if(attributes is not None):
			self.attributes = attributes

		self.indent = indent_level
		self.generateHTMLPrefix()
		self.generateHTMLPostfix()


	def generateHTMLPrefix(self):
		if self.attributes:
			self.prefix = os.linesep + self.indent*self.TAB + \
					"# Begin <a> tag" + 2*os.linesep + \
					self.sulley_helper.addStatic("<a ", self.indent) + \
					self.formatAttributes() + \
					self.sulley_helper.addStatic(">", self.indent)
		else:
			self.prefix = os.linesep + self.indent*self.TAB + \
					"# Begin <a> tag" + 2*os.linesep + \
					self.sulley_helper.addStatic("<a>", self.indent)


	def generateHTMLPostfix(self):
		self.postfix = self.sulley_helper.addStatic("</a>", self.indent) + \
					self.indent*self.TAB + "# End <a> tag" + 2*os.linesep



class IMG_tag(Generic_HTML_Tag):
	def __init__(self, indent_level=0, attributes=None):

		Generic_HTML_Tag.__init__(self)

		if(attributes is not None):
			self.attributes = attributes

		self.indent = indent_level
		self.generateHTMLPrefix()
		self.generateHTMLPostfix()


	def generateHTMLPrefix(self):
		if self.attributes:
			self.prefix = os.linesep + self.indent*self.TAB + \
					"# Begin <img> tag" + 2*os.linesep + \
					self.sulley_helper.addStatic("<img ", self.indent) + \
					self.formatAttributes() + \
					self.sulley_helper.addStatic(">", self.indent)
		else:
			self.prefix = os.linesep + self.indent*self.TAB + \
					"# Begin <img> tag" + 2*os.linesep + \
					self.sulley_helper.addStatic("<img>", self.indent)

	def generateHTMLPostfix(self):
		self.postfix = self.sulley_helper.addStatic("</img>", self.indent) + \
					self.indent*self.TAB + "# End <img> tag" + 2*os.linesep



class DIV_tag(Generic_HTML_Tag):
	def __init__(self, indent_level=0, attributes=None):

		Generic_HTML_Tag.__init__(self)

		if(attributes is not None):
			self.attributes = attributes

		self.indent = indent_level
		self.generateHTMLPrefix()
		self.generateHTMLPostfix()

	def generateHTMLPrefix(self):
		if self.attributes:
			self.prefix = os.linesep + self.indent*self.TAB + \
					"# Begin <div> tag" + 2*os.linesep + \
					self.sulley_helper.addStatic("<div ", self.indent) + \
					self.formatAttributes() + \
					self.sulley_helper.addStatic(">", self.indent)
		else:
			self.prefix = os.linesep + self.indent*self.TAB + \
					"# Begin <div> tag" + 2*os.linesep + \
					self.sulley_helper.addStatic("<div>", self.indent)

	def generateHTMLPostfix(self):
		self.postfix = self.sulley_helper.addStatic("</div>", self.indent) + \
					self.indent*self.TAB + "# End <div> tag" + 2*os.linesep



class IFRAME_tag(Generic_HTML_Tag):
	def __init__(self, indent_level=0, attributes=None):

		Generic_HTML_Tag.__init__(self)

		if(attributes is not None):
			self.attributes = attributes

		self.indent = indent_level
		self.generateHTMLPrefix()
		self.generateHTMLPostfix()

	def generateHTMLPrefix(self):
		if self.attributes:
			self.prefix = os.linesep + self.indent*self.TAB + \
				"# Begin <iframe> tag" + 2*os.linesep + \
				self.sulley_helper.addStatic("<iframe ", self.indent) + \
				self.formatAttributes() + \
				self.sulley_helper.addStatic(">", self.indent)
		else:
			self.prefix = os.linesep + self.indent*self.TAB + \
				"# Begin <iframe> tag" + 2*os.linesep + \
				self.sulley_helper.addStatic("<iframe>", self.indent)

	def generateHTMLPostfix(self):
		self.postfix = self.sulley_helper.addStatic("</iframe>", self.indent) + \
				self.indent*self.TAB + "# End <iframe> tag" + 2*os.linesep



class OBJECT_tag(Generic_HTML_Tag):
	def __init__(self, indent_level=0, attributes=None):

		Generic_HTML_Tag.__init__(self)

		if(attributes is not None):
			self.attributes = attributes

		self.indent = indent_level
		self.generateHTMLPrefix()
		self.generateHTMLPostfix()

	def generateHTMLPrefix(self):
		if self.attributes:
			self.prefix = os.linesep + self.indent*self.TAB + \
				"# Begin <object> tag" + 2*os.linesep + \
				self.sulley_helper.addStatic("<object ", self.indent) + \
				self.formatAttributes() + \
				self.sulley_helper.addStatic(">", self.indent)
		else:
			self.prefix = os.linesep + self.indent*self.TAB + \
				"# Begin <object> tag" + 2*os.linesep + \
				self.sulley_helper.addStatic("<object>", self.indent)

	def generateHTMLPostfix(self):
		self.postfix = self.sulley_helper.addStatic("</object>", self.indent) + \
				self.indent*self.TAB + "# End <object> tag" + 2*os.linesep



class SCRIPT_tag(Generic_HTML_Tag):
	def __init__(self, indent_level=0, attributes=None):

		Generic_HTML_Tag.__init__(self)

		if(attributes is not None):
			self.attributes = attributes

		self.indent = indent_level
		self.generateHTMLPrefix()
		self.generateHTMLPostfix()

	def generateHTMLPrefix(self):
		if self.attributes:
			self.prefix = os.linesep + "# Begin <script> tag" + 2*os.linesep + \
				self.sulley_helper.addStatic("<script ", self.indent) + \
				self.formatAttributes() + \
				self.sulley_helper.addStatic(">", self.indent)
		else:
			self.prefix = os.linesep + "# Begin <script> tag" + 2*os.linesep + \
				self.sulley_helper.addStatic("<script>", self.indent)

	def generateHTMLPostfix(self):
		self.postfix = self.sulley_helper.addStatic("</script>", self.indent) + \
				"# End <script> tag" + 2*os.linesep



class APPLET_tag(Generic_HTML_Tag):
	def __init__(self, indent_level=0, attributes=None):

		Generic_HTML_Tag.__init__(self)

		if(attributes is not None):
			self.attributes = attributes

		self.indent = indent_level
		self.generateHTMLPrefix()
		self.generateHTMLPostfix()

	def generateHTMLPrefix(self):
		if self.attributes:
			self.prefix = os.linesep + self.indent*self.TAB + \
				"# Begin <applet> tag" + 2*os.linesep + \
				self.sulley_helper.addStatic("<applet ", self.indent) + \
				self.formatAttributes() + \
				self.sulley_helper.addStatic(">", self.indent)
		else:
			self.prefix = os.linesep + self.indent*self.TAB + \
				"# Begin <applet> tag" + 2*os.linesep + \
				self.sulley_helper.addStatic("<applet>", self.indent)

	def generateHTMLPostfix(self):
		self.postfix = self.sulley_helper.addStatic("</applet>", self.indent) + \
				self.indent*self.TAB + "# End <applet> tag" + 2*os.linesep




'''
if __name__ == "__main__":


	print 'Basic HTML Test...\n\n'
	h1 = HTML_tag()
	print h1.getPrefix()
	print h1.getPostfix()

	print "\nBasic <a> test...\n\n"
	a1 = A_tag(attributes={
		"href": ("ALL HTML", "checksum", "127.0.0.1/"), 
		"alt": ("alt text", "string", ""),
		})
	print a1.getPrefix()
	print a1.getPostfix()

	print "\nBasic <img> test...\n\n"
	img = IMG_tag(attributes={
		"src": ("ALL HTML", "checksum", "127.0.0.1/"), 
		"alt": ("alt text", "string", ""),
		})
	print img.getPrefix()
	print img.getPostfix()

	print "\nBasic <div> test...\n\n"
	div = DIV_tag(attributes={
		"id": ("test_div", "string", ""), 
		})
	print div.getPrefix()
	print div.getPostfix()

	print "\nBasic <iframe> test...\n\n"
	iframe = IFRAME_tag(attributes={
		"src": ("ALL HTML", "checksum", "127.0.0.1/"), 
		})
	print iframe.getPrefix()
	print iframe.getPostfix()

	print "\nBasic <object> test...\n\n"
	obj = OBJECT_tag(attributes={
		})
	print obj.getPrefix()
	print obj.getPostfix()

	print "\nBasic <script> test...\n\n"
	script = SCRIPT_tag(attributes={
		"language": ("JavaScript", "string", ""), 
		})
	print script.getPrefix()
	print script.getPostfix()

	print "\nBasic <applet> test...\n\n"
	applet = APPLET_tag(attributes={
		"code": ("ALL HTML", "checksum", "127.0.0.1/"), 
		})
	print applet.getPrefix()
	print applet.getPostfix()
'''
