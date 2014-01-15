


'''

	Author: Caleb Shortt

	Description:
		'Smart' Protocol Definition Creator (For the Sulley Fuzzing Framework)
		This module contains helper classes for creating protocol definitions

'''

import sys
import random
import pickle
import os
import imp
import traceback

from Definition_Tree import DefinitionTree, DefTreeNode
from Sulley_Definition_Helpers import Sulley_Code_Helper
import HTML_Tags



class HTMLTreeConstructor(object):
	'''

		This class contains the methods, and internal structure, of the HTML
		tree. 

	'''

	def __init__(self, defn_name=str(random.random())):
		self.TAB_SPACE = "    "
		self.NEW_LINE = os.linesep

		self.has_links = True
		self.has_imgs = True
		self.has_divs = True
		self.has_iframes = True
		self.has_objects = True
		self.has_js = True
		self.has_applets = True

		self.sulley_helper = Sulley_Code_Helper()

		self.tree = None
		self.init_tree(defn_name)



	def init_tree(self, defn_name):
		root = DefTreeNode(
			"init_code", 
			HTML_Tags.HTML_Empty_tag(), 
			self.sulley_helper.generateInitCode(
				defn_name, 
				"HTMLTreeConstructor",
				"Auto Generated Protocol Definition", 
				"PDHelpers.py"
				))

		self.tree = DefinitionTree(root)

		self.tree.addChildToNode(
			DefTreeNode(
				"html", 
				HTML_Tags.HTML_tag()
				), 
			"init_code"
			)

		self.tree.addChildToNode(
			DefTreeNode(
				"head", 
				HTML_Tags.HEAD_tag()
				), 
			"html"
			)

		self.tree.addChildToNode(
			DefTreeNode(
				"title", 
				HTML_Tags.TITLE_tag()
				), 
			"head"
			)

		self.add_text_node("title_text", "title", "Sulley Says Hello!")

		self.tree.addChildToNode(
			DefTreeNode(
				"body", 
				HTML_Tags.BODY_tag()
				), 
			"html"
			)



	def getIndent(self, indent_level=0):
		'''
			Gets the proper indentation in tab spaces to write valid Python
		'''
		return indent_level * self.TAB_SPACE



	def getTraversal(self):
		if self.tree:
			return self.tree.traverse()
		else:
			return ""



	def get_parent_indent(self, parent):
		p_node = self.tree.findNode(str(parent))

		if p_node:
			node_tag = p_node.getPayload()

			if node_tag and p_node.getType() == "block":
				return node_tag.getIndent() + 1
			elif node_tag and p_node.getType() == "default":
				return node_tag.getIndent()
		return 0



	def set_chromosome(self, chromosome=[1, 1, 1, 1, 1, 1, 1]):
		self.has_links = (chromosome[0] == 1)
		self.has_imgs = (chromosome[1] == 1)
		self.has_divs = (chromosome[2] == 1)
		self.has_iframes = (chromosome[3] == 1)
		self.has_objects = (chromosome[4] == 1)
		self.has_js	 = (chromosome[5] == 1)
		self.has_applets = (chromosome[6] == 1)


	'''
	==========================================================================
						Sulley and HTML-Specific Functions
	==========================================================================	
	'''


	def add_text_node(self, label, parent, text=""):
		indent = self.get_parent_indent(str(parent))
		self.tree.addChildToNode(
			DefTreeNode(
				str(label), 
				HTML_Tags.HTML_Empty_tag(indent_level=indent), 
				self.sulley_helper.addString(text, indent)
				),
			str(parent)
			)


	def add_checksum_anchor_node(self, label, parent, target):
		if self.has_links:
			indent = self.get_parent_indent(str(parent))
			self.tree.addChildToNode(
				DefTreeNode(
					str(label), 
					HTML_Tags.A_tag(attributes={
						"href": (str(target), "checksum", ""),
						"alt": (str(target), "string", "")
						},
						indent_level=indent)
					), 
				str(parent)
				)

			return True
		return False


	def add_anchor_node(self, label, parent, prefix="127.0.0.1/"):
		if self.has_links:
			indent = self.get_parent_indent(str(parent))
			self.tree.addChildToNode(
				DefTreeNode(
					str(label), 
					HTML_Tags.A_tag(attributes={
						"href": (str(label), "string", prefix), 
						"alt": (str(label), "string", "")
						},
						indent_level=indent)
					), 
				str(parent)
				)

			return True
		return False


	def add_block_node(self, label, parent):
		indent = self.get_parent_indent(str(parent))
		ind_space = indent*self.TAB_SPACE

		b_tag = HTML_Tags.HTML_Empty_tag(indent_level=indent)

		b_tag.setPrefix(
			os.linesep + \
			ind_space + "# Beginning of block: " + str(label) + os.linesep + \
			ind_space + "if s_block_start(\"" + \
				str(label) + "\"):" + os.linesep
			)

		b_tag.setPostfix(
			ind_space + "s_block_end(\"" + str(label) + "\")" + 2*os.linesep
		)


		self.tree.addChildToNode(
			DefTreeNode(str(label), b_tag, node_type="block"),
			str(parent),
			)

		# This text node assures that the block will have something in it
		self.add_text_node(
			str(label) + "_assurance", 
			str(label), 
			str(label) + "+assurance")


	def add_div_node(self, label, parent):
		if self.has_divs:
			# create a block to be checksummed
			block_label = str(random.random())
			self.add_block_node(block_label, parent)

			indent = self.get_parent_indent(block_label)
			self.tree.addChildToNode(
				DefTreeNode(
					str(label), 
					HTML_Tags.DIV_tag(attributes={
						"id": (str(label), "string", "")
						},
						indent_level=indent)
					),
				block_label
				)

			# Create checksum link for given block
			self.add_checksum_anchor_node(
				str(random.random()), 
				str(parent), 
				block_label
				)

			return True
		return False


	def add_img_node(self, label, parent, prefix="127.0.0.1/"):
		if self.has_imgs:
			indent = self.get_parent_indent(str(parent))
			self.tree.addChildToNode(
				DefTreeNode(
					str(label), 
					HTML_Tags.IMG_tag(attributes={
						"src": ("somepath", "string", prefix)
						}, 
						indent_level=indent)
					),
				str(parent)
				)

			return True
		return False


	def add_iframe_node(self, label, parent, prefix="127.0.0.1/"):
		if self.has_iframes:
			indent = self.get_parent_indent(str(parent))
			self.tree.addChildToNode(
				DefTreeNode(
					str(label), 
					HTML_Tags.IFRAME_tag(attributes={
						"src": ("testpath", "string", prefix)
						}, 
						indent_level=indent)
					), 
				str(parent)
				)

			return True
		return False


	def add_object_node(self, label, parent):
		if self.has_objects:
			indent = self.get_parent_indent(str(parent))
			self.tree.addChildToNode(
				DefTreeNode(
					str(label), 
					HTML_Tags.OBJECT_tag(
						attributes={

						}, 
						indent_level=indent)
					),
				str(parent)
				)

			return True
		return False


	def add_script_node(self, label, parent):
		if self.has_js:
			indent = self.get_parent_indent(str(parent))
			self.tree.addChildToNode(
				DefTreeNode(
					str(label), 
					HTML_Tags.SCRIPT_tag(attributes={
						"language": ("JavaScript", "string", "")
						},
						indent_level=indent),
					self.sulley_helper.addJavascript()
					),
				str(parent)
				)

			return True
		return False


	def add_applet_node(self, label, parent, prefix="127.0.0.1/"):
		if self.has_applets:
			indent = self.get_parent_indent(str(parent))
			self.tree.addChildToNode(
				DefTreeNode(
					str(label),
					HTML_Tags.APPLET_tag(attributes={
						"code": ("sulleylikesapples", "string", prefix),
						}, 
						indent_level=indent)
					),
				str(parent)
				)

			return True
		return False





class HelperFunctions(object):
	'''
		This class contains any helper functions that are not completely
		associated with the HTMLTreeConstructor
	'''

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




'''
if __name__ == "__main__":
	t = HTMLTreeConstructor("Protocol Definition")
	print t.getTraversal()
'''

