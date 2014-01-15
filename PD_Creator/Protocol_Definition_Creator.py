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
from PD_Helpers import HTMLTreeConstructor


class PDef_Creator(object):

	def __init__(self):
		self.html_tree = HTMLTreeConstructor("Protocol Definition")


	def reset(self):
		self.html_tree = HTMLTreeConstructor("Protocol Definition")


	def save_protocol(self, protocol, filename="PD_Creator/protocol.py"):
		try:
			with open(filename, "w") as f:
				f.write(protocol)
		except IOError as ioe:
			print 'There was an I/O Error when saving the protocol to ' + \
					str(filename)
		except:
			print 'An Unexpected exception has occurred while saving the ' + \
					'protocol definition to ' + str(filename)


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

		# Support any level of nesting
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



