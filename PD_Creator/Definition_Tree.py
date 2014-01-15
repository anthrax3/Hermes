
'''
	
	Creator:	Caleb Shortt
	Date:		January 2014
	
	Description:
		This file contains the classes (and helpers) associated with the 
		protocol definition tree. This is an extensible method of defining 
		generic protocol definitions.

		The tree is left-justified and each node may hold n children
'''


import HTML_Tags


class DefinitionTree(object):

	def __init__(self, node):
		self.root = node


	def getRoot(self):
		return self.root


	def findNode(self, label):
		return self.recursive_findNode(label, self.root)


	def traverse(self):
		if self.root:
			return self.recursive_traverse(self.root)
		else:
			return ""


	def recursive_traverse(self, node, construction=""):
		'''
			Traverse the tree.
			This algorithm will run a pre-order traversal. When the algorithm 
			encounters a new node it immediately calls its 'prefix' function, 
			it then appends the node's payload, and traverses the node's 
			children. After visiting the node's children, its 'postfix' 
			function is called and the traversal for this node it complete.

			Returns a complete construction of the nodes' prefix, content, 
			and postfix in a pre-order traversal.
		'''
		
		if(node):
			construction = construction + node.getPrefix() + node.getContents()

			for child in node.getChildren():
				construction = self.recursive_traverse(child, construction)
				
			return construction + node.getPostfix()


	def recursive_findNode(self, label, node):
		'''
			Executes a search of the tree to find the node 
			with the specified label. This algorithm finds the first 
			label that matches the search and is case insensitive.

			Returns the node with the specified label or None.
		'''

		if(node is None or node.getLabel().lower() == label.lower()):
			return node

		for child in node.getChildren():
			node = self.recursive_findNode(label, child)
			if node is not None:
				return node


	def addChildToNode(self, node, target_label):
		'''
			Searches for the first node with the given label.
			If a node is found, add the given node as a child of the 
			found node.

			Returns True or False pending success
		'''

		if node:
			target_node = self.findNode(target_label)

			if target_node:
				target_node.addChild(node)
				return True

		return False



class DefTreeNode(object):
	'''
		A Protocol Definition Tree Node. 
		It will contain a single payload (ex: an <html> tag in HTML),
		a list of child nodes, a label, and what to do prefix and 
		postfix during traversal.

		The payload is of type 'Generic_HTML_Tag' (HTML_Tags.py)
		The label is a unique string that identifies the node.

		Both the label and the payload are required to initialize a node.
	'''


	def __init__(self, label, payload, contents="", node_type="default"):
		self.children = []
		self.payload = payload
		self.label = label
		self.contents = contents
		self.node_type = node_type


	def addChild(self, child):
		if child:
			self.children.append(child)
			return True
		return False

	def setPayload(self, payload):
		if payload:
			self.payload = payload
			return True
		return False

	def setLabel(self, label):
		self.label = label

	def setContents(self, contents):
		self.contents = contents


	def getChildren(self):
		return self.children

	def getPayload(self):
		return self.payload

	def getLabel(self):
		return self.label

	def getPrefix(self):
		if self.payload:
			return self.payload.getPrefix()
		else:
			return None

	def getPostfix(self):
		if self.payload:
			return self.payload.getPostfix()
		else:
			return None

	def getContents(self):
		return self.contents

	def getType(self):
		return self.node_type



