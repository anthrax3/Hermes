

#	
#	Analyzer Helper Classes
#	Just a few classes that help with the analysis executed in analyzer.py
#	
#	Author: Caleb Shortt (2013, July)
#





#	
#	'FindBugs Bug'
#	Stores all of the information of a single FindBugs bug, includes getters and setters for each property
#	
class FB_Bug(object):


	def __init__(self):

		# Contains the raw, unformatted bug info that is extracted from the parser file
		self._raw_bug_info = []

		# Bug Information
		self._category = ''
		self._priority = 0
		self._bugtype = ''
		self._classname = ''
		self._isstatic = ''
		self._abbrev = ''

		self.clabel = ''

		self._src_file = ''
		self._start_line = 0
		self._end_line = 0

		# Method Information
		self._methodrole = ''
		self._methodcontext = ''
		self._methodcontextname = ''
		self._methodclassname = ''
		self._methodname = ''

		# Calculated Bug Rank
		self._rank = 0


	def printNicely(self):
		print "FindBug Bug (" + str(self._category) + ")"
		print "\tType:\t\t" + str(self._bugtype) + " (Priority " + str(self._priority) + ")" 
		print "\tClass:\t\t" + str(self._classname)
		print "\tSrc File:\t" + str(self._src_file)
		print "\tBug Rank:\t" + str(self._rank)
		print '\tStart Line:\t' + str(self._start_line)
		print '\tEnd Line:\t' + str(self._end_line)
		print '\tMethod Name:\t' + str(self._methodname)
		print '\tMethod Class:\t' + str(self._methodclassname)
		print '\tMethod Role:\t' + str(self._methodrole)
		print '\tMethod Context:\t' + str(self._methodcontext)
		print '\tMethod Ctx Name:\t' + str(self._methodcontextname)


	def getClass(self):
		if self.clabel and len(self.clabel) > 0:
			return self.clabel
		else:
			if self._classname and len(self._classname) > 0:
				self.clabel = self._classname.split('.')[-1]
				return self.clabel
			return ''

		
	# ------------------------------------------------------


	@property
	def raw_bug_info(self):
		return self._raw_bug_info

	@raw_bug_info.setter
	def raw_bug_info(self, value):
		self._raw_bug_info = value


	@property
	def category(self):
		return self._category

	@category.setter
	def category(self, value):
		self._category = value


	@property
	def priority(self):
		return self._priority

	@priority.setter
	def priority(self, value):
		self._priority = value


	@property
	def bugtype(self):
		return self._bugtype

	@bugtype.setter
	def bugtype(self, value):
		self._bugtype = value


	@property
	def classname(self):
		return self._classname

	@classname.setter
	def classname(self, value):
		self._classname = value


	@property
	def isstatic(self):
		return self._isstatic

	@isstatic.setter
	def isstatic(self, value):
		self._isstatic = value


	@property
	def abbrev(self):
		return self._abbrev

	@abbrev.setter
	def abbrev(self, value):
		self._abbrev = value


	@property
	def rank(self):
		return self._rank

	@rank.setter
	def rank(self, value):
		self._rank = value
		

	@property
	def start_line(self):
		return self._start_line

	@start_line.setter
	def start_line(self, value):
		self._start_line = value


	@property
	def end_line(self):
		return self._end_line

	@end_line.setter
	def end_line(self, value):
		self._end_line = value


	@property
	def src_file(self):
		return self._src_file

	@src_file.setter
	def src_file(self, value):
		self._src_file = value


	# ------------------------------------------------------

	@property
	def methodrole(self):
		return self._methodrole

	@methodrole.setter
	def methodrole(self, value):
		self._methodrole = value


	@property
	def methodclassname(self):
		return self._methodclassname

	@methodclassname.setter
	def methodclassname(self, value):
		self._methodclassname = value


	@property
	def methodname(self):
		return self._methodname

	@methodname.setter
	def methodname(self, value):
		self._methodname = value


	@property
	def methodcontext(self):
		return self._methodcontext

	@methodcontext.setter
	def methodcontext(self, value):
		self._methodcontext = value


	@property
	def methodcontextname(self):
		return self._methodcontextname

	@methodcontextname.setter
	def methodcontextname(self, value):
		self._methodcontextname = value

	# ------------------------------------------------------



#	
#	Stores the defect density information for a single package
#	
#	
class FB_PackageDefectDensity(object):

	def __init__(self):
		self._name = ''
		self._kind = ''

		# defect density is measured in density / KNCSS
		self._density = 0.0

		self._bugs = ''
		self._NCSS = 0

		self._avgbugrank = 0
		self._mostseverebugrank = 40

		self._buglist = []

	def printNicely(self):
		print "Findbug Package Defect Density (Object)"
		print "Name: \t\t\t" + self._name
		print "Kind: \t\t\t" + self._kind
		print "Density: \t\t" + self._density
		print "Bugs: \t\t\t" + self._bugs
		print "NCSS: \t\t\t" + self._NCSS
		print "AVG Bug Rank: \t\t" + str(self._avgbugrank)
		print "Most Severe Bug Rank: \t" + str(self._mostseverebugrank)
		print "Bug List: \t\t" 

		for bug in self._buglist:
			bug.printNicely()
			print ""


	@property
	def name(self):
		return self._name

	@name.setter
	def name(self, value):
		self._name = value


	@property
	def kind(self):
		return self._kind

	@kind.setter
	def kind(self, value):
		self._kind = value


	@property
	def density(self):
		return self._density

	@density.setter
	def density(self, value):
		self._density = value


	@property
	def bugs(self):
		return self._bugs

	@bugs.setter
	def bugs(self, value):
		self._bugs = value


	@property
	def NCSS(self):
		return self._NCSS

	@NCSS.setter
	def NCSS(self, value):
		self._NCSS = value


	@property
	def avgbugrank(self):
		return self._avgbugrank

	@avgbugrank.setter
	def avgbugrank(self, value):
		self._avgbugrank = value


	@property
	def mostseverebugrank(self):
		return self._mostseverebugrank

	@mostseverebugrank.setter
	def mostseverebugrank(self, value):
		self._mostseverebugrank = value


	@property
	def buglist(self):
		return self._buglist

	@buglist.setter
	def buglist(self, value):
		self._buglist = value
