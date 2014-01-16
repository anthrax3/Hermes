

import pickle
import sys, getopt

from analyzer_helpers import FB_PackageDefectDensity, FB_Bug
import math
import bugranks

import imp
from Config.analysis import DETAILS
#cvg = imp.load_source('DETAILS', '../Config/analysis.py')


#
#	GENERAL FLOW:
#
# Find the package with the highest defect density (start there)
# Look through the bugs found for that package
# are the bugs a high (enough?) priority category? 
#	If yes, continue, else, recalculate the defect density after removing those bugs and begin again
# find out what bugs are in the targetd package
# modify fuzz protocol definition file to target those bugs (genetic algorithm)
# fuzz the software
# keep track of what bugs are found and with what version of the protocol definition
# try to associate found bugs (via fuzzing) to those found via FindBugs
# Try to optimize the GA to look for 'bug coverage' 


class FBAnalyzer(object):

	parser_results_file = ""
	parser_defdens_file = ""
	parser_results_list = []
	parser_defdens_list = []

	SAVE_FILENAME = DETAILS.PATH_TO_ANALYZER + DETAILS.TARGET_FILENAME


	def __init__(self, tmpPR='parse_results.txt', tmpDD='parse_densities.txt'):
		self.parser_results_file = tmpPR
		self.parser_defdens_file = tmpDD


	def initialize(self):

		self.buglist = []
		self.defectdensitieslist = []

		self.parser_results_list = self.loadPickledFile(self.parser_results_file)
		self.parser_defdens_list = self.loadPickledFile(self.parser_defdens_file)

		self.organizeData()


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
			except:
				print 'An unexpected error occurred while loading data from the parser results file: %s' % (pfile)
		else:
			sys.exit()

		return thislist


	# Organize the data from the pickled files (defect density and parse results)
	# Load the data into lists of FB_Bug or FB_PackageDefectDensity classes
	def organizeData(self):

		for bugdata in self.parser_results_list:

			# ----------------------------------------------------------------------------------------------------DEBUG
			#print '\n[DEBUG]\tBUGDATA:'
			#print '\n[DEBUG]\t\t' + str(bugdata) + "\n"			

			# Bug information is always first index in element list (set that way in the parser when pickled)
			bug_info = bugdata.pop(0)

			tempBug = FB_Bug()

			# Get category
			category_list = [item for item in bug_info if item[0] == 'category']
			if len(category_list) > 0:
				tempBug.category = category_list.pop()[1]

			# Get priority
			priority_list = [item for item in bug_info if item[0] == 'priority']
			if len(priority_list) > 0:
				tempBug.priority = priority_list.pop()[1]

			# Get type
			type_list = [item for item in bug_info if item[0] == 'type']
			if len(type_list) > 0:
				tempBug.bugtype = str(type_list.pop()[1])

			# Get abbreviation
			abbrev_list = [item for item in bug_info if item[0] == 'abbrev']
			if len(abbrev_list) > 0:
				tempBug.abbrev = str(abbrev_list.pop()[1])


			# Check child data for info
			for child in bugdata:


				tag_find_list = [item for item in child if item[0] == 'tag']
				tag = ''
				if tag_find_list and len(tag_find_list) > 0:
					tag = tag_find_list.pop()[1]

				#print 'Child: ' + str(child) + '\n'


				# ----------------------------------------------------------------------
				# NEW CODE

				# Get the classname
				if tag == 'Class':
					cname_list = [item for item in child if item[0] == 'classname']
					if cname_list and len(cname_list) > 0:
						# cname_list is a list of tuples - get the second element in the tuple
						#Ex: [('classname', 'package.module.Class'), ...]
						tempBug.classname = str(cname_list.pop()[1])

				# Get the method name, classname, context, context name, and role
				elif tag == 'Method':
					# The method that doesn't have a role is the method in the actual class
					# The method that has a role is the method called (a system call)

					mthd_cname_list = [item for item in child if item[0] == 'classname']
					mname_list = [item for item in child if item[0] == 'name']

					role_list = [item for item in child if item[0] == 'role']
					if role_list and len(role_list) > 0:
						tempBug.methodrole = str(role_list.pop()[1])

						# If this is the role method, the classname will provide the method context
						if mthd_cname_list and len(mthd_cname_list) > 0:
							tempBug.methodcontext = str(mthd_cname_list.pop()[1])

						if mname_list and len(mname_list) > 0:
							tempBug.methodcontextname = str(mname_list.pop()[1])

					else:
						if mthd_cname_list and len(mthd_cname_list) > 0:
							tempBug.methodclassname = str(mthd_cname_list.pop()[1])

						if mname_list and len(mname_list) > 0:
							tempBug.methodname = str(mname_list.pop()[1])

				# Get the line numbers that the bug is found on (might be multiple: start - end)
				elif tag == 'SourceLine':
					start_list = [item for item in child if item[0] == 'start']
					end_list = [item for item in child if item[0] == 'end']
					src_list = [item for item in child if item[0] == 'sourcefile']


					if start_list and len(start_list) > 0:
						tempBug.start_line = int(start_list.pop()[1])

					if end_list and len(end_list) > 0:
						tempBug.end_line = int(end_list.pop()[1])
					if src_list and len(src_list) > 0:
						tempBug.src_file = str(src_list.pop()[1])


				# END OF NEW CODE
				# ----------------------------------------------------------------------
				'''
				classname_list = [item for item in child if item[0] == 'classname']
				methodrole_list = [item for item in child if item[0] == 'role']

				# If it is the classname tag (will ONLY have the classname in it)
				if len(child) == 1:
					if len(classname_list) > 0:
						# Take the first classname - as they will all be the same
						tempBug.classname = str(classname_list.pop()[1])

				elif len(methodrole_list) > 0:
					tempBug.methodrole = str(methodrole_list.pop()[1])

					if len(classname_list) > 0:
						tempBug.methodclassname = str(classname_list.pop()[1])
				'''

			self.buglist.append(tempBug)

			#print '-------------------------------------------------------------'



		labels = self.parser_defdens_list.pop(0)

		for defdata in self.parser_defdens_list:

			# DEBUG
			#print '=============================================================='
			#print defdata

			kind, name, density, bugs, ncss = defdata

			tempDD = FB_PackageDefectDensity()
			tempDD.kind = kind
			tempDD.name = name
			tempDD.density = density
			tempDD.bugs = bugs
			tempDD.NCSS = ncss

			self.defectdensitieslist.append(tempDD)



	# Calculate Bug Ranks
	# Look at defect densities:
	#   Calculate the severity density of the bugs for each classname (defect density class)
	#   What package has the highest potential defect density (including severity)?
	def analyze(self):


		# Calculate Bug Ranks for each bug discovered (store in the bug's class)
		# Do this using the bugranks specified by the findbugs documentation - stored values in bugranks.py
		for bug in self.buglist:
			tmp_rank = 0

			if bug.category in bugranks.BUGCATEGORY_dict:
				tmp_rank += bugranks.BUGCATEGORY_dict[bug.category]

			if bug.abbrev in bugranks.BUGKIND_dict:
				tmp_rank += bugranks.BUGKIND_dict[bug.abbrev]

			if bug.bugtype in bugranks.BUGRANK_dict:
				tmp_rank += bugranks.BUGRANK_dict[bug.bugtype]

			bug.rank = tmp_rank



		num_bugs_total = len(self.buglist)
		num_bugs_keep = int(math.ceil(DETAILS.PERCENT_CODE_TO_KEEP * num_bugs_total))

		print 'Total Bugs: ' + str(num_bugs_total) + ', keeping: ' + str(num_bugs_keep) + \
				' (Top ' + str(DETAILS.PERCENT_CODE_TO_KEEP * 100) + '% of offending code)'

		self.buglist.sort(key = lambda x: x.rank)

		target_list = self.buglist[:num_bugs_keep]




		'''

		# Calculate the average severity of the bugs in each class
		for dd in self.defectdensitieslist:

			ranktotal = 0
			most_severe_bugrank = 40

			# Get a list of all of the bugs with the same classname as the current defect density package name
			bugs_of_cname_list = [item for item in self.buglist if dd.name in item.classname]
			dd.buglist = bugs_of_cname_list

			# calculate the severity of the bugs in the class (avg bug rank and most severe bug rank)
			for bug in bugs_of_cname_list:
				ranktotal = ranktotal + bug.rank
				if most_severe_bugrank > bug.rank:
					most_severe_bugrank = bug.rank

			if len(bugs_of_cname_list) > 0:
				dd.avgbugrank = ranktotal / len(bugs_of_cname_list)
			else:
				dd.avgbugrank = 0
			dd.mostseverebugrank = most_severe_bugrank


		# find the package with the worst average severity. If there is a tie, take the one with the most severe bug.
		target_list = []
		max_targets = 4
		iterations = 0

		while len(target_list) < max_targets and iterations <= len(self.defectdensitieslist):

			target = None
			target_avgbugrank = 999

			for dd in self.defectdensitieslist:
				# Do not include classes with no name (edge?), project details, or previously added targets
				if dd in target_list or dd.name == "" or dd.kind == "project":
					continue
				if dd.avgbugrank < target_avgbugrank:
					target = dd
					target_avgbugrank = dd.avgbugrank
				if dd.avgbugrank == target_avgbugrank:
					if dd.mostseverebugrank < target.mostseverebugrank:
						target = dd

			if target:
				target_list.append(target)

			# Just in case there are not enough results to hit the max target
			iterations = iterations + 1

		'''


		# At this point, we have a target package that contains the most severe bugs from static analysis and a list of those bugs
		# along with the defect density metrics to prove it and all of the data that describes the bug types and context

		# DEBUG
		#--------------------------------------------------------------------------------------------------
		print '='*40
		for target in target_list:
			print 'Target Object: ' + str(target)
			target.printNicely()
			print "-"*40
		print '\n'
		#--------------------------------------------------------------------------------------------------


		#--------------------------------------------------------------------------------------------------		
		#TODO
		# Save the information to a file somehow (pickle?)
		#--------------------------------------------------------------------------------------------------

		#print 'saving ' + str(len(target_list)) + ' bugs. : ' + str(target_list) + '\n\nTo: ' + self.SAVE_FILENAME
		self.saveThis(target_list, self.SAVE_FILENAME)







	def saveThis(self, data, filename):
		try:
			f = self.savefile = open(filename, 'wb')
			pickle.dump(data, f)
			f.close()
		except IOError as e:
			print 'I/O error ({0}): {1}'.format(e.errno, e.strerror)
		except:
			print "Unexpected error opening file to save results."



def usage():
	print "\n"
	print "======================================================"
	print "                    analyzer.py USAGE"
	print ""
	print "-r [--parseresultsfile]"
	print "\tREQUIRED"
	print "\tPath to the parser results file generated by the parser program"
	print "\n"
	print "-d [--parserdefectdensity]"
	print "\tREQUIRED"
	print "\tPath the the defect density file generated by the parser program"
	print "\n"
	return



if __name__ == "__main__":

	tmpDD = ""
	tmpPR = ""

	arguments = sys.argv[1:]
	try:
		#dd=defect density file, b=bug file    BOTH REQUIRED
		opts, args = getopt.getopt(arguments, "r:d:", ["parseresultsfile", "parserdefectdensity"])
	except getopt.GetoptError:
		usage()
		sys.exit(2)
	
	for opt, arg in opts:
		if opt in ("-r", "--parseresultsfile"):
			tmpPR = arg
		elif opt in ("-d", "--parserdefectdensity"):
			tmpDD = arg


	if tmpPR and tmpDD:
		a = FBAnalyzer(tmpPR, tmpDD)
		a.initialize()
		a.analyze()
	else:
		usage()
		sys.exit(2)
