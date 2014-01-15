
# 
# Genetic Algorithm Coverage Report Interpreter
# 
# Description:
#
# This program takes the latest coverage report from the 'Reports' directory and uses the coverage metrics 
# contained within to determine the format of the next sulley protocol definition.
# 
# The protocol definition creator is initialized and used to construct the templates
# 
# 
# Author:
#  			Caleb Shortt, 2013



import random
import os
import imp
import time
import traceback

from datetime import datetime, timedelta
from deap import creator, base, tools

from PD_Creator.Protocol_Definition_Creator import PDef_Creator
from PD_Creator.PD_Helpers import HelperFunctions
from Config.analysis import DETAILS
from CvgHelpers import EMMAXMLParser
from Config.fuzzserver import DETAILS as FUZZCONFIG


class CVG_Max():

	def __init__(self, fuzz_server, CX=0.5, MPB=0.1, NG=30, PS=10, simple=False):

		# probability of crossing two individuals (mate), mutation probability, number of generations
		self.CXPB = CX
		self.MUTPB = MPB
		self.NGEN = NG
		self.POP_SIZE = PS
		self.SIMPLE = simple

		# The fuzz server and all its functions (/Fuzz_Server/fuzzer_lib.py)
		self.Fuzz_Server = fuzz_server

		# Server timeout in seconds
		self.TIMEOUT = 60

		# Initialize a protocol definition creator
		self.pd_creator = PDef_Creator()

		# Initialize the helper functions and get the list of targets from the analyzer
		# The analyzer has been changed (December 6, 2013) to save a list of FB_Bug objects instead
		#		of the xml
		self.helper_functions = HelperFunctions()
		self.target_list = self.helper_functions.loadPickledFile(DETAILS.PATH_TO_ANALYZER + DETAILS.TARGET_FILENAME)

		# Initialize an EMMA XML Parser and give it the targets we want
		#self.emma_xml_parser = EMMAXMLParser([target.name for target in self.target_list])
		self.emma_xml_parser = EMMAXMLParser(self.target_list)

		# Granularity of analysis: 0=Package Level, 1=Source File Level, 2=Class Level, 3=Method Level
		self.PACKAGE_LEVEL	= "package"
		self.SRCFILE_LEVEL	= "srcfile"
		self.CLASS_LEVEL	= "class"
		self.METHOD_LEVEL	= "method"

		self.CVG_GRANULARITY_LIST = [self.PACKAGE_LEVEL, self.SRCFILE_LEVEL, self.CLASS_LEVEL, self.METHOD_LEVEL]

		# Change this variable to change the chosen granularity (index of above list)
		self.GRANULARITY = 3


		# Coverage Focus
		self.FOCUS_CLASS_CVG = "class"
		self.FOCUS_METHOD_CVG = "method"
		self.FOCUS_BLOCK_CVG = "block"
		self.FOCUS_LINE_CVG = "line"

		self.CVG_FOCUSES = [self.FOCUS_CLASS_CVG, self.FOCUS_METHOD_CVG, self.FOCUS_BLOCK_CVG, self.FOCUS_LINE_CVG]

		# Change this variable to change the coverage focus (index of above list)
		self.CVG_FOCUS = 3

		# --------------------------------------------------------------------
		#		Start of Genetic Algorithm Code (Still in Constructor)
		# --------------------------------------------------------------------

		'''
			Create a maximizing fitness parameter for mean coverage of target 
			code, minimizing parameter for the target cvg standard deviation, 
			and a minimizing parameter for non-target code coverage (target 
			complement)

			Goal:
				Max target cvg while minimizing std deviation, and other cvg
		'''
		creator.create("CvgMaxMin", base.Fitness, weights=(1.0, -1.0, -1.0))

		# Each individual will be a list of flags that say which attribute is added, and which is not of target code 
		creator.create("Individual", list, fitness=creator.CvgMaxMin)

		# Right now there are 7 features for each individual (In this order):
		# [Links Enabled, imgs enabled, divs enabled, iframes enabled, objects enabled, js enabled, applets enabled]
		INDIVIDUAL_SIZE = 7

		# Create a population of individuals with random init values
		self.toolbox = base.Toolbox()
		self.toolbox.register("attr_bool", random.randint, 0, 1)
		self.toolbox.register("individual", tools.initRepeat, creator.Individual, self.toolbox.attr_bool, n=INDIVIDUAL_SIZE)
		self.toolbox.register("population", tools.initRepeat, list, self.toolbox.individual)

		self.toolbox.register("mate", tools.cxTwoPoints)
		self.toolbox.register("mutate", tools.mutFlipBit, indpb=0.05)
		self.toolbox.register("select", tools.selTournament, tournsize=3)
		self.toolbox.register("evaluate", self.evaluate)




	# ------------------------------------------------------------------------
	# This function evaluates the given individual (list of flags) based on its performance in the fuzz server
	def evaluate(self, individual):
		# note the date and time
		# Get protocol definition from PD_Creator given the individual
		# Initialize and run the fuzz server - server will run for x amount of mutations (or some time limit)
		# wait for a file to be created in the Coverage/Reports directory that was created after the noted date and time
		# load that coverage (EMMA) file
		# 		Note that there are different types of coverage: class, method, block, and line coverage
		#		Might be able to target a different coverage given the type of bug we're looking for
		# extract the desired coverage type
		# return the number (%) coverage as an int

		print 'Individual: ' + str(individual)

		# Get the current time, this will be used to find the latest coverage report
		started_at = datetime.now()

		# try to get the protocol definition for the given individual
		try:
			self.pd_creator.reset()
			pdef = self.pd_creator.generate_html(individual)

		except Exception as ex:
			print 'An unexpected exception occurred while generating the protocol definition.\n%s\n' % (str(ex))

		# try to save the generated protocol definition
		if pdef:
			self.pd_creator.save_protocol(pdef)
		else:
			raise Exception("No Protocol Definition Created")

		# Attempt to load the auto-generated protocol definition into sulley and run the fuzz server
		try:
			self.Fuzz_Server.reset()
			self.Fuzz_Server.reloadSulleyRequest()
			self.Fuzz_Server.run()
			(num_responses, fsvr_start, fsvr_end) = self.Fuzz_Server.getStats()
		except Exception as e:
			print 'An unexpected error has occurred while evaluating the fuzz server.\n%s\n' % (str(e))
			traceback.print_exc()


		# Get the latest coverage report from EMMA
		report_file = self.get_latest_cvg_report()
		if report_file:
			report_created = datetime.fromtimestamp(os.stat(report_file).st_mtime)
		else:
			report_created = datetime(2010, 1, 1, 1, 1)

		# If the report was NOT created after the 'started_at' timestamp, wait for the new results to show up
		# This might take a while since it is transferred to the coverage listener which saves it to file
		if started_at > report_created:
			print 'Waiting for coverage report to finish writing'

		timeout_time = datetime.now() + timedelta(minutes=self.TIMEOUT)
		while (started_at > report_created) and (datetime.now() < timeout_time):
			time.sleep(1)
			print '.',
			report_file = self.get_latest_cvg_report()
			if report_file:
				report_created = datetime.fromtimestamp(os.stat(report_file).st_mtime)

		# Now we have the proper coverage report for the evaluation we just did
		# Now extract the selected coverage metrics and return them

		print '\nAnalyzing Coverage Report.'

		report_xml = ""
		with open(report_file, "r") as f:
			report_xml = f.read()


		# Extract the target information, parse the results, and format them in a TargetData tree structure
		# NOTE: tgt_data and tgt_comp are lists of TargetData objects
		self.emma_xml_parser.extractEMMAData(report_xml)
		tgt_data = self.emma_xml_parser.getTargetResults()
		tgt_comp = self.emma_xml_parser.getTargetComplement()

		'''
		nov = len(target_data)
		cc = []
		mc = []
		bc = []
		lc = []
		for data in target_data:
			# Merge Lists
			cc.append(data.class_coverage)
			mc.append(data.method_coverage)
			bc.append(data.block_coverage)
			lc.append(data.line_coverage)

		return_value = 0.0
		if self.CVG_FOCUSES[self.CVG_FOCUS] == self.FOCUS_CLASS_CVG:
			return_value = sum(cc)/nov
		if self.CVG_FOCUSES[self.CVG_FOCUS] == self.FOCUS_METHOD_CVG:
			return_value = sum(mc)/nov
		if self.CVG_FOCUSES[self.CVG_FOCUS] == self.FOCUS_BLOCK_CVG:
			return_value = sum(bc)/nov
		if self.CVG_FOCUSES[self.CVG_FOCUS] == self.FOCUS_LINE_CVG:
			return_value = sum(lc)/nov

		'''

		(tgt_rv, tgt_std, tgt_cvg_values) = self.crunch_cvg_data(tgt_data)
		(comp_rv, comp_std, comp_cvg_values) = self.crunch_cvg_data(tgt_comp)

		# DEBUG ------------------------------------------------------------------------------------------------------
		print "Coverage Value (" + str(self.CVG_FOCUSES[self.CVG_FOCUS]) + " coverage, " + self.CVG_GRANULARITY_LIST[self.GRANULARITY] +  " granularity): " + str(return_value)


		'''
		logfile = "%scvg_log%s.txt" % (FUZZCONFIG.SERVER_LOG_PATH, time.time())
		with open(logfile, 'w') as f:
			txt = "Individual: " + str(individual) + '\n\n'

			# (num_responses, fsvr_start, fsvr_end)

			txt = txt + "Number of responses from Fuzz Server: " + str(num_responses) + '\n'
			txt = txt + "Start Time of Fuzz Server:\t\t" + str(fsvr_start) + '\n'
			txt = txt + "End Time of Fuzz Server:\t\t" + str(fsvr_end) + '\n\n'
			txt = txt + "Average Coverage Value (" + str(self.CVG_FOCUSES[self.CVG_FOCUS]) + " coverage, " + self.CVG_GRANULARITY_LIST[self.GRANULARITY] +  " granularity): " + str(return_value)
			txt = txt + '\nEquation used: sum(cvg)/nov = returned number\n'
			txt = txt + '\nTargets:'

			for target in tgt_data:
				txt = txt + '\n\t' + str(target.name) + '\n\tBug Type:\t' + str(target.type)
				txt = txt + '\n\t' + '-'*30

			txt = txt + '\n\nOther Values:\n\n'
			txt = txt + 'Number of Values (nov): ' + str(nov) + '\n'
			txt = txt + 'Class CVG (cc):\t\t' + str(cc) + '\n'
			txt = txt + 'Methd CVG (mc):\t\t' + str(mc) + '\n'
			txt = txt + '\tBlock CVG (bc):\t' + str(bc) + '\n'
			txt = txt + '\tLine CVG (lc):\t' + str(lc) + '\n'
			
			f.write(txt)
			print 'Coverage log saved to %s' % (logfile)
		'''

		self.save_cvg_log(
			tgt_data, 
			(tgt_rv, tgt_std), 
			tgt_cvg_values, 
			(comp_rv, comp_std), 
			(num_responses, fsvr_start, fsvr_end))


		return (tgt_rv, tgt_std, comp_rv)


	def save_cvg_log(self, tgt_data, tgt_cvg, tgt_values, comp_cvg, svr_data):
		'''
			Saves the given data to a log file.
			'tgt_data' contains a list of FB_Bug objects (the targets)
			'tgt_cvg' is a tuple: (tgt_rv, tgt_std)
			'tgt_values' is a tuple: (cc, mc, bc, lc)
			'comp_cvg' is a tuple: (comp_rv, comp_std)
			'svr_data' is a tuple: (num_responses, fsvr_start, fsvr_end)
		'''

		(tgt_rv, tgt_std) = tgt_cvg
		(cc, mc, bc, lc) = tgt_values
		(comp_rv, comp_std) = comp_cvg
		(num_responses, fsvr_start, fsvr_end) = svr_data

		log_f = "%scvg_log%s.txt" % (FUZZCONFIG.SERVER_LOG_PATH, time.time())

		with open(log_f, 'w') as f:
			txt = "Individual: " + str(individual) + '\n\n'

			txt += "Number of responses from Fuzz Server: " + \
					str(num_responses) + '\n'

			txt += "Start Time of Fuzz Server:\t\t" + str(fsvr_start) + '\n'
			txt += "End Time of Fuzz Server:\t\t" + str(fsvr_end) + '\n\n'

			txt += "-"*30 + "\n"
			txt += "TARGET INFORMATION\n\n"

			txt += "Settings:\t\t(" + str(self.CVG_FOCUSES[self.CVG_FOCUS])+ \
					" coverage, " + \
					self.CVG_GRANULARITY_LIST[self.GRANULARITY] + \
					" granularity)\n\n"

			txt += "Mean Coverage Value:\t" + str(tgt_rv) + "\n"
			txt += "Standard Deviation:\t" + str(tgt_std) + "\n\n"

			txt += 'Number of Values (nov): ' + str(nov) + '\n'
			txt += 'Class CVG (cc):\t\t' + str(cc) + '\n'
			txt += 'Methd CVG (mc):\t\t' + str(mc) + '\n'
			txt += '\tBlock CVG (bc):\t' + str(bc) + '\n'
			txt += '\tLine CVG (lc):\t' + str(lc) + '\n\n'

			txt += "-"*30 + "\n"
			txt += "TARGET COMPLEMENT INFORMATION\n\n"

			txt += "Mean Coverage Value:\t" + str(comp_rv) + "\n"
			txt += "Standard Deviation:\t" + str(comp_std) + "\n\n"

			txt += "\nTARGETS:"

			for target in tgt_data:
				txt += "\n\t" + str(target.name) + "\n\tBug Type:\t" + str(target.type)
				txt += "\n\t" + "-"*30

			
			f.write(txt)
			print 'Coverage log saved to %s' % (log_f)



	def crunch_cvg_data(self, data_list):
		'''
			Calcuates the average code coverage of the given values and 
			the standard deviation of the values
		'''

		nov = len(data_list)
		cc, mc, bc, lc = [], [], [], []
		
		for data in data_list:
			cc.append(data.class_coverage)
			mc.append(data.method_coverage)
			bc.append(data.block_coverage)
			lc.append(data.line_coverage)

		mean_cvg = 0.0
		std_deviation = 0.0

		if self.CVG_FOCUSES[self.CVG_FOCUS] == self.FOCUS_CLASS_CVG:
			mean_cvg = sum(cc)/nov
			sum2 = sum(x*x for x in cc)
			std_deviation = abs(sum2 / nov - mean_cvg**2)**0.5

		if self.CVG_FOCUSES[self.CVG_FOCUS] == self.FOCUS_METHOD_CVG:
			mean_cvg = sum(mc)/nov
			sum2 = sum(x*x for x in mc)
			std_deviation = abs(sum2 / nov - mean_cvg**2)**0.5

		if self.CVG_FOCUSES[self.CVG_FOCUS] == self.FOCUS_BLOCK_CVG:
			mean_cvg = sum(bc)/nov
			sum2 = sum(x*x for x in bc)
			std_deviation = abs(sum2 / nov - mean_cvg**2)**0.5

		if self.CVG_FOCUSES[self.CVG_FOCUS] == self.FOCUS_LINE_CVG:
			mean_cvg = sum(lc)/nov
			sum2 = sum(x*x for x in lc)
			std_deviation = abs(sum2 / nov - mean_cvg**2)**0.5

		'''
		sum2 = sum(x*x for x in cc)
		std_deviation = abs(sum2 / nov - mean_cvg**2)**0.5
		'''

		return (mean_cvg, std_deviation, (cc, mc, bc, lc))



	# ------------------------------------------------------------------------
	# Calculates the average coverage of the given targets at the set granularity level
	# granularity is set by the self.GRANULARITY variable
	# returns the sum of the coverages and the number of calculated values. the avg is easily calculated from this
	# returned data format: (<num_of_values>, <class cvg>, <method cvg>, <block cvg>, <line cvg>)

	# DEPRECATED--------------------------------------------------------------
	def getTargetCoverageValues(self, target_data):
		num_of_values = 0
		class_cvg = []
		method_cvg = []
		block_cvg = []
		line_cvg = []

		#print 'Type: ' + target_data.type + ', target type: ' + self.CVG_GRANULARITY_LIST[self.GRANULARITY] + ', ' + str(target_data.type == self.CVG_GRANULARITY_LIST[self.GRANULARITY])

		if target_data.type == self.CVG_GRANULARITY_LIST[self.GRANULARITY]:
			class_cvg.append(target_data.class_coverage)
			method_cvg.append(target_data.method_coverage)
			block_cvg.append(target_data.block_coverage)
			line_cvg.append(target_data.line_coverage)
			num_of_values = 1

		for child in target_data.children:
			(tmp_nov, tmp_cc, tmp_mc, tmp_bc, tmp_lc) = self.getTargetCoverageValues(child)
			num_of_values = num_of_values + tmp_nov
			#class_cvg = class_cvg + tmp_cc
			#method_cvg = method_cvg + tmp_mc
			#block_cvg = block_cvg + tmp_bc
			#line_cvg = line_cvg + tmp_lc
			if tmp_cc:
				class_cvg.append(tmp_cc[0])
			if tmp_mc:
				method_cvg.append(tmp_mc[0])
			if tmp_bc:
				block_cvg.append(tmp_bc[0])
			if tmp_lc:
				line_cvg.append(tmp_lc[0])



		return (num_of_values, class_cvg, method_cvg, block_cvg, line_cvg)






	# ------------------------------------------------------------------------
	# Find the latest coverage report in the specified directory
	# from http://ubuntuforums.org/showthread.php?t=1526010
	def get_latest_cvg_report(self, path="GA/Reports/"):
		filelist = os.listdir(path)
		filelist = filter(lambda x: not os.path.isdir(path + str(x)), filelist)


		# TODO: Might want to make it so that the coverage reports (xml) are stored in their own
		#		directory for each run, then we can just grab all of the files, parse them, and average 
		#		the results

		# Reason:
		#		What if there are multiple files from the same test run?

		if filelist:
			newest = max(filelist, key=lambda x: os.stat(path + str(x)).st_mtime)
			return path + newest
		else:
			return ""



	# ------------------------------------------------------------------------
	def run_algorithm(self):

		if self.SIMPLE:
			pop = [[1,1,1,1,1,1,1]]
			fitnesses = map(self.toolbox.evaluate, pop)
		else:
			# Set the population size (number of individuals per generation) - each will have to be evaluated
			pop = self.toolbox.population(n=self.POP_SIZE)

			print 'Starting Evolution Algorithm...'

			fitnesses = map(self.toolbox.evaluate, pop)
			for ind, fit in zip(pop, fitnesses):
				# DEBUG-------------------------------------------------------
				print 'fit: ' + str(fit)
				print 'ind: ' + str(ind)
				# END DEBUG --------------------------------------------------
				ind.fitness.values = fit

			for g in range(self.NGEN):
				# Select the next generation of individuals
				offspring = self.toolbox.select(pop, len(pop))
				offspring = map(self.toolbox.clone, offspring)

				# Apply the crossover function (mate) to the new generation and reset the parents' fitness values
				for child1, child2 in zip(offspring[::2], offspring[1::2]):
					if random.random() < self.CXPB:
						self.toolbox.mate(child1, child2)
						del child1.fitness.values
						del child2.fitness.values

				# Apply mutation function - reset any mutant's fitness values
				for mutant in offspring:
					if random.random() < self.MUTPB:
						self.toolbox.mutate(mutant)
						del mutant.fitness.values

				# Only evaluate the individuals who have invalid fitness values
				invalid_ind = [ind for ind in offspring if not ind.fitness.valid]
				fitnesses = map(self.toolbox.evaluate, invalid_ind)
				for ind, fit in zip(invalid_ind, fitnesses):
					ind.fitness.values = fit

				# The new population is the generated offspring and mutants
				pop[:] = offspring


			# Run some numbers to see the stats
			fits = [ind.fitness.values[0] for ind in pop]

			length = len(pop)
			mean = sum(fits) / length
			sum2 = sum(x*x for x in fits)
			std = abs(sum2 / length - mean**2)**0.5

			print 'Algorithm Execution Final Population Results'
			print 'Max: ' + str(max(fits))
			print 'Min: ' + str(min(fits))
			print 'Avg: ' + str(mean)
			print 'StD: ' + str(std)


		return pop



# DEBUG
#lib = imp.load_source('*', '../Fuzz_Server/fuzzer_lib.py')
#f = FuzzServer()
#test = CVG_Max(f)

#test.evaluate()



		




















