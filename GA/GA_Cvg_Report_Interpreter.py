
'''
	Genetic Algorithm Coverage Report Interpreter

	Author:	Caleb Shortt, 2013

	Description:
		This program takes the latest coverage report from the 'Reports' 
		directory and uses the coverage metrics contained within to determine 
		the format of the next sulley protocol definition.

		The protocol definition creator is initialized and used to construct 
		the templates.
'''


import random
import os
import imp
import time
import traceback
import logging

from datetime import datetime, timedelta
from deap import creator, base, tools

from PD_Creator.Protocol_Definition_Creator import PDef_Creator
from PD_Creator.PD_Helpers import HelperFunctions
from Config.analysis import DETAILS
from CvgHelpers import EMMAXMLParser
from Config.fuzzserver import DETAILS as FUZZCONFIG


class CVG_Max():

	def __init__(self, fuzz_server, CX=0.5, MPB=0.1, NG=30, PS=10, 
				simple=False, timeout=3600):

		self.logger = logging.getLogger('GA_CRI_Logger')
		self.logger.setLevel(logging.DEBUG)
		fh = logging.FileHandler('Logs/GA_CRI.log', mode='w')
		fh.setLevel(logging.DEBUG)
		formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
		fh.setFormatter(formatter)
		self.logger.addHandler(fh)

		# Probabilities and values for genetic algorithm
		self.CXPB = CX
		self.MUTPB = MPB
		self.NGEN = NG
		self.POP_SIZE = PS
		self.SIMPLE = simple

		# From (/Fuzz_Server/fuzzer_lib.py)
		self.Fuzz_Server = fuzz_server

		self.start_time = None

		# Server timeout in seconds
		self.TIMEOUT = timeout

		
		self.pd_creator = PDef_Creator()
		self.helper_functions = HelperFunctions()

		self.target_list = self.helper_functions.loadPickledFile(
					DETAILS.PATH_TO_ANALYZER + DETAILS.TARGET_FILENAME)


		self.emma_xml_parser = EMMAXMLParser(self.target_list)


		self.PACKAGE_LEVEL	= "package"
		self.SRCFILE_LEVEL	= "srcfile"
		self.CLASS_LEVEL	= "class"
		self.METHOD_LEVEL	= "method"

		self.CVG_GRANULARITY_LIST = [self.PACKAGE_LEVEL, 
									self.SRCFILE_LEVEL, 
									self.CLASS_LEVEL, 
									self.METHOD_LEVEL]

		# Chosen granularity (index of above list)
		self.GRANULARITY = 3

		# Coverage Focus
		self.FOCUS_CLASS_CVG = "class"
		self.FOCUS_METHOD_CVG = "method"
		self.FOCUS_BLOCK_CVG = "block"
		self.FOCUS_LINE_CVG = "line"

		self.CVG_FOCUSES = [self.FOCUS_CLASS_CVG, 
							self.FOCUS_METHOD_CVG, 
							self.FOCUS_BLOCK_CVG, 
							self.FOCUS_LINE_CVG]

		# Coverage focus (index of above list)
		self.CVG_FOCUS = 3


		'''
			Start of Genetic Algorithm-Specific Code

			Create a maximizing fitness parameter for mean coverage of target 
			code, minimizing parameter for the target cvg standard deviation, 
			and a minimizing parameter for non-target code coverage (target 
			complement)

			Goal:
				Max target cvg
				Minimize std deviation, other code cvg, and number of 'genes' used
		'''
		creator.create("CvgMaxMin", base.Fitness, weights=(1.0, -1.0, -1.0, -1.0))
		creator.create("Individual", list, fitness=creator.CvgMaxMin)

		'''
			As of January 2014, There are 7 features for each individual
			(In this order):

			[Links Enabled, imgs enabled, divs enabled, iframes enabled, 
			objects enabled, js enabled, applets enabled]
		'''
		INDIVIDUAL_SIZE = 7

		self.toolbox = base.Toolbox()
		self.toolbox.register("attr_bool", random.randint, 0, 1)
		self.toolbox.register("individual", tools.initRepeat, 
			creator.Individual, self.toolbox.attr_bool, n=INDIVIDUAL_SIZE)

		self.toolbox.register("population", tools.initRepeat, list, 
			self.toolbox.individual)

		self.toolbox.register("mate", tools.cxTwoPoints)
		self.toolbox.register("mutate", tools.mutFlipBit, indpb=0.05)
		self.toolbox.register("select", tools.selTournament, tournsize=3)
		self.toolbox.register("evaluate", self.evaluate)

		#fuzz_server, CX=0.5, MPB=0.1, NG=30, PS=10, 
		#simple=False, timeout=3600
		params = {"CX": CX, "MPB": MPB, "NG": NG, "PS": PS, "simple": simple, "timeout": timeout}
		self.logger.info('GA Initialized with params: ' + str(params))



	def evaluate(self, individual):
		'''
			Evaluate the given individual.
			This means running the fuzz server until it has hit its specified 
			number of responses (with the individual dictating the protocol 
			used).
		'''

		print 'Evaluating individual: ' + str(individual)
		self.logger.info('Individual: ' + str(individual))

		# Time evaulation started - used to find latest eval report.
		#self.start_time = datetime.now()
		self.mark_server_start()

		# try to get the protocol definition for the given individual.
		try:
			self.pd_creator.reset()
			pdef = self.pd_creator.generate_html(individual)

		except Exception as ex:
			self.logger.error('An unexpected exception occurred while generating the ' + \
						'protocol definition.\n' + str(ex))

		# try to save the generated protocol definition
		if pdef:
			self.pd_creator.save_protocol(pdef)
		else:
			raise Exception("No Protocol Definition Created")

		'''
			Attempt to load the auto-generated protocol definition into 
			sulley and run the fuzz server
		'''
		try:
			self.Fuzz_Server.reset()
			self.Fuzz_Server.reloadSulleyRequest()
			self.Fuzz_Server.run()



			# now in generate_report()
			#(num_resps, fsvr_start, fsvr_end) = self.Fuzz_Server.getStats()
		except Exception as e:
			self.logger.critical('An unexpected error has occurred while evaluating the ' + \
							'fuzz server.\n' + str(e))

		return self.generate_results(individual)



	def mark_server_start(self):
		self.start_time = datetime.now()
		self.logger.info('mark_server_start: server start time set to ' + str(self.start_time))


	def generate_results(self, individual):
		(num_resps, fsvr_start, fsvr_end) = self.Fuzz_Server.getStats()

		# Get the latest coverage report from EMMA
		report_file = self.get_latest_cvg_report()
		if report_file:
			report_created = datetime.fromtimestamp(
								os.stat(report_file).st_mtime)
		else:
			report_created = datetime(2010, 1, 1, 1, 1)


		'''
			If the report was NOT created after the 'self.start_time' 
			timestamp, wait for the new results to show up. This might 
			take a while since it is transferred to the coverage listener 
			which saves it to file.
		'''
		if self.start_time > report_created:
			self.logger.info('Waiting for coverage report to finish writing')
			print 'Waiting for coverage report to finish writing'

		timeout_time = datetime.now() + timedelta(minutes=self.TIMEOUT)
		time_count = 0
		while (self.start_time > report_created) and \
				(datetime.now() < timeout_time):

			time.sleep(1)
			if time_count % 10 == 0:
				self.logger.info('... ' + str(time_count))
				print '.',

			report_file = self.get_latest_cvg_report()
			if report_file:
				report_created = datetime.fromtimestamp(
									os.stat(report_file).st_mtime)
			time_count = time_count + 1

		print 'Report found. Analyzing.'
		self.logger.info('Analyzing Coverage XML Report.')

		report_xml = ""
		with open(report_file, "r") as f:
			report_xml = f.read()


		try:
			self.emma_xml_parser.extractEMMAData(report_xml)
		except Exception as e:
			self.logger.error(str(e) + "\n" + 'Parse Error: Skipping test.')
			return (0, 1, 1, 100)


		# NOTE: tgt_data and tgt_comp are lists of TargetData objects
		tgt_data = self.emma_xml_parser.getTargetResults()
		tgt_comp = self.emma_xml_parser.getTargetComplement()

		(tgt_rv, tgt_std, tgt_cvg_values) = self.crunch_cvg_data(tgt_data)
		(comp_rv, comp_std, comp_cvg_values) = self.crunch_cvg_data(tgt_comp)

		self.logger.info(
			"Coverage Value (" + str(self.CVG_FOCUSES[self.CVG_FOCUS]) + \
			" coverage, " + self.CVG_GRANULARITY_LIST[self.GRANULARITY] + \
			" granularity): " + str(tgt_rv))

		self.save_cvg_log(
			tgt_data, 
			(tgt_rv, tgt_std), 
			tgt_cvg_values, 
			(comp_rv, comp_std), 
			(num_resps, fsvr_start, fsvr_end),
			individual)

		gene_count = self.get_gene_count(individual)

		return (tgt_rv, tgt_std, comp_rv, gene_count)



	def get_gene_count(self, individual):
		return sum(individual)



	def save_cvg_log(self, tgt_data, tgt_cvg, tgt_values, comp_cvg, svr_data, 
					individual):
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
				txt += "\n\t" + str(target.name) + "\n\tBug Type:\t" + \
						str(target.type)

				txt += "\n\t" + "-"*30

			
			f.write(txt)
			self.logger.info('Coverage log saved to ' + str(log_f))



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

		return (mean_cvg, std_deviation, (cc, mc, bc, lc))



	def get_latest_cvg_report(self, path="GA/Reports/"):
		'''
			Finds the latest coverage report in the specified directory
			Used from: 
				http://ubuntuforums.org/showthread.php?t=1526010
		'''

		filelist = os.listdir(path)
		filelist = filter(lambda x: not os.path.isdir(path+str(x)), filelist)

		'''
			TODO:
				Might want to make it so that the coverage reports (xml) are 
				stored in their own directory for each run, then we can just 
				grab all of the files, parse them, and average the results.

				Reason:
					What if there are multiple files from the same test run?
		'''

		if filelist:
			newest = max(filelist, 
						key=lambda x: os.stat(path + str(x)).st_mtime)
			return path + newest
		else:
			return ""



	def run_algorithm(self):
		'''
			Initiate the genetic algorithm.

			This function takes the population, evaluates each individual 
			and then creates the new generation based on the performance 
			of the previous generation's individuals (via mutation, 
			selection, )
		'''

		if self.SIMPLE:
			pop = [[1,1,1,1,1,1,1]]
			fitnesses = map(self.toolbox.evaluate, pop)
		else:
			pop = self.toolbox.population(n=self.POP_SIZE)

			print 'Starting Algorithm.'
			self.logger.info('Starting Evolution Algorithm...')

			fitnesses = map(self.toolbox.evaluate, pop)
			for ind, fit in zip(pop, fitnesses):
				ind.fitness.values = fit

			for g in range(self.NGEN):
				# Select the next generation of individuals
				offspring = self.toolbox.select(pop, len(pop))
				offspring = map(self.toolbox.clone, offspring)

				# Apply the crossover function (mate)
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

			self.logger.info('Algorithm Execution Final Population Results')
			self.logger.info('Max: ' + str(max(fits)))
			self.logger.info('Min: ' + str(min(fits)))
			self.logger.info('Avg: ' + str(mean))
			self.logger.info('StD: ' + str(std))

		return pop



# DEBUG
#lib = imp.load_source('*', '../Fuzz_Server/fuzzer_lib.py')
#f = FuzzServer()
#test = CVG_Max(f)

#test.evaluate()

