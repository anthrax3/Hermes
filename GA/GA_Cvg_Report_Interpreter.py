
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


from deap import creator, base, tools
import random, os, imp, time
from datetime import datetime, timedelta
import traceback

from PD_Creator.Protocol_Definition_Creator import PDef_Creator


class CVG_Max():

	def __init__(self, fuzz_server):

		# The fuzz server and all its functions (/Fuzz_Server/fuzzer_lib.py)
		self.Fuzz_Server = fuzz_server

		# Server timeout in seconds
		self.TIMEOUT = 60

		# Initialize a protocol definition creator
		self.pd_creator = PDef_Creator()

		# Create a maximizing fitness parameter for coverage
		creator.create("FitnessMax", base.Fitness, weights=(1.0,))

		# Each individual will be a list of flags that say which attribute is added, and which is not
		creator.create("Individual", list, fitness=creator.FitnessMax)

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
			pdef = self.pd_creator.genAdvancedHTML(individual)
		except Exception as ex:
			print 'An unexpected exception occurred while generating the protocol definition.\n%s\n' % (str(ex))

		# try to save the generated protocol definition
		if pdef:
			self.pd_creator.save_protocol(pdef)
		else:
			raise Exception("No Protocol Definition Created")

		# Attempt to load the auto-generated protocol definition into sulley and run the fuzz server
		try:
			self.Fuzz_Server.reloadSulleyRequest()
			self.Fuzz_Server.run()
		except Exception as e:
			print 'An unexpected error has occurred while evaluating the fuzz server.\n%s\n' % (str(e))
			traceback.print_exc()


		# Get the latest coverage report from EMMA
		report_file = self.get_latest_cvg_report()
		report_created = datetime.fromtimestamp(os.stat(report_file).st_mtime)

		# If the report was NOT created after the 'started_at' timestamp, wait for the new results to show up
		# This might take a while since it is transferred to the coverage listener which saves it to file
		if started_at > report_created:
			print 'Waiting for coverage report to finish writing'

		timeout_time = datetime.now() + timedelta(minutes=self.TIMEOUT)
		while (started_at > report_created) and (datetime.now() < timeout_time):

			print '='*40
			print 'started at: ' + str(started_at) + ", " + str(report_file) + " created: " + str(report_created)
			print 'started_at > report_created = ' + str(started_at > report_created)
			print 'now < timeout_time = ' + str(datetime.now() < timeout_time)
			print ''

			time.sleep(1)
			print '.',
			report_file = self.get_latest_cvg_report()
			report_created = datetime.fromtimestamp(os.stat(report_file).st_mtime)

		# Now we have the proper coverage report for the evaluation we just did
		# Now extract the selected coverage metrics and return them

		print str(report_file)

		return 1


	# Find the latest coverage report in the specified directory
	# from http://ubuntuforums.org/showthread.php?t=1526010
	def get_latest_cvg_report(self, path="GA/Reports/"):
		filelist = os.listdir(path)
		filelist = filter(lambda x: not os.path.isdir(path + str(x)), filelist)
		newest = max(filelist, key=lambda x: os.stat(path + str(x)).st_mtime)
		return path + newest


	def run_algorithm(self):
		# probability of crossing two individuals (mate), mutation probability, number of generations
		CXPB, MUTPB, NGEN = 0.5, 0.2, 30
		POP_SIZE = 50
		random.seed(64)

		# Set the population size (number of individuals per generation) - each will have to be evaluated
		pop = self.toolbox.population(n=POP_SIZE)

		print 'Starting Evolution Algorithm...'

		fitnesses = map(self.toolbox.evaluate, pop)
		for ind, fit in zip(pop, fitnesses):
			ind.fitness.values = fit

		for g in range(NGEN):
			# Select the next generation of individuals
			offspring = self.toolbox.select(pop, len(pop))
			offspring = map(self.tool.clone, offspring)

			# Apply the crossover function (mate) to the new generation and reset the parents' fitness values
			for child1, child2 in zip(offspring[::2], offspring[1::2]):
				if random.random() < CXPB:
					self.toolbox.mate(child1, child2)
					del child1.fitness.values
					del child2.fitness.values

			# Apply mutation function - reset any mutant's fitness values
			for mutant in offspring:
				if random.random() < MUTPB:
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




		'''
		fitnesses = list(map(self.toolbox.evaluate, pop))
		for ind, fit in zip(pop, fitnesses):
			ind.fitness.values = fit


		for g in range(NGEN):

			# Select the next generation of individuals
			offspring = self.toolbox.select(pop, len(pop))

			offspring = list(map(self.toolbox.clone, offspring))

			# Apply the crossover function (mate) to the new generation and reset the parents' fitness values
			for child1, child2 in zip(offspring[::2], offspring[1::2]):
				if random.random() < CXPB:
					self.toolbox.mate(child1, child2)
					del child1.fitness.values
					del child2.fitness.values

			# Apply mutation function - reset any mutant's fitness values
			for mutant in offspring:
				if random.random() < MUTPB:
					self.toolbox.mutate(mutant)
					del mutant.fitness.values

			# Only evaluate the individuals who have invalid fitness values
			invalid_ind = [ind for ind in offspring if not ind.fitness.valid]
			fitnesses = map(self.toolbox.evaluate, invalid_ind)
			for ind, fit in zip(invalid_ind, fitnesses):
				ind.fitness.values = fit


			# The new population is the generated offspring and mutants
			pop[:] = offspring


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
		'''





# DEBUG
#lib = imp.load_source('*', '../Fuzz_Server/fuzzer_lib.py')
#f = FuzzServer()
#test = CVG_Max(f)

#test.evaluate()



		




















