
import random, sys
from deap import creator, base, tools

class Max():

	def __init__(self):
		creator.create("FitnessMax", base.Fitness, weights=(1.0,))
		creator.create("Individual", list, fitness=creator.FitnessMax)

		INDIVIDUAL_SIZE = 10

		self.toolbox = base.Toolbox()
		self.toolbox.register("attr_bool", random.randint, 0, 1)
		self.toolbox.register("individual", tools.initRepeat, creator.Individual, self.toolbox.attr_bool, n=INDIVIDUAL_SIZE)
		self.toolbox.register("population", tools.initRepeat, list, self.toolbox.individual)

		self.toolbox.register("mate", tools.cxTwoPoints)
		self.toolbox.register("mutate", tools.mutFlipBit, indpb=0.05)
		self.toolbox.register("select", tools.selTournament, tournsize=3)
		self.toolbox.register("evaluate", self.evaluate)

		print self.main()


	def evaluate(self, individual):
		# Some debug code
		print 'Evaluating Individual: ' + str(individual)
		return sum(individual),

	def main(self):

		CXPB, MUTPB, NGEN = 0.5, 0.2, 40
		pop = self.toolbox.population(n=10)

		print "Starting the Evolution Algorithm..."

		fitnesses = list(map(self.toolbox.evaluate, pop))
		for ind, fit in zip(pop, fitnesses):
			ind.fitness.values = fit

		# ----------------------------------------------------------
		# Killing the program here - just want to see the population created
		sys.exit()

		print "Evaluated %i individuals" % (len(pop))

		for g in range(NGEN):
			print "-- Generation %i --" % (g)

			# Select the next genereation individuals
			offspring = self.toolbox.select(pop, len(pop))

			# Clone the selected individuals
			offspring = list(map(self.toolbox.clone, offspring))

			# Apply crossover and mutation on the offspring
	        for child1, child2 in zip(offspring[::2], offspring[1::2]):
	        	if random.random() < CXPB:
	        		self.toolbox.mate(child1, child2)
	            	del child1.fitness.values
	            	del child2.fitness.values

	        for mutant in offspring:
	        	if random.random() < MUTPB:
	        		self.toolbox.mutate(mutant)
	        		del mutant.fitness.values

	        # Evaluate the individuals with an invalid fitness
	        invalid_ind = [ind for ind in offspring if not ind.fitness.valid]
	        fitnesses = map(self.toolbox.evaluate, invalid_ind)
	        for ind, fit in zip(invalid_ind, fitnesses):
	        	ind.fitness.values = fit

	        print "\tEvaluated %i individuals" % (len(pop))

	        pop[:] = offspring

	        fits = [ind.fitness.values[0] for ind in pop]

	        length = len(pop)
	        mean = sum(fits) / length
	        sum2 = sum(x*x for x in fits)
	        std = abs(sum2 / length - mean**2)**0.5

	        print "\tMin %s" % (min(fits))
	        print "\tMax %s" % (max(fits))
	        print "\tAvg %s" % (mean)
	        print "\tStd %s" % (std)




class Multi():

	def __init__(self):
		IND_SIZE = 5

		creator.create("FitnessMin", base.Fitness, weights=(-1.0, -1.0))
		creator.create("Individual", list, fitness=creator.FitnessMin)

		self.toolbox = base.Toolbox()
		self.toolbox.register("attr_float", random.random)
		self.toolbox.register("individual", tools.initRepeat, creator.Individual, self.toolbox.attr_float, n=IND_SIZE)

		ind1 = self.toolbox.individual()

		print "Individual: " + str(ind1)
		print "Valid?: " + str(ind1.fitness.valid)

		print "Evaluating..."
		ind1.fitness.values = self.evaluate(ind1)

		print "Valid?: " + str(ind1.fitness.valid)
		print "Fitness: " + str(ind1.fitness)


	def evaluate(self, individual):
		a = sum(individual)
		b = len(individual)
		return a, 1. / b


class Knapsack():

	def __init__(self):

		NBR_ITEMS = 20
		IND_INIT_SIZE = 5
		MAX_ITEM = 50
		MAX_WEIGHT = 50

		# weights -> (<minimize bag size>, <Maximize value of the bag>)
		creator.create("Fitness", base.Fitness, weights=(-1.0, 1.0))
		creator.create("Individual", set, fitness=creator.Fitness)

		items = {}
		for i in range(NBR_ITEMS):
			items[i] = (random.randint(1, 10), random.uniform(0, 100))

		self.toolbox.register("attr_item", random.randrange, NBR_ITEMS)




	def evaluate(individual):
		weight = 0.0
		value = 0.0

		for item in individual:
			weight += items[item][0]
			value += items[item][1]

		# Ensure overweighted bags are dominated
		if len(individual) > MAX_ITEM or weight > MAX_WEIGHT:
			return 10000, 0

		return weight, value


	



class R_Test:
	def __init__(self):

		print str([random.randint(0, 1) for i in range(10)])


if __name__ == '__main__':
	#random.seed()
	#rt = R_Test()
	mx = Max()
	#mti = Multi()