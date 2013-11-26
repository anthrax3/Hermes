
# 
# Hermes Testing Framework
#
# Author:		Caleb Shortt
#
# Date:			November 2013
#
# 
# Description:	Hermes is a security testing framework. It utilizes static analysis, fuzz testing, 
# 				coverage metrics, and genetic algorithms to target software weaknesses and 
# 				maximize testing potential, and exploitation, of those targeted weaknesses.
#
#				Hermes targets Java applications and is intended to be used during the development
#				process (in continuous integration), particularly in the build tests.
# 
# 				Feedback is provided using the EMMA coverage tool wrapped in a messenger application. 
# 				This allows for a client-server relationship with the tester and the target
#				software. To utilize the EMMA tool and messenger, it is assumed that access 
#				to the target source code is allowed. Additionally, the static analysis and 
#				initial target acquisition requires access to the source code (at least the JARs)
#
# Included / Required Software:
#				FindBugs Version 2.0.2 		(Included)		(Static Analysis Tool)
#				EMMA Version 2.0.5312		(Included)		(Coverage Metrics Tool)
#				DEAP 1.0.0 rc2				(Required)		(Genetic Algorithm Library)
#				Python Version 2.7			(Required)		(Majority of Hermes is written in Python)
#				Java Version 1.6+			(Required)		(FindBugs is a JAR, and Hermes targets Java applications)
# 
# Basic Flow:
#
#		1. Execute static analysis (FindBugs)
#		2. Parse static snalysis results
#		3. Analyze parsed data from static analysis and provide target (or cluster of targets)
#		4. (SERVER) Take initial protocol definition and begin genetic algorithm (starts fuzz server)
#		5. (SERVER) Initiate coverage listener (Listens for the coverage data that is sent from the client - EMMA)
#		6. (CLIENT) Initiate target software (Crawler)
#		7. (CLIENT) Once crawler crashes or runs out of links, send coverage data (from EMMA) to server (coverage listener)
#		8. (SERVER) Receive coverage data, update protocol definition based on genetic algorithm suggestions
#		9. (SERVER) Re-initiate server and wait for client to reconnect
#
# -------------------------------------------------------------------------------------------------------------------------
#
# Basic Usage:
#
#	python hermes.py [-FuzzServer|-CVGListen]
#
#	Commands:
#		-f, --FuzzServer			Starts the fuzz server. The server will initialize by default on localhost:80.
#		-c, --CVGListen			Starts the coverage listener
#	
#		A command (specified above) is required to be specified for Hermes to execute.
#


import getopt, sys, os, inspect, imp

# Add the current path to the system path
# Found here: http://stackoverflow.com/questions/279237/import-a-module-from-a-folder
cmd_folder = os.path.realpath(os.path.abspath(os.path.split(inspect.getfile( inspect.currentframe() ))[0] ))
if cmd_folder not in sys.path:
	sys.path.insert(0, cmd_folder)





class Hermes():


	def __init__(self):
		self.addSysPaths()


# ---------------------------------------------------------------------------------------------------------
	def runFuzzServer(self, address="localhost", port=80):

		from GA_Cvg_Report_Interpreter import CVG_Max
		from fuzzer_lib import FuzzServer

		# DEBUG - set the server to only take 10 requests or run for 1 minute
		# Normal execution: 100 requests, or 10 minutes
		fuzz_algorithm = CVG_Max(FuzzServer(1000, 10))
		fuzz_algorithm.run_algorithm()


# ---------------------------------------------------------------------------------------------------------
	def runBasicFuzzServer(self, address="localhost", port=80):
		from GA_Cvg_Report_Interpreter import CVG_Max
		from fuzzer_lib import FuzzServer

		fuzz_algorithm = CVG_Max(FuzzServer(1000, 10), CX=0.5, MPB=0.2, NG=1, PS=1, simple=True)
		fuzz_algorithm.run_algorithm()



# ---------------------------------------------------------------------------------------------------------
	def runCoverageListener(self):
		
		from CoverageListener import Listener

		cvg_listener = Listener()
		cvg_listener.run()




# ---------------------------------------------------------------------------------------------------------
	def reset(self):
		try:
			from PD_Creator.Protocol_Definition_Creator import PDef_Creator
			pd = PDef_Creator()
			prot = pd.genAdvancedHTML([1,1,1,1,1,1,1])
			pd.save_protocol(prot)
			print 'Fuzz Server Reset.'
		except Exception as e:
			print 'An unexpected exception has occurred while trying to reset Hermes: ' + str(e)





# ---------------------------------------------------------------------------------------------------------
	def addSysPaths(self):

		# Set the system path to include the path to the fuzzing code
		fuzz_subfolder = os.path.realpath(
			os.path.abspath(
				os.path.join(
					os.path.split(
						inspect.getfile( inspect.currentframe() ))[0], "Fuzz_Server")))

		if fuzz_subfolder not in sys.path:
			sys.path.insert(0, fuzz_subfolder)

		
		# Add the genetic algorithm directory to the path too
		ga_subfolder = os.path.realpath(
			os.path.abspath(
				os.path.join(
					os.path.split(
						inspect.getfile( inspect.currentframe() ))[0], "GA")))

		if ga_subfolder not in sys.path:
			sys.path.insert(0, ga_subfolder)

		# Add the PD_Creator module
		pd_subfolder = os.path.realpath(
			os.path.abspath(
				os.path.join(
					os.path.split(
						inspect.getfile( inspect.currentframe() ))[0], "PD_Creator")))

		if pd_subfolder not in sys.path:
			sys.path.insert(0, pd_subfolder)

		# Add the Coverage module
		cvg_subfolder = os.path.realpath(
			os.path.abspath(
				os.path.join(
					os.path.split(
						inspect.getfile( inspect.currentframe() ))[0], "Coverage")))

		if cvg_subfolder not in sys.path:
			sys.path.insert(0, cvg_subfolder)

		# Add the config module
		cfg_subfolder = os.path.realpath(
			os.path.abspath(
				os.path.join(
					os.path.split(
						inspect.getfile( inspect.currentframe() ))[0], "Config")))

		if cfg_subfolder not in sys.path:
			sys.path.insert(0, cfg_subfolder)

		# Add the Analyzer module
		cfg_subfolder = os.path.realpath(
			os.path.abspath(
				os.path.join(
					os.path.split(
						inspect.getfile( inspect.currentframe() ))[0], "Analyzer")))

		if cfg_subfolder not in sys.path:
			sys.path.insert(0, cfg_subfolder)





# ---------------------------------------------------------------------------------------------------------

def usage():
	print '\nHERMES SECURITY TESTING FRAMEWORK'
	print 'Usage: > python hermes.py [--FuzzServer|--CVGListen|--reset]'
	print 'Commands:'
	print '\t-f, --FuzzServer\n\t\tStarts the fuzz server. Default address is localhost:80'
	print '\t-c, --CVGListen\n\t\tStarts the coverage listener'
	print '\t-r, --reset\n\t\tResets the protocol definition to default'
	print '\n'
	print '\tThe user MUST specify a command (above) for Hermes to execute'


if __name__ == "__main__":

	command = ""

	arguments = sys.argv[1:]
	try:
		opts, args = getopt.getopt(arguments, "fcrb", ["FuzzServer", "CVGListen", "reset", "BasicFuzzServer"])
	except getopt.GetoptError:
		usage()
		sys.exit(2)
	
	for opt, arg in opts:
		if opt in ("-f", "--FuzzServer"):
			command = "FuzzServer"
		elif opt in ("-c", "--CVGListen"):
			command = "CVGListen"
		elif opt in ("-r", "--reset"):
			command = "reset"
		elif opt in ("-b", "--basic"):
			command = "basic"


	if command and command == "FuzzServer":
		hermes = Hermes()
		hermes.runFuzzServer()
	elif command and command == "CVGListen":
		hermes = Hermes()
		hermes.runCoverageListener()
	elif command and command == "reset":
		hermes = Hermes()
		hermes.reset()
	elif command and command == "basic":
		hermes = Hermes()
		hermes.runBasicFuzzServer()
	else:
		usage()
		sys.exit(2)

















