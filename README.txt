

Hermes Targeted Fuzz Testing System: README

------------------------------------------------------------------------------
==============================================================================
------------------------------------------------------------------------------

Contents:

	Configuration and Usage
	Parser
	Analyzer
	Coverage
	Fuzz Test Server
	Server Logs
	Genetic Algorithm
	Protocol Definition Creator
	Target Projects

------------------------------------------------------------------------------
==============================================================================
------------------------------------------------------------------------------


Configuration and Usage
------------------------------------------------------------------------------

Usage:

	Some scripts have been written to simplify the excution of Hermes:

	uni_findbugrun.sh 	[Unix: Executes FindBugs on the target]
	win_client.bat 		[Windows: Execute a single run of the client]
	win_evaluation.bat 	[Windows: Execute client infinitely]
	win_findbugrun.bat 	[Windows: Executes FindBugs on the target]
	win_server.bat 		[Windows: Execute the server (hermes.py)]

	--------------------------------------------------------------------------

	> python hermes.py [options]

	OPTIONS:

		-r
			reset:	Reset the fuzz server on Hermes to completely start over.
					This will delete any generated protocol definitions.

		-f
			fuzz:	Activate the fuzz server and start the testing.
					This also activates the genetic algorithm to start 
					generating protocol definitions.

		-c
			cvg:	Activate the coverage listener server. This is used to 
					listen for coverage reports sent from the client-side 
					of Hermes (Coverage wrapper for EMMA).

------------------------------------------------------------------------------

Configuration:
	
	Dependencies:

		Python 2.7 (With PATH set)		[Untested on Python 3.0+]
		Java 1.6.2+ (With PATH set)
		DEAP (Python genetic algorithm library)


	Set the target for Hermes in the win_findbugrun.bat and uni_findbugrun.sh 
	scripts. The win_client.bat and win_evaluation.bat will also have to be 
	modified to exeute the target application.


------------------------------------------------------------------------------
==============================================================================
------------------------------------------------------------------------------


Parser
------------------------------------------------------------------------------

The parser takes the results from FindBugs (*_findbugrun.[sh|bat], which 
produces an xml file) and converts the information into an intermediate 
list format with only the information desired (general filtering).


------------------------------------------------------------------------------
==============================================================================
------------------------------------------------------------------------------


Analyzer
------------------------------------------------------------------------------

The ananlyzer takes the results from the parser and e















------------------------------------------------------------------------------
General Flow


-> user only runs 'win_findbugrun.bat'


win_finbugrun.bat takes target jars and produces results that are fed into parser.
The parser parses results and defect densities and produces formatted inputs for analyzer.
The analyzer takes formatted inputs and determines which class should be the focus of the test.

(Right now, the analyzer only targets a single class. Multiple class targets are definitely
possible.)

NOT INCLUDED YET
win_findbugrun.bat will also initialize the fuzz server


NOTE:
	uni_findbugrun.sh is the unix version of the win_findbugrun.bat file




-------------------------------------------------------------------------
Assumptions

-> Python is installed and configured on the current system (Including in, 
	Windows, the PATH variable)
-> Java is installed and configured on the current system
-> DEAP (Python genetic algorithm library) is installed as a Python library









-------------------------------------------------------------------------
Parser



-------------------------------------------------------------------------
Analyzer



-------------------------------------------------------------------------
Target Jars



-------------------------------------------------------------------------
win_findbugrun.bat


The Windows batch file that runs the python scripts






