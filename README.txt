

				Thesis Code

=========================================================================

Contents:

<dir>	Analyzer
<dir>	Config
<dir>	Coverage
<dir>	<findbugs directory>
<dir>	Fuzz_Server
<dir>	GA
<dir>	Parser
<dir>	Target_Projects
<dir>	test

	README.txt
	uni_findbugrun.sh
	win_client.bat
	win_findbugrun.bat






-------------------------------------------------------------------------
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

-> FindBugs is installed on the current system
-> Python is installed and configured on the current system
-> Java is installed and configured on the current system
-> DEAP (Python genetic algorithm library) is installed







-------------------------------------------------------------------------
Parser



-------------------------------------------------------------------------
Analyzer



-------------------------------------------------------------------------
Target Jars



-------------------------------------------------------------------------
win_findbugrun.bat


The Windows batch file that runs the python scripts






