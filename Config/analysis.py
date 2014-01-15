
#	
#	Config file for the Analyzer
#	
#	
#	

import os


class DETAILS:

	TARGET_FILENAME = "targets"

	# path to analyzer from root
	PATH_TO_ANALYZER = "Analyzer" + str(os.sep)

	# Top percent (0.0 to 1.0) of the problem bugs that we will focus on
	PERCENT_CODE_TO_KEEP = 0.2



