

#	
#	coverage.py
#	
#	This file contains the settings for the coverage listener and transmitter.
#	
#	Creator: 	Caleb Shortt
#	Date:		October 1, 2013
#	

import os

class DETAILS:
	# port and ip address of the coverage listener (and where the fuzzer server is)
	CVG_PORT 		= 28000
	CVG_ADDRESS 	= "127.0.0.1"

	LIST_XML_DUMP_PATH = ".." + str(os.sep) + "GA" + str(os.sep) + "Reports" + str(os.sep)
	























