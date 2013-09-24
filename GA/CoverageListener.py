


# sits in its own thread and listens on port 8080 for any incomming messages from the coverage reporter
# 		The received data will be a file string in JSON format as such:
#
#				{data:<file text>}
#
#
#	The recieved file text is the text from an XML document that was transmitted as is. Parsing for this 
#	file has already been half-coded in the CoverageWrapper.py file. It is currently commented out there.
#	Use that code to complete the parsing information.
#
#	Tie the coverage statistics in with the 'template' that is given to the fuzzer. Use this to modify the 
#	template in such a way to improve coverage via fuzzing. 
#
#	This folder is where the genetic algorithm, coverage listener, and template script definitions are
#
#	The files in this folder will be accessed by a batch (or shell) script from a higher directory



