

import logging
import random


class logging_tester(object):

	def __init__(self):
		logging.basicConfig(filename="logging_tests", level=logging.INFO)



	def do_loop(self, iterations):
		for i in range(iterations):
			if i % 2:
				logging.debug("Should be in debug ... " + str(random.random()))
			else:
				logging.warning("Should be in warning ..." + str(random.random()))

			logging.info("All in info" + str(random.random()))



if __name__ == "__main__":
	log_class = logging_tester()
	log_class.do_loop(10)





















