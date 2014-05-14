

from distutils.core import setup

setup(
    name='Hermes',
    description='Hermes Software Testing Framework',
    version='0.0.1',
    author='Caleb Shortt',
    author_email='cshortt@uvic.ca', 
    packages=['Analyzer', 'Config', 'Coverage', 'Fuzz_Server', 'GA', 'Parser', 'PD_Creator', 'Generated_Protocols'],
)


