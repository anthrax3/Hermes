
curr=${PWD}

java -XX:-UseSplitVerifier -cp $curr/Coverage/EMMA/lib/emma.jar emmarun -verbose -r xml -jar $curr/Target_Projects/BasicCrawler.jar test 1
python $curr/Coverage/CoverageWrapper.py -f coverage.xml
