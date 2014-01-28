java -XX:-UseSplitVerifier -cp Coverage/EMMA/lib/emma.jar emmarun -verbose -r xml -jar Target_Projects/BasicCrawler.jar test 1

python Coverage/CoverageWrapper.py -f coverage.xml