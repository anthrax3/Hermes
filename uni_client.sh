
curr=${PWD}
target_path=$curr/Target_Projects
emmapath=$curr/Coverage/EMMA/lib

java -XX:-UseSplitVerifier -cp $emmapath/emma.jar emmarun -verbose -r xml -jar $target_path/BasicCrawler.jar test 1
python $curr/Coverage/CoverageWrapper.py -f coverage.xml
