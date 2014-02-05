
clear

classpath=Target_Projects/Crawler4j/jars
fboutputfile=fb_results.xml
fbtargetjar=Target_Projects/Crawler4j/crawler4j-3.5.jar
fbddfile=defectdensity.txt

classpathjars=""

echo "Updating Hermes config and modules..."
sudo python setup.py install
echo "Running FindBugs..."
./findbugs-2.0.2/bin/findbugs -textui -xml -auxclasspath $classpath -output $fboutputfile $fbtargetjar
echo "Done."
echo "Running Parser..."
python Parser/parser.py -d $fbddfile -b $fboutputfile
echo "Done."
echo "Running Analyzer..."
python Analyzer/analyzer.py -r parse_results.txt
echo "Done."








