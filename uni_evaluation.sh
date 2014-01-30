max_time_minutes=4320
now_ts=$(date +%s)
end_ts=$((now_ts + max_time_minutes*60))
curr=${PWD}
while [ $(date +%s) -lt $end_ts ]
do
	java -XX:-UseSplitVerifier -cp $curr/Coverage/EMMA/lib/emma.jar emmarun -verbose -r xml -jar $curr/Target_Projects/BasicCrawler.jar test 1
	python $curr/Coverage/CoverageWrapper.py -f coverage.xml
done
