@echo off

REM -auxclasspath %classpathjars%
REM -xml:withMessages -output findbug_results.xml

REM set classpath=C:\Users\Caleb\Desktop\Crawler4j\jars
set classpath=%CD%\Target_Projects\Crawler4j\jars

set classpathjars=%classpath%\apache-mime4j-core-0.7.jar;%classpath%\apache-mime4j-dom-0.7.jar;%classpath%\asm-3.1.jar;%classpath%\boilerpipe-1.1.0.jar;%classpath%\commons-codec-1.6.jar;%classpath%\commons-compress-1.3.jar;%classpath%\commons-logging-1.1.1.jar;%classpath%\geronimo-stax-api_1.0_spec-1.0.1.jar;%classpath%\httpclient-4.2.3.jar;%classpath%\httpcore-4.2.2.jar;%classpath%\je-4.0.92.jar;%classpath%\log4j-1.2.14.jar;%classpath%\metadata-extractor-2.4.0-beta-1.jar;%classpath%\tagsoup-1.2.1.jar;%classpath%\tika-core-1.0.jar;%classpath%\tika-parsers-1.0.jar

if NOT "%1"=="" (
	IF "%1"=="-fbhelp" (
		echo.
		echo FindBugs Batch Script Options
		echo NOTE: These commands are for reference only - they will not work on this script.
		echo.
		echo.
		findbugs-2.0.2\bin\findbugs.bat -help
	) ELSE (
		echo.
		echo USAGE of findbugrun batch script
		echo -------------------------------------------
		echo.
		echo findbugrun.bat [-fbhelp]
		echo.
		echo -------------------------------------------
		echo.
		echo -fbhelp
		echo      get the options for the FindBugs script
	)
) ELSE (
	echo Running Findbugs...
	%CD%\findbugs-2.0.2\bin\findbugs.bat -textui -xml -auxclasspath %classpath% -output fb_results.xml %CD%\Target_Projects\Crawler4j\crawler4j-3.5.jar
	echo Done.
	echo Calculating Defect Densities...
	%CD%\findbugs-2.0.2\bin\findbugs.bat -defectDensity fb_results.xml > defectdensity.txt
	echo Done.
	echo Running Parser...
	python Parser\parser.py -d defectdensity.txt -b fb_results.xml
	echo Done.
	echo Running Analyzer...
	python Analyzer\analyzer.py -r parse_results.txt -d parse_densities.txt
	echo Done.
)
