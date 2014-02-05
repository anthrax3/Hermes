@echo off

rem start "Hermes Initialize" /wait win_findbugrun.bat

call win_findbugrun.bat

echo Resetting any foreign server values...
python hermes.py -r
echo Done.
echo Starting Hermes fuzz server...
start "Fuzz Server" python hermes.py -f > hermes_f_dump.txt 2>&1
echo Done.
echo Starting Hermes coverage listener...
start "Coverage Listener" python hermes.py -c > hermes_c_dump.txt 2>&1
echo Done.
echo Process Started.
echo NOTE: These processes may have started as background processes. Refer to task manager.




