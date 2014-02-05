sudo ./uni_findbugrun.sh
echo "Resetting any foreign servver values..."
python hermes.py -r
echo "Done"
echo "Starting Hermes Fuzz Server..."
sudo python hermes.py -f > hermes_f_dump.txt 2>&1 &
echo "Done"
echo "Starting Hermes Coverage Listener..."
sudo python hermes.py -c > hermes_c_dump.txt 2>&1 &
echo "Done"
echo "Processes Started."
echo "NOTE: These processes are background processes! You can find them with the \"ps aux\" command."
