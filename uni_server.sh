echo "Starting Hermes Server and Coverage Listener..."
sudo python hermes.py -f > hermes_f_dump.txt &
sudo python hermes.py -c > hermes_c_dump.txt &
echo "Processes Started."
echo "NOTE: These processes are background processes! You can find them with the \"ps T\" command."
