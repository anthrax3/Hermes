echo "Starting a full evaluation run of Hermes..."
echo "NOTE: The uni_evaluation.sh script will run until the user kills its process."
./uni_server.sh &
./uni_evaluation.sh > hermes_eval_dump.txt &
echo "Server, Coverage Listener, and Evaluation scripts are now executing."
