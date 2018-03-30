#!/bin/bash

#Functions
terminate(){
	echo "Terminating process"
	exit 1
}

checkProgram(){
	if command -v $1; then
		echo "Found program: '${1}'"
	else
		echo "Did not find '${1}'"
		terminate
	fi
	echo "" #Just adds a new line
}

checkPath(){
	if [ -e "${1}" ]; then
		echo "Found file: '${1}'"
	else
		echo "Did not find file: '${1}'"
		terminate
	fi
}

#main
checkProgram python
checkProgram tshark
checkProgram java

checkPath "Scripts/main.py"
checkPath "model/SingleModelTest.jar"
checkPath "model/RF .model"

# Prompt for password, so that we don't get prompted again
	sudo echo -n

# Source: https://askubuntu.com/questions/634173/how-to-get-date-and-time-using-command-line-interface
	date_time=`date '+%Y_%m_%d_%H_%M_%S'`

# Make a variable containing "live-capture" input and output
# It won't create the file again if it already exists
	live_capture_output_dir=live_capture_output
	live_capture_input_dir=live_capture_input
	mkdir ${live_capture_input_dir}
	cd ${live_capture_input_dir}

# Create an empty file called %date_time%.pcapng
	date_time_pcapng=${date_time}.pcapng
	touch ${date_time_pcapng}

# Add permissions to the newly created file
	chmod o=rw ${date_time_pcapng}

# Start capturing on Wi-fi and output the result to the filename %date_time_pcapng%
	echo "Starting tshark packet capture"
	sudo tshark -i ens33 -a duration:65 -w ${date_time_pcapng}

# Activate the virtual environment
	cd ..
	echo "Starting python virtual environment"
	source ubuntu_venv/bin/activate

# Go to the area containing scripts
	cd Scripts

# Start the program and give it the ../live_capture_input_dir
# We need the ../ since we're currently in Scripts
	echo "Extracting features from the packet capture"
	python main.py ../${live_capture_input_dir} ../${live_capture_input_dir}

# CD to the home directory
	cd ..

# Deactivate the virtual environment
	echo "Deactivating python virtual environment"
	deactivate

# Start classifying based on the flow
	cd model
	echo Classifying the extracted features
	java -jar SingleModelTest.jar "../${live_capture_input_dir}/${date_time}.arff" "RF .model"

# Go back to the home directory
	cd ..

# Move everything in live capture input to a folder called ${date_time}
	mkdir ${date_time}
	mv ${live_capture_input_dir}/* ${date_time}/

# Move the ${date_time} folder inside ${live_capture_output_dir}
	mv ${date_time} ${live_capture_output_dir}/

