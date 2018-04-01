#!/bin/bash

#Global variables
interface="ens33"
duration=60
systemType="single"
singleModelPath="Single_1RF_.model"
hybridModelPath1="Hybrid_isAttack_RF_.model"
hybridModelPath2="Hybrid_DDoS_Type_RF_.model"

#Functions
displayArguments(){
	echo ""
	echo "interface is ${interface}"
	echo "duration is ${duration}"
	echo "systemType is ${systemType}"
	echo "singleModelPath is ${singleModelPath}"
	echo "hybridModelPath1 is ${hybridModelPath1}"
	echo "hybridModelPath2 is ${hybridModelPath2}"
}

helpMenu(){
	echo "Usage ./live.sh [options]"
	echo ""
	echo "Options (case sensitive and unable to handle spaces):"
	echo "-h --help display this help message"
	echo "-i --interface <interface name> change the interface used to capture packets (default: 'Wi-Fi')"
	echo "-d --duration <duration value> change capture duration (default: 60)"
	echo "--single <single system model path> Use a single system in classification from within the model/ folder(default: 'RF .model')"
	echo "--hybrid <attack or not model path> <ddos type model path> Use a hybrid system in classification from within the model/ folder"
	exit 0
}

processArguments(){
	while [ ! $# -eq 0 ]; do

		validArg=0
		case "$1" in
			--help | -h)
				validArg=1
				helpMenu
				exit
				;;

			--interface | -i)
				validArg=1
				interface="${2}"
				shift 2
				;;

			--duration | -d)
				validArg=1
				duration="${2}"
				shift 2
				;;

			--single)
				validArg=1
				systemType="single"
				singleModelPath="${2}"
				shift 2
				;;

			--hybrid)
				validArg=1
				systemType="hybrid"
				echo 2 is ${2} 3 is ${3}
				hybridModelPath1="${2}"
				hybridModelPath2="${3}"
				shift 3
				;;
		esac

		if [ $validArg -eq 0 ]; then
			echo "Invalid flag: ${1}"
			displayArguments
			helpMenu
			exit 1
		fi
	done
}

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

checkAllProgramsAndPaths(){
	echo "Checking if all requirements are present"

	checkProgram python
	checkProgram tshark
	checkProgram java
	checkProgram touch

	checkPath "Scripts/main.py"
	checkPath "model/LiveTest.jar"
}

#main

# ${@} means pass all arguments
processArguments ${@}
displayArguments

echo ""
checkAllProgramsAndPaths


# Prompt for password, so that we don't get prompted again
	sudo echo -n

# Source: https://askubuntu.com/questions/634173/how-to-get-date-and-time-using-command-line-interface
	date_time=`date '+%Y_%m_%d_%H_%M_%S'`

# Make a variable containing "live-capture" input and output
# It won't create the file again if it already exists
	live_capture_output_dir=live_capture_output
	live_capture_input_dir=live_capture_input
	mkdir ${live_capture_input_dir} -v
	mkdir ${live_capture_output_dir} -v
	cd ${live_capture_input_dir}

# Create an empty file called %date_time%.pcapng
	date_time_pcapng=${date_time}.pcapng
	touch ${date_time_pcapng}

# Add permissions to the newly created file
	chmod o=rw ${date_time_pcapng}

# Start capturing on Wi-fi and output the result to the filename %date_time_pcapng%
	echo ""
	echo "Starting tshark packet capture"
	sudo tshark -i ${interface} -a duration:${duration} -w ${date_time_pcapng}

# Activate the virtual environment
	cd ..
	echo ""
	echo "Starting python virtual environment"
	source ubuntu_venv/bin/activate

# Go to the area containing scripts
	cd Scripts

# Start the program and give it the ../live_capture_input_dir
# We need the ../ since we're currently in Scripts
	echo ""
	echo "Extracting features from the packet capture"
	python main.py ../${live_capture_input_dir} ../${live_capture_input_dir}

# CD to the home directory
	cd ..

# Deactivate the virtual environment
	echo ""
	echo "Deactivating python virtual environment"
	deactivate

# Start classifying based on the flow
	cd model
	echo ""
	echo Classifying the extracted features using ${systemType}

	date_time_log="../${live_capture_input_dir}/${date_time}.log"
	echo Writing output to ${date_time_log}

# We use = for string comparison
# Source https://stackoverflow.com/questions/10849297/compare-a-string-in-unix
	if [ "${systemType}" = "single" ]; then
		echo "Model: ${singleModelPath}"
		java -jar LiveTest.jar ${systemType} "../${live_capture_input_dir}/${date_time}.arff" "${singleModelPath}" > "${date_time_log}"

	elif [ "${systemType}" = "hybrid" ]; then
		echo "Attack or not model: ${hybridModelPath1}, DDoS type model: ${hybridModelPath2}"
		java -jar LiveTest.jar ${systemType} "../${live_capture_input_dir}/${date_time}.arff" "${hybridModelPath1}" "${hybridModelPath2}" > "${date_time_log}"
	fi

# Go back to the home directory
	cd ..

# Move everything in live capture input to a folder called ${date_time}
	echo ""
	echo Creating ${date_time} folder and moving capture data there
	mkdir ${date_time} -v
	mv ${live_capture_input_dir}/* ${date_time}/

# Move the ${date_time} folder inside ${live_capture_output_dir}
	echo ""
	echo Moving ${date_time} to ${live_capture_output_dir}
	mv ${date_time} ${live_capture_output_dir}/

