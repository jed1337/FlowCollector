@echo off
rem Source:		https://stackoverflow.com/questions/15143259/adding-flags-to-a-batch-script
rem Source2:	https://stackoverflow.com/questions/3973824/windows-bat-file-optional-argument-parsing

SET interface="Wi-Fi"
SET duration=60
SET systemType="single"
SET singleModelPath="Single RF .model"
SET hybridModelPath1="Hybrid isAttack RF .model"
SET hybridModelPath2="Hybrid DDoS Type RF .model"

:loop
set arg=%1
if defined arg (
	if "%1"=="-h" (
		call :help
	)
	if "%1"=="-i" (
		SET interface=%2

		rem SHIFT moves the arguments back
		rem SHIFT & SHIFT moves the arguments back twice
		rem We move it twice since this takes 2 parameters: "-i" and "<value>"
			SHIFT & SHIFT
	)
	if "%1"=="-d" (
		SET duration=%2
		SHIFT & SHIFT
	)
	if "%1"=="--single" (
		SET systemType="single"
		SET singleModelPath=%2
		SHIFT & SHIFT
	)
	if "%1"=="--hybrid" (
		SET systemType="hybrid"
		SET hybridModelPath1=%2
		SET hybridModelPath2=%3

		rem We move it trice since this takes 3 parameters
			SHIFT & SHIFT & SHIFT
	)
 GOTO :loop
)
call :OUTPUT_VARIABLES

call :CHECK_ALL_PROGRAMS_AND_PATHS
rem "rem" means to treat the following line as a comment

rem Assign the result of %date% and %time% functions to variable date_time
	SET date_time=%date% %time%

rem Changes the " ", "/", ":" in the date_time variable to underscores
	SET date_time=%date_time: =_%
	SET date_time=%date_time:/=_%
	SET date_time=%date_time::=_%

rem Make a variable containing "live-capture" input and output
rem It won't create the file again if it already exists
	SET live_capture_output_dir=live_capture_output
	SET live_capture_input_dir=live_capture_input
	mkdir %live_capture_input_dir%
	mkdir %live_capture_output_dir%
	cd %live_capture_input_dir%

rem Create an empty file called %date_time%.pcapng
	SET date_time_pcapng=%date_time%.pcapng
	fsutil file createnew %date_time_pcapng% 0

rem Start capturing on %interface% and output the result to the filename %date_time_pcapng%
	call :NEW_LINE
	echo Starting tshark packet capture for %duration% seconds
	tshark -i %interface% -a duration:%duration% -w %date_time_pcapng%

rem Activate the virtual environment
	call :NEW_LINE
	echo Starting python virtual environment
	cd ..
	call venv\Scripts\activate.bat

rem Go to the area containing scripts
	cd Scripts

rem Start the program and give it the ..\live_capture_input_dir
rem We need the ..\ since we're currently in Scripts
	call :NEW_LINE
	echo Extracting features from the packet capture
	python main.py ..\%live_capture_input_dir% ..\%live_capture_input_dir%
	rem python main.py ..\%live_capture_input_dir% ..\%live_capture_output_dir%

rem CD to the home directory
	cd ..

rem Deactivate the virtual environment
	call :NEW_LINE
	echo Deactivating python virtual environment
	call venv\Scripts\deactivate.bat

rem Start classifying based on the flow
	cd model
	call :NEW_LINE
	echo Classifying the extracted features using %systemType%

	set date_time_log="..\%live_capture_input_dir%\%date_time%.log"
	echo Writing output to %date_time_log%

	if %systemType% == "single" (
		echo "Model: %singleModelPath%"
			java -jar LiveTest.jar %systemType% "..\%live_capture_input_dir%/%date_time%.arff" %singleModelPath% > %date_time_log%
	) else if %systemType% == "hybrid" (
		echo "Attack or not model: %hybridModelPath1%, DDoS type model: %hybridModelPath2%"
			java -jar LiveTest.jar %systemType% "..\%live_capture_input_dir%/%date_time%.arff" %hybridModelPath1% %hybridModelPath2% > %date_time_log%
	)

rem Go back to the home directory
	cd ..

rem Move everything in live capture input to a folder called %date_time%
	call :NEW_LINE
	echo Moving live capture data to %date_time%
	mkdir %date_time%
	move %live_capture_input_dir%\* %date_time%\

rem Move the %date_time% folder inside %live_capture_output_dir%
	call :NEW_LINE
	echo Moving %date_time% to %live_capture_output_dir%
	move %date_time% %live_capture_output_dir%\

rem So we don't accidentally execute the functions area
	goto:EOF

rem Functions
	:NEW_LINE
		rem Print blank line
			echo(
			goto:EOF

	:HELP
		echo "Usage live.bat [options]"
		call :NEW_LINE
		echo "Options (case sensitive):"
		echo "-h display this help message"
		echo "-i <interface name> change the interface used to capture packets (default: 'Wi-Fi')"
		echo "-d <duration value> change capture duration (default: 60)"
		echo "--single <single system model path> Use a single system in classification from within the model\ folder(default: 'RF .model')"
		echo "--hybrid <attack or not model path> <ddos type model path> Use a hybrid system in classification from within the model\ folder"
		pause
		exit 0

	:OUTPUT_VARIABLES
		echo interface is %interface%
		echo duration is %duration%
		echo systemType is %systemType%
		echo singleModelPath is %singleModelPath%
		echo hybridModelPath1 is %hybridModelPath1%
		echo hybridModelPath2 is %hybridModelPath2%
		call :NEW_LINE
		goto:EOF

	:CHECK_ALL_PROGRAMS_AND_PATHS
		echo Checking if all requirements are present
		call :CHECK_PATH "Scripts\main.py"
		call :CHECK_PATH "model\LiveTest.jar"
		call :CHECK_PATH "model\RF .model"
		call :CHECK_PROGRAM python
		call :CHECK_PROGRAM tshark
		call :CHECK_PROGRAM java
		call :CHECK_PROGRAM fsutil
		call :CHECK_FAIL
		call :NEW_LINE
		goto:EOF

	:CHECK_PATH
		rem If the current file doesn't exist, exit code 1
		rem Else goto:eof

		if not exist %1 (
			exit /b 3
		)
		goto:EOF

	:CHECK_PROGRAM
		rem Source: https://superuser.com/questions/175466/determine-if-command-is-recognized-in-a-batch-file

		WHERE %1 >nul 2>&1 && (
			echo Found %1
		) || (
			echo The program %1 cannot be found
			exit /b 3
		)
		goto:EOF

	:CHECK_FAIL
		rem %ERRORLEVEL% will be equal to zero if there are no errors
		if NOT ["%ERRORLEVEL%"]==["0"] (
			echo Some or all operations did not execute successfully.
			echo Error level is %ERRORLEVEL%
			echo Terminating execution
		   pause
		   exit
		)
