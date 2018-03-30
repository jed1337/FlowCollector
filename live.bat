@echo off
call :CHECK_ALL_PROGRAMS_AND_PATHS
rem "rem" means to treat the following line as a comment

rem Assign the result of %date% and %time% functions to variable date_time
	set date_time=%date% %time%

rem Changes the " ", "/", ":" in the date_time variable to underscores
	set date_time=%date_time: =_%
	set date_time=%date_time:/=_%
	set date_time=%date_time::=_%

rem Make a variable containing "live-capture" input and output
rem It won't create the file again if it already exists
	set live_capture_output_dir=live_capture_output
	set live_capture_input_dir=live_capture_input
	mkdir %live_capture_input_dir%
	cd %live_capture_input_dir%

rem Create an empty file called %date_time%.pcapng
	set date_time_pcapng=%date_time%.pcapng
	fsutil file createnew %date_time_pcapng% 0

rem Start capturing on Wi-fi and output the result to the filename %date_time_pcapng%
	echo Starting tshark packet capture
	tshark -i Wi-Fi -a duration:60 -w %date_time_pcapng%

rem Activate the virtual environment
	echo Starting python virtual environment
	cd ..
	call venv\Scripts\activate.bat

rem Go to the area containing scripts
	cd Scripts

rem Start the program and give it the ../live_capture_input_dir
rem We need the ../ since we're currently in Scripts
	echo Extracting features from the packet capture
	python main.py ../%live_capture_input_dir% ../%live_capture_input_dir%
	rem python main.py ../%live_capture_input_dir% ../%live_capture_output_dir%

rem CD to the home directory
	cd ..

rem Deactivate the virtual environment
	echo Deactivating python virtual environment
	call venv\Scripts\deactivate.bat

rem Start classifying based on the flow
	cd model
	echo Classifying the extracted features
	java -jar SingleModelTest.jar "../%live_capture_input_dir%/%date_time%.arff" "RF .model"
	rem java -jar SingleModelTest.jar "../%live_capture_output_dir%/%date_time%.arff" "RF .model"

rem Go back to the home directory
	cd ..

rem Move everything in live capture input to a folder called %date_time%
	mkdir %date_time%
	move %live_capture_input_dir%\* %date_time%\

rem Move the %date_time% folder inside %live_capture_output_dir%
	move %date_time% %live_capture_output_dir%\

rem So we don't accidentally execute the functions area
	goto:EOF

rem Functions
	:CHECK_ALL_PROGRAMS_AND_PATHS
		echo Checking if all requirements are present
		call :CHECK_PATH "Scripts\main.py"
		call :CHECK_PATH "model\SingleModelTest.jar"
		call :CHECK_PATH "model\RF .model"
		call :CHECK_PROGRAM python
		call :CHECK_PROGRAM tshark
		call :CHECK_PROGRAM java
		call :CHECK_PROGRAM fsutil
		call :CHECK_FAIL
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
