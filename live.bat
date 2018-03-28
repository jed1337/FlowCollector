@echo off
call :CHECK_ALL_PROGRAMS_AND_PATHS
rem rem rem means to treat the following line as a comment

rem rem Assign the result of %date% and %time% functions to variable date_time
rem 	set date_time=%date% %time%

rem rem Changes the " ", "/", ":" in the date_time variable to underscores
rem 	set date_time=%date_time: =_%
rem 	set date_time=%date_time:/=_%
rem 	set date_time=%date_time::=_%

rem rem Make a variable containing "live-capture" input and output
rem rem It won't create the file again if it already exists
rem 	set live_capture_output_dir=live_capture_output
rem 	set live_capture_input_dir=live_capture_input
rem 	mkdir %live_capture_input_dir%
rem 	cd %live_capture_input_dir%

rem rem Create an empty file called %date_time%.pcapng
rem 	set date_time_pcapng=%date_time%.pcapng
rem 	fsutil file createnew %date_time_pcapng% 0

rem rem Start capturing on Wi-fi and output the result to the filename %date_time_pcapng%
rem 	tshark -i Wi-Fi -a duration:6 -w %date_time_pcapng%

rem rem Activate the virtual environment
rem 	cd ..
rem 	call venv\Scripts\activate.bat

rem rem Go to the area containing scripts
rem 	cd Scripts

rem rem Start the program and give it the ../live_capture_input_dir
rem rem We need the ../ since we're currently in Scripts
rem 	python main.py ../%live_capture_input_dir% ../%live_capture_output_dir%

rem So we don't accidentally execute the functions area

goto:EOF

rem Functions
	:CHECK_ALL_PROGRAMS_AND_PATHS
		call :CHECK_PATH "Scripts\main.py"
		call :CHECK_PROGRAM python
		call :CHECK_PROGRAM tshark
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
		if NOT ["%ERRORLEVEL%"]==["0"] (
			echo Some or all operations did not execute successfully.
			echo Error level is %ERRORLEVEL%
			echo Terminating execution
		   pause
		   exit
		)
