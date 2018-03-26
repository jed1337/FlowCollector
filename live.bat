@echo off

rem Assign the result of %date% and %time% functions to variable date_time
	set date_time=%date% %time%

rem Changes the " ", "/", ":" in the date_time variable to underscores
	set date_time=%date_time: =_%
	set date_time=%date_time:/=_%
	set date_time=%date_time::=_%

rem Make a variable containing "live-capture"
	set live_capture_dir=live_capture
	mkdir %live_capture_dir%
	cd %live_capture_dir%

rem Create an empty file called %date_time%.pcapng
	set date_time_pcapng=%date_time%.pcapng
	fsutil file createnew %date_time_pcapng% 0

rem Start capturing on Wi-fi and output the result to the filename %date_time_pcapng%
	tshark -i Wi-Fi -a duration:3 -w %date_time_pcapng%

rem Activate the virtual environment
	cd ..
	call venv\Scripts\activate.bat

rem Go to the area containing scripts
	cd Scripts

rem Start the program and give it the live_capture_dir
	python main.py %live_capture_dir%