@echo off

rem Assign the result of %date% and %time% functions to variable date_time
set date_time=%date% %time%

rem Changes the " ", "/", ":" in the date_time variable to underscores
set date_time=%date_time: =_%
set date_time=%date_time:/=_%
set date_time=%date_time::=_%

rem Make a directory called live-capture
mkdir live_capture
cd live_capture

rem Create an empty file called %date_time%.pcapng
set date_time_pcapng=%date_time%.pcapng
fsutil file createnew %date_time_pcapng% 0
tshark -i Wi-Fi -a duration:3 -w %date_time_pcapng%

rem echo dtp is %date_time_pcapng%

rem rem call venv\Scripts\activate.bat

rem rem mkdir live_capture
rem rem cd live_capture

