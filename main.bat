@echo off
rem Activate the virtual environment
call venv\Scripts\activate.bat

rem We need to execute main.py from the Scripts folder
rem since parts in main.py execute using relative paths from "Scripts"
cd Scripts

rem Put the output of main.py to ..\output.txt
python main.py > ..\output.txt

rem Go back to the original directory from where we first executed this script
cd ..

rem Deactivate the virtual environment
call venv\Scripts\deactivate.bat

rem Put "Press any key to continue..." so that this terminal isn't immediately closed
rem This allows you to see any errors
pause