@echo off
rem Activate the virtual environment
call venv\Scripts\activate.bat

rem We need to execute main.py from the Scripts folder
rem since parts in main.py execute using relative paths from "Scripts"
cd Scripts

rem rem Put the output of main.py to ..\output.txt
rem python main.py > ..\output.txt

rem rem Go back to the original directory from where we first executed this script
rem cd ..

rem rem Deactivate the virtual environment
rem call venv\Scripts\deactivate.bat

rem rem Put "Press any key to continue..." so that this terminal isn't immediately closed
rem rem This allows you to see any errors
rem pause