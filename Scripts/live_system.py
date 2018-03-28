import os
import subprocess
# os.listdir()


# os.system("tshark -i Wi-Fi -a duration:3 -w"+file_name)

# Make "wifi changeable to any interface"
file_name="owo.pcapng"
# subprocess.call(['tshark', '-i', 'Wi-Fi', '-a', 'duration:3', '-w', file_name])

# subprocess.call(['cmd', '/c',"call", "C:/Users/dell/Documents/Pycharm/FlowCollector/venv/Scripts/activate.bat"])
subprocess.Popen(["../venv/Scripts/activate.bat", 'main.py'])

# subprocess.call(["call", "C:/Users/dell/Documents/Pycharm/FlowCollector/venv/Scripts/activate.bat"])

# subprocess.call(['cmd', '/c', "dir"], cwd="Scripts")

# subprocess.call(['python', 'main.py', "../"+file_name], cwd="Scripts")