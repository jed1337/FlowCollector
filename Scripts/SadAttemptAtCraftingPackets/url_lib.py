import urllib.request

response = urllib.request.urlopen('http://152.14.13.11')
html = response.read()