run as admin

if powershell exec is blocked, run this in terminal:

powershell -ExecutionPolicy Bypass -File "path\to\analyzer.ps1"

if you want interval in seconds control set it after the process to search.

example usage: 

.\analyzer.ps1 brave 2
