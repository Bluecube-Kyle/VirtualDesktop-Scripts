#Force Admin elevation prompt if not ran as administrator
If(-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	$arguments = "& '" + $myInvocation.MyCommand.Definition + "'"
	Start-Process Powershell -Verb runAs -ArgumentList $arguments
	exit
}

#Create directory for scripts
$ScriptPath = "C:\VDI Tools\Scripts\"
	If(!(Test-Path -PathType container $ScriptPath)) {New-Item -ItemType Directory -Path $ScriptPath}

#Script names converted to variables
$Seal = "Windows Sealing Script"
$Patching = "Windows Patching Script"
$Maintenance = "Windows Maintenance Script"
$LocalCertSign = "Local Sign Script"
$Updater = "Update Scripts"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#Download Scripts from Github repo
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Bluecube-Kyle/VirtualDesktop-Scripts/main/Sealing/Windows%20Sealing%20Script.ps1" -OutFile $ScriptPath$Seal.ps1
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Bluecube-Kyle/VirtualDesktop-Scripts/main/Patching/Windows%20Patching%20Script.ps1" -OutFile $ScriptPath$Patching.ps1
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Bluecube-Kyle/VirtualDesktop-Scripts/main/Maintenance/Windows%20Maintenance%20Script.ps1" -OutFile $ScriptPath$Maintenance.ps1

Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Bluecube-Kyle/VirtualDesktop-Scripts/main/Scripts/Local%20Sign%20Script.ps1" -OutFile $ScriptPath$LocalCertSign.ps1
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Bluecube-Kyle/VirtualDesktop-Scripts/main/Scripts/Script%20Updater.ps1" -OutFile $ScriptPath$Updater.ps1

#Acquire current users desktop path
$Desktop = [Environment]::GetFolderPath("Desktop")

#Create desktop shortcuts for all of the scripts
$Scripts = "Windows Sealing Script,Windows Patching Script,Windows Maintenance Script,Local Sign Script,Update Scripts"
$ScriptFile = $Scripts -Split ","
Foreach($Script in $ScriptFile) { 
	$shell = New-Object -comObject WScript.Shell
	$shortcut = $shell.CreateShortcut("$Desktop\$Script.lnk")
	$shortcut.TargetPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
	$shortcut.Arguments = "-F `"$ScriptPath$Script.ps1`""
	$shortcut.Save()
}

#Sign all of the scripts
Powershell -F "$ScriptPath$LocalCertSign.ps1"