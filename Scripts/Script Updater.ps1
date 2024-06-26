$ScriptPath = "C:\Bluecube\Scripts\"
	If(!(Test-Path -PathType container $ScriptPath)) {New-Item -ItemType Directory -Path $ScriptPath}

$Seal = "Windows Sealing Script"
$Patching = "Windows Patching Script"
$Maintenance = "Windows Maintenance Script"
$LocalCertSign = "Local Sign Script"

Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Bluecube-Kyle/VirtualDesktop-Scripts/main/Sealing/Windows%20Sealing%20Script.ps1" -OutFile $ScriptPath$Seal.ps1
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Bluecube-Kyle/VirtualDesktop-Scripts/main/Patching/Windows%20Patching%20Script.ps1" -OutFile $ScriptPath$Patching.ps1
#Invoke-WebRequest -Uri "" -OutFile $ScriptPath$Maintenance.ps1

Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Bluecube-Kyle/VirtualDesktop-Scripts/main/Scripts/Local%20Sign%20Script.ps1" -OutFile $ScriptPath$LocalCertSign.ps1

$Desktop = [Environment]::GetFolderPath("Desktop")

$Scripts = "Windows Sealing Script,Windows Patching Script,Windows Maintenance Script,Local Sign Script"
$ScriptFile = $Scripts -Split ","
Foreach($Script in $ScriptFile) { 

$shell = New-Object -comObject WScript.Shell
$shortcut = $shell.CreateShortcut("$Desktop\$Script.lnk")
$shortcut.TargetPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$shortcut.Arguments = "-F $ScriptPath$Script.ps1"
$shortcut.Save()

}