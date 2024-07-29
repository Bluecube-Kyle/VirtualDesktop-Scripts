#Force Admin elevation prompt if not ran as administrator
If(-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	$arguments = "& '" + $myInvocation.MyCommand.Definition + "'"
	Start-Process Powershell -Verb runAs -ArgumentList $arguments
	exit
}

#Create directory for scripts
$Paths = @(
	"C:\VDI Tools\Sealing\"
	"C:\VDI Tools\Patching\"
	"C:\VDI Tools\Maintenance\"
	"C:\VDI Tools\Scripts\"
)
Foreach($Path in $Paths) {If(!(Test-Path -PathType container $Path)) {New-Item -ItemType Directory -Path $Path}}

#Download Archive from Github and extract it
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri "https://github.com/Bluecube-Kyle/VirtualDesktop-Scripts/archive/refs/heads/main.zip" -OutFile "C:\VDI Tools\Scripts.zip"
Expand-Archive "C:\VDI Tools\Scripts.zip" -DestinationPath "C:\VDI Tools\" -Force
Get-ChildItem -Path "C:\VDI Tools\VirtualDesktop-Scripts-main\" | Copy-Item -Destination "C:\VDI Tools\" -Force -Recurse
Remove-Item "C:\VDI Tools\Scripts.zip" -Force
Remove-Item "C:\VDI Tools\VirtualDesktop-Scripts-main\" -Recurse -Force

#Run Signing script
Powershell -F "C:\VDI Tools\Scripts\Local Sign Script.ps1"

#Acquire current users desktop path
$Desktop = [Environment]::GetFolderPath("Desktop")

#Create desktop shortcuts for all of the scripts
$Scripts = @(
"C:\VDI Tools\Sealing\Windows Sealing Script.ps1"
"C:\VDI Tools\Patching\Windows Patching Script.ps1"
"C:\VDI Tools\Maintenance\Windows Maintenance Script.ps1"
"C:\VDI Tools\Scripts\Script Updater.ps1"
"C:\VDI Tools\Scripts\Local Sign Script.ps1"
)
$Scripts = Get-ChildItem $Scripts -Recurse -Filter *.ps1*

Foreach($Script in $Scripts) {
	$Name = $script.Name
	$shell = New-Object -comObject WScript.Shell
	$shortcut = $shell.CreateShortcut("$Desktop\$Name.lnk")
	$shortcut.TargetPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
	$shortcut.Arguments = "-F `"$Script`""
	$shortcut.Save()
}