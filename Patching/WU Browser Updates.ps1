<#
------------WU Browser Updates Script V2.0---------------
----------------Created by Kyle Baxter----------------

.Synopsis
Patching Script for windows Browser Updates

.Description
This script is for the installation of windows Browser Updates to a machine autonomously 
#>

#Detect if run as admin and if not request elevation
If(-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	$arguments = "& '" + $myInvocation.MyCommand.Definition + "'"
	Start-Process Powershell -Verb runAs -ArgumentList $arguments
	exit
}

#Create Required Directories
$Date = Get-Date -F yyyy-MM-dd
$Time = Get-Date -F HH-mm
$LogPath = "C:\VDI Tools\PatchingLogs\$Date\"
$ConfigPath = "C:\VDI Tools\Configs\"
$Log = "$ENV:ComputerName - $Time"
$Installs = "C:\VDI Tools\Installers"
	If(!(Test-Path -PathType container $LogPath)) {New-Item -ItemType Directory -Path $LogPath} 
	If(!(Test-Path -PathType container $Installs)) {New-Item -ItemType Directory -Path $Installs} 
	If(!(Test-Path -PathType Container $ConfigPath)) {New-Item -ItemType Directory -Path $ConfigPath}

#Create Variables File
$ConfigFile = "C:\VDI Tools\Configs\PatchingConf.txt"
$Config = Test-Path -Path $ConfigFile
	If($Config -eq $false){New-Item -Path $ConfigFile
Add-Content -Path $ConfigFile -Value "#---------------Patching Config V1.0---------------#
#Created by Kyle Baxter

#Configurable Variable for script execution
#Toggle settings have a value of 0 or 1 to disable or enable the option"
}

#Acquire all Variable stored in file
Get-Content -Path $ConfigFile | Where-Object {$_.length -gt 0} | Where-Object {!$_.StartsWith("#")} | ForEach-Object {
    $var = $_.Split('=',2).Trim()
    Set-Variable -Scope Script -Name $var[0] -Value $var[1]
}

#Look if required variables are stored
Clear
If($Script:ExcludedUpdates -eq $null) {
	Write-Output "Exclude these KB's from updates"
	Add-Content -Path $ConfigFile -Value "ExcludedUpdates ="
	Clear}
If($Script:IncludeOfficeUpdates -eq $null) {
	Add-Content -Path $ConfigFile -Value "IncludeOfficeUpdates = 1"
	Clear}		

#Acquire all Variable stored in file
Get-Content -Path $ConfigFile | Where-Object {$_.length -gt 0} | Where-Object {!$_.StartsWith("#")} | ForEach-Object {
    $var = $_.Split('=',2).Trim()
    Set-Variable -Scope Script -Name $var[0] -Value $var[1]
}

#Global Variables.
$CurrentTask = 0
$PercentComplete = 0
$TotalTasks = 0

#Start of Browser Tasks
#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Start-Transcript -Append  -Path "$LogPath$Log - BrowserUpdates.log" 
Write-Output "====================---------- Start of Browser Patching ----------===================="
Write-Output ""

#--------------------Edge--------------------#
Write-Progress -Activity "Browser Updates" -Status "Updating Browsers" -Id 1 -PercentComplete 0
#Checking if Edge exists and clearing directory. (Running latest installer doesn't overwrite the existing exe's to latest version)
$EdgeExists = Test-Path -Path "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
$Chrome = Test-Path -Path "C:\Program Files\Google\Chrome\Application\Chrome.exe"
$Chrome64 = Test-Path -Path "C:\Program Files (x86)\Google\Chrome\Application\Chrome.exe"
$FireFox = Test-Path -Path "C:\Program Files\Mozilla Firefox"
	If($EdgeExists -eq $true) {$TotalTasks += 3}
	If(($Chrome -eq $true) -or ($Chrome64 -eq $true)) {$TotalTasks += 3}
	If($FireFox -eq $true) {$TotalTasks += 3}

	If($EdgeExists -eq $true) {
		$Processes = Get-Process
		If($Processes -match "msedge") {Stop-Process -Name MsEdge -Verbose -Force}
		Start-Sleep 3
		Remove-Item -Path 'C:\Program Files (x86)\Microsoft\Edge\Application\*.exe' -Force -Recurse

		#Download Online Installer for latest release and run it
		Write-Progress -Activity "Browser Updates" -Status "Downloading Latest Edge Version" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
		Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2108834&Channel=Stable&language=en&brand=M100" -OutFile "$Installs\Edge.exe"
		Write-Progress -Activity "Browser Updates" -Status "Installing Latest Edge Version" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
		Start-Process "$Installs\Edge.exe" -Wait
		Remove-Item -Path "$Installs\Edge.exe"
		Write-Output "Edge Updated"

		#Disable Automatic Updater services and tasks
		Write-Progress -Activity "Browser Updates" -Status "Disabling Edge Services and Tasks" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
		Start-Sleep 3
		Stop-Process -Name MsEdge -Verbose
		$Services = Get-Service
		$ScheduledTask = Get-ScheduledTask
			if($Services -match "edgeupdate") {Set-Service edgeupdate -StartupType Disabled -Passthru}
			if($Services -match "edgeupdatem") {Set-Service edgeupdatem -StartupType Disabled -Passthru}
			if($Services -match "MicrosoftEdgeElevationService") {Set-Service MicrosoftEdgeElevationService -StartupType Disabled -Passthru}
			if($ScheduledTask -match "MicrosoftEdgeUpdateBrowserReplacement") {Disable-ScheduledTask -TaskName "MicrosoftEdgeUpdateBrowserReplacementTask"}
			if($ScheduledTask -match "MicrosoftEdgeUpdateTaskMachineCore") {Disable-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskMachineCore"}
			if($ScheduledTask -match "MicrosoftEdgeUpdateTaskMachineUA") {Disable-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskMachineUA"}
	} 
	else {Write-Output "Edge not present, skipping"}

#--------------------Chrome--------------------#
	If(($Chrome -eq $true) -or ($Chrome64 -eq $true))  {
	Write-Progress -Activity "Browser Updates" -Status "Downloading Latest Chrome Version" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
	$ChromeUpdate = 'HKLM:\SOFTWARE\Policies\Google\Update'
		If(!(Test-Path $ChromeUpdate)) {New-Item -Path $ChromeUpdate -Force}	
	Set-ItemProperty -Path $ChromeUpdate -Name "UpdateDefault" -Value 1 -Type Dword -Force -PassThru
	Invoke-WebRequest "https://dl.google.com/chrome/install/latest/chrome_installer.exe" -OutFile "$Installs\Chrome.exe"
	Write-Progress -Activity "Browser Updates" -Status "Installing Latest Chrome Version" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
	Start-Process -FilePath "$Installs\Chrome.exe" -Args "/silent /install" -Verb RunAs -Wait
	Remove-Item "$Installs\Chrome.exe"
	Write-Output "Chrome Updated"

	#Disable Automatic Updater services and tasks - Google adds an MSI code onto Scheduledtasks to try and prevent auto stopping the tasks. The following will acquire the task name and then wildcard for the MSIcode to disable it
	Write-Progress -Activity "Browser Updates" -Status "Disabling Chrome Services and Tasks" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
	Set-ItemProperty -Path $ChromeUpdate -Name "UpdateDefault" -Value 0 -Type Dword -Force -PassThru
	$Services = Get-Service
	$ScheduledTask = Get-ScheduledTask
		If($Services -match "gupdate") {Set-Service gupdate -StartupType Disabled -PassThru}
		If($Services -match "gupdatem") {Set-Service gupdatem -StartupType Disabled -PassThru}
		$GoogleUpdaterService = (Get-Service -DisplayName "GoogleUpdater Service*").Name
		$GoogleUpdaterIntService = (Get-Service -DisplayName "GoogleUpdater InternalService*").Name
		Get-Service -DisplayName "GoogleUpdaterService*" | Set-Service -StartupType Disabled		
		Get-Service -DisplayName "GoogleUpdaterInternalService*" | Set-Service -StartupType Disabled
		Write-Output "Startup of service $GoogleUpdaterService set to Disabled"
		Write-Output "Startup of service $GoogleUpdaterIntService set to Disabled"
		If($Services -match "GoogleChromeElevationService") {Set-Service GoogleChromeElevationService -StartupType Disabled}
		If($Tasks -match "GoogleUpdateTaskMachineUA*") {Get-ScheduledTask -TaskName "*GoogleUpdateTaskMachineUA*" | Disable-ScheduledTask}
		If($Tasks -match "GoogleUpdateTaskMachineCore*") {Get-ScheduledTask -TaskName "*GoogleUpdateTaskMachineCore*" | Disable-ScheduledTask}
		If($Tasks -match "GoogleUpdaterTaskSystem*") {Get-ScheduledTask -TaskName "*GoogleUpdaterTaskSystem*" | Disable-ScheduledTask}
	}
	else { Write-Output "Chrome Not installed. Skipping Update" }

#--------------------Firefox--------------------#
	If($FireFox -eq $true){
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\FireFox" -Name "DisableAppUpdate" -Value 0 -Type Dword -Force -PassThru
	#Downloads and runs the latest online installer
	Write-Progress -Activity "Browser Updates" -Status "Downloading Latest Firefox Version" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
	Invoke-WebRequest -Uri "https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US" -OutFile "$Installs\FireFox.exe"
	Write-Progress -Activity "Browser Updates" -Status "Installing Latest Firefox Version" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
	Start-Process "$Installs\FireFox.exe" -ArgumentList "-ms -ma" -Wait
	#Remove leftover installer
	Remove-Item -Path "$Installs\FireFox.exe"
	Write-Output "Firefox Updated"
	
	#Disable Automatic Updater services and tasks
	Write-Progress -Activity "Browser Updates" -Status "Disabling FireFox Services and Tasks" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
	$Services = Get-Service
			if($Services -match "MozillaMaintenance") {Set-Service MozillaMaintenance -StartupType Disabled -Passthru}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\FireFox" -Name "DisableAppUpdate" -Value 1 -Type Dword -Force -PassThru
	}
	else {Write-Output "Firefox not present, skipping"}

Write-Output ""
Write-Output "====================---------- End of Browser Patching ----------===================="
Stop-Transcript
#End of Browser Tasks
#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------