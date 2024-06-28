<#
---------------CTS Patching Script V1.3---------------
----------------Created by Kyle Baxter----------------

.Synopsis
Windows Patching Script to automatic monthly patching 

.Description
This script will perform automated patching of a number of applications. Upon running this script will prompt a user selection interfacte to choose what tasks are to be completed
The list of available functions is as follows; Windows Updates, Office Updates, Browser Updates, Adobe Updates and Disk Cleanup of patch files.
Each task is isolated into its own function and creates its own block inside the log file.
To complete each task first the required services will be enabled and then disabled at the end -
	Windows Updates: Imports the PSWIndowsUpdate module and then first runs a get updates command and then an install updates command skipping KB890830. Following Windows updates will update Defender Definitions
	Microsoft Office Updates: Runs the Click to Run updater with force close of applications. As normal -Wait does not work a loop is created that waits for the process to report up to date before progressing
	Browser Updates: First checks if that browser is installed by looking for the application.exe / registry keys. If it is present will download the latest online installer and run it silently before removing it.
For edge specifically installed the latest version does not overwrite the existing version. To resolve this it first kills all edge processes and wipes the directory, then runs the installer.
Following Installation disables services and ScheduledTasks used to enable automatic elevation and updating of the application
	Adobe: First checks installed type and then runs the AdobeARM which will update the current Reader version to the latest version. Following update disables manual check for updates.
	DiskCleanup: Disk Cleanup runs 4 different cleanup tasks. First will set Stateflags for DiskMgr cleanup to clean all options on drive C, Cleans up Windows Event Logs, Analyzes WinSxS store and performs cleanup if windows reports cleanup recommended
Lastly clears the Software distribution  folder.
This script does not use an erroraction silent continue conditions as it always checks for its present first before attempting to modify.

.Requirements 
Requires the PSWIndowsUpdate Module to be installed. This can be done with the following command (Requires changing execution policy)
Install-Module -Name PSWindowsUpdate -Force

.LogFile
C:\CTS\UpdateLogs\Hostname - Date - Patching.log
#>

#Detect if run as admin and if not request elevation
If(-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	$arguments = "& '" + $myInvocation.MyCommand.Definition + "'"
	Start-Process Powershell -Verb runAs -ArgumentList $arguments
	exit
}

#Create Required Directories
$Date = Get-Date -F yyyy-MM-dd
$LogPath = "C:\Bluecube\PatchingLogs\$Date\"
$ConfigPath = "C:\Bluecube\Configs\"
$Log = "$ENV:ComputerName - Patching"
$Installs = "C:\Bluecube\Installers"
	If(!(Test-Path -PathType container $LogPath)) {New-Item -ItemType Directory -Path $LogPath} 
	If(!(Test-Path -PathType container $Installs)) {New-Item -ItemType Directory -Path $Installs} 
	If(!(Test-Path -PathType Container $ConfigPath)) {New-Item -ItemType Directory -Path $ConfigPath}

#Create Script that prevents machine going to sleep during script execution if its not present - Script presses F13 key every 2 minutes. As F13 doesn't exist it doesn't do anything but stop sleep
#Required as if host sleeps can pause PS execution. To work you must be connected to the host directly and not over RDP
$NoLock = Test-Path -Path "C:\Scripts\NoLock.ps1"
	If($NoLock -eq $false) {
New-Item -Path "C:\Scripts\NoLock.ps1"
Add-Content -Path "C:\Scripts\NoLock.ps1" -Value 'Do {
[void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[System.Windows.Forms.SendKeys]::SendWait("{F13}")
Start-Sleep -Seconds 120
} While ("$true")'
}

#Create Variables File
$ConfigFile = "C:\Bluecube\Configs\PatchingConf.txt"
$Config = Test-Path -Path $ConfigFile
	If($Config -eq $false){New-Item -Path $ConfigFile
Add-Content -Path $ConfigFile -Value "#---------------Bluecube Patching Config V1.0---------------#
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
If($Script:ExcludedUpdates -eq $null) {
	Write-Output "Exclude these KB's from updates"
	$Script:ExcludedUpdates = Read-Host -Prompt "Enter the full KB Id of patch to excluded seperated by a comma for multiple. Leave empty for no exclusions"
	Add-Content -Path $ConfigFile -Value "ExcludedUpdates = $Script:ExcludedUpdates"
	Clear}
If($Script:IncludeOfficeUpdates -eq $null) {
	$Script:IncludeOfficeUpdates = Read-Host -Prompt "Update Office apps. 0 to Deny 1 to Include"
	Add-Content -Path $ConfigFile -Value "IncludeOfficeUpdates = $Script:IncludeOfficeUpdates"
	Clear}	
If($Script:ServicesWindowsUpdates -eq $null) {Add-Content -Path $ConfigFile -Value "ServicesWindowsUpdates = UsoSvc,Wuauserv,Vss,SmpHost,Uhssvc,DPS,BITS"}	

#Acquire all Variable stored in file
Get-Content -Path $ConfigFile | Where-Object {$_.length -gt 0} | Where-Object {!$_.StartsWith("#")} | ForEach-Object {
    $var = $_.Split('=',2).Trim()
    Set-Variable -Scope Script -Name $var[0] -Value $var[1]
}

#Global Variables.
$global:CurrentTask = 0
$global:PercentComplete = 0
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Function WindowsUpdates {
Start-Transcript -Append -Path "$LogPath$Log - WindowsPatching.log" 
Write-Output "====================---------- Start of Windows Patching ----------===================="
Write-Output ""

#Start Services needed for updates - Windows Update, Update Orchestrator, Windows Medic Service and Trusted installer.
Write-Progress -Activity "Windows Updates" -Status "Starting Services" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
$Services = Get-Service
$Script:ServicesWindowsUpdates = $Script:ServicesWindowsUpdates -Split ","
$Matches = Select-String $Script:ServicesWindowsUpdates -Input $Services -AllMatches | Foreach {$_.matches} | Select -Expand Value 
	Foreach($Matches in $Script:ServicesWindowsUpdates) {
		If($Services -match $Matches) {
			Set-Service $Matches -StartupType Manual
			Write-Output "Startup of service $Matches set to Manual"
		} Else {Write-Output "$Matches not present"}
	}	
Set-Service TrustedInstaller -StartupType Manual
Write-Output "Startup of service TrustedInstaller set to Manual"
$RegWuMedic = 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc'
$RegWu = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
$RegAu = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
If((Test-Path $RegWuMedic) -eq $true) {Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc' -Name Start -Value 3 -Force -Passthru}
If(!(Test-Path $RegWu)) {New-Item -Path $RegWu -Force}
If(!(Test-Path $RegAu)) {New-Item -Path $RegAu -Force}
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -Name DisableWindowsUpdateAccess -Value 0 -Force -Passthru
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Value 0 -Force -Passthru

#Check if the PS module is present or not and install it if not
Write-Progress -Activity "Windows Updates" -Status "Checking If Module Is Present" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
$WUModule = Get-Module -ListAvailable
$NuGetProvider = Get-PackageProvider -ListAvailable
	If($WUModule -match "PSWIndowsUpdate") {} 
	else {
		If($NuGetProvider -match "NuGet") {Install-Module PSWindowsUpdate -Force}
		else {
		Install-PackageProvider -Name NuGet -Force
		Install-Module PSWindowsUpdate -Force
		}
	}

#Pull Updates list and then install updates list - Pulling first outputs full update options to log before installing
Write-Progress -Activity "Windows Updates" -Status "Checking For Updates" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
bitsadmin.exe /reset /allusers
Import-Module PSWindowsUpdate
Get-WUInstall -MicrosoftUpdate
Write-Progress -Activity "Windows Updates" -Status "Installing Updates" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
	If($Script:ExcludedUpdates) {Install-WindowsUpdate -UpdateType Software -NotKBArticleID $Script:ExcludedUpdates -IgnoreReboot -AcceptAll} 
	Else {Install-WindowsUpdate -UpdateType Software -MicrosoftUpdate -IgnoreReboot -AcceptAll}

#Update Windows Defender Definitions
Write-Progress -Activity "Windows Updates" -Status "Updating Defender Definitions" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
$NativeDefender = Test-Path -Path "C:\Program Files\Windows Defender\MpCmdRun.exe"
	If($NativeDefender -eq $true) {
	& "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -DynamicSignatures
	& "C:\Program Files\Windows Defender\MpCmdRun.exe" -SignatureUpdate
	} else { Write-Output "Native Defender Not Presetn. Skipping Definition Update"}

#--------------------INet Framework Queued Items and Update--------------------#
Write-Output "Inet Framework v4 queued items and updates"
Write-Progress -Activity "Windows Updates" -Status "Inet2 Execute Queued Items x32" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
Write-Output "Inet framework v2 x32 Queued Items"
Start-Process "C:\Windows\Microsoft.Net\Framework\v2.0.50727\ngen.exe" -Args "update /force" -Wait | Out-Null
Write-Progress -Activity "Windows Updates" -Status "Inet2 Execute Queued Items x64" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
Write-Output "Inet framework v2 x64 Queued Items"
Start-Process "C:\Windows\Microsoft.Net\Framework64\v2.0.50727\ngen.exe" -Args "update /force" -Wait | Out-Null
Write-Progress -Activity "Windows Updates" -Status "Inet4 Execute Queued Items x32" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
Write-Output "Inet framework v4 x32 Queued Items"
Start-Process "C:\Windows\Microsoft.Net\Framework\v4.0.30319\ngen.exe" -Args "update /force" -Wait | Out-Null
Write-Progress -Activity "Windows Updates" -Status "Inet4 Execute Queued Items x64" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
Write-Output "Inet framework v4 x64 Queued Items"
Start-Process "C:\Windows\Microsoft.Net\Framework64\v4.0.30319\ngen.exe" -Args "update /force" -Wait | Out-Null
Write-Progress -Activity "Windows Updates" -Status "Inet2 Update x32" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
Write-Output "Inet framework v2 x32 Updating"
Start-Process "C:\Windows\Microsoft.Net\Framework\v2.0.50727\ngen.exe" -Args "executeQueuedItems" -Wait | Out-Null
Write-Progress -Activity "Windows Updates" -Status "Inet2 Update x64" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
Write-Output "Inet framework v2 x64 Updating"
Start-Process "C:\Windows\Microsoft.Net\Framework64\v2.0.50727\ngen.exe" -Args "executeQueuedItems" -Wait | Out-Null
Write-Progress -Activity "Windows Updates" -Status "Inet4 Update x32" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
Write-Output "Inet framework v4 x32 Updating"
Start-Process "C:\Windows\Microsoft.Net\Framework\v4.0.30319\ngen.exe" -Args "executeQueuedItems" -Wait | Out-Null
Write-Progress -Activity "Windows Updates" -Status "Inet4 Update x64" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
Write-Output "Inet framework v4 x64 Updating"
Start-Process "C:\Windows\Microsoft.Net\Framework64\v4.0.30319\ngen.exe" -Args "executeQueuedItems" -Wait | Out-Null

#Stop Services and then Disable them
Write-Progress -Activity "Windows Updates" -Status "Disabling Services" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
	Foreach($Matches in $Script:ServicesWindowsUpdates) {
		If($Services -match $Matches) {
			Set-Service $Matches -StartupType Disabled
			Write-Output "Startup of service $Matches set to Disabled"
		} Else {Write-Output "$Matches not present"}
	}	
$RegWuMedic = 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc'
$RegWu = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
$RegAu = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
If((Test-Path $RegWuMedic) -eq $true) {Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc' -Name Start -Value 4 -Force -Passthru}
If(!(Test-Path $RegWu)) {New-Item -Path $RegWu -Force}
If(!(Test-Path $RegAu)) {New-Item -Path $RegAu -Force}
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -Name DisableWindowsUpdateAccess -Value 1 -Force -Passthru
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Value 1 -Force -Passthru
$Tasks = Get-ScheduledTask
	If($Tasks -match ".NET Framework NGEN v4.0.30319") {Disable-ScheduledTask -TaskName ".NET Framework NGEN v4.0.30319" -TaskPath "\Microsoft\Windows\.NET Framework"}
	If($Tasks -match ".NET Framework NGEN v4.0.30319 64") {Disable-ScheduledTask -TaskName ".NET Framework NGEN v4.0.30319 64" -TaskPath "\Microsoft\Windows\.NET Framework"}
	If($Tasks -match ".NET Framework NGEN v4.0.30319 Critical") {Disable-ScheduledTask -TaskName ".NET Framework NGEN v4.0.30319 Critical" -TaskPath "\Microsoft\Windows\.NET Framework"}
	If($Tasks -match ".NET Framework NGEN v4.0.30319 64 Critical") {Disable-ScheduledTask -TaskName ".NET Framework NGEN v4.0.30319 64 Critical" -TaskPath "\Microsoft\Windows\.NET Framework"}

Write-Output ""
Write-Output "====================---------- End of Windows Patching ----------===================="
Stop-Transcript
}

Function OfficeUpdates {
Start-Transcript -Append  -Path "$LogPath$Log - OfficeUpdates.log" 
Write-Output "====================---------- Start of Office Patching ----------===================="
Write-Output ""

#Run Office Updater
	If($Script:IncludeOfficeUpdates -eq "1") {
	Write-Progress -Activity "Office Updates" -Status "Updating Office Applications" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
	$OfficeUpdater = Test-Path -Path "C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe"
		If($OfficeUpdater -eq $true) {
		Write-Output "Click to Run updater present. Beginning update"
		If((Get-Service ClickToRunSvc | Select -Property Status) -notmatch "Running") {Start-Service ClicktoRunSvc}
		Start-Process "C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe" -ArgumentList "/Update user forceappshutdown=true"
		#Wait for Installer to report Up to date or updated - Required as C2RClients opens and closes multiple processes. -Wait only waits on the first to finish
		#Checks processes status, Sleeps for 1s then rechecks process stats. Loops until condition is met of up to date message
			While((($Process.MainWindowTitle -match "up to date!") -or ($Process.MainWindowTitle -match "Updates were installed")) -eq $false) {$Process = Get-Process ; Start-Sleep 5}
			If($Process.MainWindowTitle -match "up to date!") {Write-Output "Office is already up to date"}
			If($Process.MainWindowTitle -match "Updates were installed") {Write-Output "Office has been updated"}
		
			#Disable ScheduledTasks not required for non persistent image
			Write-Progress -Activity "Office Updates" -Status "Disabling Scheduled Tasks" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
			$Tasks = Get-ScheduledTask
			If($Tasks -match "Office Automatic Updates 2.0") {Disable-ScheduledTask -TaskName "Office Automatic Updates 2.0" -TaskPath "\Microsoft\Office\"}
			If($Tasks -match "Office ClickToRun Service Monitor") {Disable-ScheduledTask -TaskName "Office ClickToRun Service Monitor" -TaskPath "\Microsoft\Office\"}
			If($Tasks -match "Office Feature Updates") {Disable-ScheduledTask -TaskName "Office Feature Updates Logon" -TaskPath "\Microsoft\Office\"}
			If($Tasks -match "Office Feature Updates Logon") {Disable-ScheduledTask -TaskName "Office Feature Updates Logon" -TaskPath "\Microsoft\Office\"}
			If($Tasks -match "Office Serviceability Manager") {Disable-ScheduledTask -TaskName "Office Serviceability Manager" -TaskPath "\Microsoft\Office\"}
			If($Tasks -match "OfficeTelemetryAgentFallBack2016") {Disable-ScheduledTask -TaskName "OfficeTelemetryAgentFallBack2016" -TaskPath "\Microsoft\Office\"}
			If($Tasks -match "OfficeTelemetryAgentLogOn2016") {Disable-ScheduledTask -TaskName "OfficeTelemetryAgentLogOn2016" -TaskPath "\Microsoft\Office\"}
		} Else {Write-Output "Office updater not present. Skipping"}
	} Else {Write-Output "Office Updates are Disabled"}
	
Write-Output ""
Write-Output "====================---------- End of Office Patching ----------===================="
Stop-Transcript
}

Function BrowserUpdates {
Start-Transcript -Append  -Path "$LogPath$Log - BrowserUpdates.log" 
Write-Output "====================---------- Start of Browser Patching ----------===================="
Write-Output ""

#--------------------Edge--------------------#
Write-Progress -Activity "Browser Updates" -Status "Updating Browsers" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
#Checking if Edge exists and clearing directory. (Running latest installer doesn't overwrite the existing exe's to latest version)
$EdgeExists = Test-Path -Path "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
	If($EdgeExists -eq $true) {$EdgeActive = Get-Process
		If($EdgeActive -match "msedge") {Stop-Process -Name MsEdge -Verbose -Force}
		Start-Sleep 3
		Remove-Item -Path 'C:\Program Files (x86)\Microsoft\Edge\Application\*.exe' -Force -Recurse

		#Download Online Installer for latest release and run it
		Write-Progress -Activity "Browser Updates" -Status "Downloading Latest Edge Version" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
		Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2108834&Channel=Stable&language=en&brand=M100" -OutFile "$Installs\Edge.exe"
		Write-Progress -Activity "Browser Updates" -Status "Installing Latest Edge Version" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
		Start-Process "$Installs\Edge.exe" -Wait
		Remove-Item -Path "$Installs\Edge.exe"
		Write-Output "Edge Updated"

		#Disable Automatic Updater services and tasks
		Write-Progress -Activity "Browser Updates" -Status "Disabling Edge Services and Tasks" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
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
$Chrome = Test-Path -Path "C:\Program Files\Google\Chrome\Application\Chrome.exe"
$Chrome64 = Test-Path -Path "C:\Program Files (x86)\Google\Chrome\Application\Chrome.exe"
	If(($Chrome -eq $true) -or ($Chrome64 -eq $true))  {
	Write-Progress -Activity "Browser Updates" -Status "Downloading Latest Chrome Version" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 	
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Update" -Name "UpdateDefault" -Value 1 -Type Dword -Force -PassThru
	$Installer = "chrome_installer.exe"; Invoke-WebRequest "https://dl.google.com/chrome/install/latest/chrome_installer.exe" -OutFile "$Installs\$Installer"
	Write-Progress -Activity "Browser Updates" -Status "Installing Latest Chrome Version" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
	Start-Process -FilePath "$Installs\$Installer" -Args "/silent /install" -Verb RunAs -Wait
	Remove-Item "$Installs\$Installer "
	Write-Output "Chrome Updated"

	#Disable Automatic Updater services and tasks - Google adds an MSI code onto Scheduledtasks to try and prevent auto stopping the tasks. The following will acquire the task name and then wildcard for the MSIcode to disable it
	Write-Progress -Activity "Browser Updates" -Status "Disabling Chrome Services and Tasks" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Update" -Name "UpdateDefault" -Value 0 -Type Dword -Force -PassThru
	$Services = Get-Service
	$ScheduledTask = Get-ScheduledTask
		If($Services -match "gupdate") {Set-Service gupdate -StartupType Disabled -PassThru}
		If($Services -match "gupdatem") {Set-Service gupdatem -StartupType Disabled -PassThru}
		If($Services -match "GoogleUpdaterService*")	{Get-Service -DisplayName "GoogleUpdater Service*" | Set-Service -StartupType Disabled}		
		If($Services -match "GoogleUpdaterInternalService*")	{Get-Service -DisplayName "GoogleUpdater InternalService*" | Set-Service -StartupType Disabled}
		If($Services -match "GoogleChromeElevationService") {Set-Service GoogleChromeElevationService -StartupType Disabled -PassThru}
		If($Tasks -match "GoogleUpdateTaskMachineUA*") {Get-ScheduledTask -TaskName "*GoogleUpdateTaskMachineUA*" | Disable-ScheduledTask}
		If($Tasks -match "GoogleUpdateTaskMachineCore*") {Get-ScheduledTask -TaskName "*GoogleUpdateTaskMachineCore*" | Disable-ScheduledTask}
		If($Tasks -match "GoogleUpdaterTaskSystem*") {Get-ScheduledTask -TaskName "*GoogleUpdaterTaskSystem*" | Disable-ScheduledTask}
	}
	else { Write-Output "Chrome Not installed. Skipping Update" }

#--------------------Firefox--------------------#
$FireFox = Test-Path -Path "C:\Program Files\Mozilla Firefox"
	If($FireFox -eq $true){
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\FireFox" -Name "DisableAppUpdate" -Value 0 -Type Dword -Force -PassThru
	#Downloads and runs the latest online installer
	Write-Progress -Activity "Browser Updates" -Status "Downloading Latest Firefox Version" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
	Invoke-WebRequest -Uri "https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US" -OutFile "$Installs\FireFox.exe"
	Write-Progress -Activity "Browser Updates" -Status "Installing Latest Firefox Version" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
	Start-Process "$Installs\FireFox.exe" -ArgumentList "-ms -ma" -Wait
	#Remove leftover installer
	Remove-Item -Path "$Installs\FireFox.exe"
	Write-Output "Firefox Updated"
	
	#Disable Automatic Updater services and tasks
	Write-Progress -Activity "Browser Updates" -Status "Disabling FireFox Services and Tasks" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
	$Services = Get-Service
			if($Services -match "MozillaMaintenance") {Set-Service MozillaMaintenance -StartupType Disabled -Passthru}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\FireFox" -Name "DisableAppUpdate" -Value 1 -Type Dword -Force -PassThru
	}
	else {Write-Output "Firefox not present, skipping"}

Write-Output ""
Write-Output "====================---------- End of Browser Patching ----------===================="
Stop-Transcript
}

Function AdobeUpdates {
Start-Transcript -Append  -Path "$LogPath$Log - AdobeUpdates.log" 
Write-Output "====================---------- Start of Adobe Patching ----------===================="
Write-Output ""

Write-Progress -Activity "Adobe Updates" -Status "Updating Adobe Applications" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
#Look for Adobe 32 or 64bit exe file to confirm its installed - Registry not viable as some installs will create it with MSI code and others with application name path. 
$AdobeX32 = Test-Path -Path "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"
$AdobeX64 = Test-Path -Path "C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe"
#Both 32 and 64bit Adobe use the same location to store the updater exe so if either are true run it
	if(($AdobeX32 -eq $true) -or ($AdobeX64 -eq $true)) {
	Write-Progress -Activity "Adobe Updates" -Status "Running Adobe Updater" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bUpdater" -Value 1 -Type Dword -Force -PassThru
	Start-Process "C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\AdobeARM.exe" -Wait 
	Write-Output "Adobe Updated"

	#Disable Auto Updater service
	Write-Progress -Activity "Adobe Updates" -Status "Disabling Adobe Services and Tasks" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
	$Services = Get-Service
	$ScheduledTask = Get-ScheduledTask
		if($Services -match "AdobeARMservice") {Set-Service AdobeARMservice -StartupType Disabled -PassThru}
		if($ScheduledTask -match "Adobe Acrobat Update Task") {Disable-ScheduledTask -TaskName "Adobe Acrobat Update Task"}
	#Disable Manual Updates in App
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bUpdater" -Value 0 -Type Dword -Force -PassThru	
	} else {Write-Output "Adobe Reader not Present"}

Write-Output ""
Write-Output "====================---------- End of Adobe Patching ----------===================="
Stop-Transcript
}

Function DiskCleanup {
Start-Transcript -Append  -Path "$LogPath$Log - DiskCleanup.log" 
Write-Output "====================---------- Start of Disk Cleanup ----------===================="
Write-Output ""

#Start Services
Write-Progress -Activity "DiskCleanup" -Status "Starting Services" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
$Services = Get-Service
$Script:ServicesWindowsUpdates = $Script:ServicesWindowsUpdates -Split ","
$Matches = Select-String $Script:ServicesWindowsUpdates -Input $Services -AllMatches | Foreach {$_.matches} | Select -Expand Value 
	Foreach($Matches in $Script:ServicesWindowsUpdates) {
		If($Services -match $Matches) {
			Set-Service $Matches -StartupType Manual
			Write-Output "Startup of service $Matches set to Manual"
		} Else {Write-Output "$Matches not present"}
	}
Set-Service TrustedInstaller -StartupType Manual
Write-Output "Startup of service TrustedInstaller set to Manual"
$RegWuMedic = 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc'
$RegWu = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
$RegAu = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
If((Test-Path $RegWuMedic) -eq $true) {Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc' -Name Start -Value 3 -Force -Passthru}
If(!(Test-Path $RegWu)) {New-Item -Path $RegWu -Force}
If(!(Test-Path $RegAu)) {New-Item -Path $RegAu -Force}
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -Name DisableWindowsUpdateAccess -Value 0 -Force -Passthru
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Value 0 -Force -Passthru


#--------------------Disk Cleanup--------------------#
#DiskMgr Cleanup. First sets stateflags to select all options with StateFlag 1
Write-Progress -Activity "DiskCleanup" -Status "Disk Cleanup" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
$VolumeCachesRegDir = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
$CacheDirItemNames = Get-ItemProperty "$VolumeCachesRegDir\*" | select -ExpandProperty PSChildName
$CacheDirItemNames | %{$exists = Get-ItemProperty -Path "$VolumeCachesRegDir\$_" -Name "StateFlags0001" -ErrorAction SilentlyContinue
	If (($exists -ne $null) -and ($exists.Length -ne 0)) {Set-ItemProperty -Path "$VolumeCachesRegDir\$_" -Name StateFlags0001 -Value 2}
	else {New-ItemProperty -Path "$VolumeCachesRegDir\$_" -Name StateFlags0001 -Value 0 -PropertyType DWord}}
	
#Run DismMgr with arguments for Stateflage option 1 and only run on SystemDrive (OS Drive, Almost always C)
Start-Process CleanMgr -ArgumentList "/sagerun:1 /D %SystemDrive%" -PassThru -NoNewWindow -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
Start-Sleep 10
#Set the task priority for DiskMgr to high - Without this Windows can make it a low priority background task and take a lot longer. Sleep required as DismHost doesn't start right away
Get-WmiObject Win32_process -filter 'name = "CleanMgr.exe"' | foreach-object { $_.SetPriority(128) }
Get-WmiObject Win32_process -filter 'name = "DismHost.exe"' | foreach-object { $_.SetPriority(128) }
#Wait for CleanMgr process to end before progressing
$Processes = Get-Process
	if ($Processes -Match "CleanMgr") {Wait-Process -Name CleanMgr}
Write-Output "Disk Cleanup cleared unecessary files"

#--------------------Event Logs--------------------#
#Clear Event Logs for Application, Security and System
Write-Progress -Activity "DiskCleanup" -Status "EventLog Cleanup" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
$logs = Get-EventLog -List | ForEach-Object {$_.Log}
$logs | ForEach-Object {Clear-EventLog -LogName $_ }
Get-EventLog -list

#--------------------WinSxS Cleanup--------------------#
#First checks the WinSxS store size and will run cleanup based on if it is recommended or not
Write-Progress -Activity "DiskCleanup" -Status "Checking WinSxS Store" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
$AnalyzeStore = Dism /Online /Cleanup-Image /AnalyzeComponentStore /NoRestart
$AnalyzeStore #Run Variable alone so its stored in Logfile
Write-Progress -Activity "DiskCleanup" -Status "Cleaning WinSxS Store" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
	if ($AnalyzeStore -match "Component Store Cleanup Recommended : Yes") {
		Write-Output "Cleanup required. Running cleanup"
		Dism /Online /Cleanup-Image /StartComponentCleanup /NoRestart}
	else {Write-Output "Cleanup not required" }
	
<# Do not run with patching as will result in large amount of errors with pending reboot updates
#--------------------Software Distribution folder--------------------#
#Makes sure Windows Update service is stopped and deletes the Software distribution folder if present
Write-Progress -Activity "DiskCleanup" -Status "Clearing SoftwareDistribution Folder" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
$SoftwareDistribution = Test-Path -Path "C:\Windows\SoftwareDistribution"
	If($Services -match "Wuauserv") {Stop-Service Wuauserv -Force -PassThru}
	if($SoftwareDistribution -eq $true) {Remove-Item -Path "C:\Windows\SoftwareDistribution" -Force -Recurse}
	else {Write-Output "SoftwareDistribution Already Cleared"}
#>

#Stop Services and disable them
Write-Progress -Activity "DiskCleanup" -Status "Stopping Services" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
	Foreach($Matches in $Script:ServicesWindowsUpdates) {
		If($Services -match $Matches) {
			Set-Service $Matches -StartupType Disabled
			Write-Output "Startup of service $Matches set to Disabled"
		} Else {Write-Output "$Matches not present"}
	}	
$RegWuMedic = 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc'
$RegWu = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
$RegAu = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
If((Test-Path $RegWuMedic) -eq $true) {Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc' -Name Start -Value 4 -Force -Passthru}
If(!(Test-Path $RegWu)) {New-Item -Path $RegWu -Force}
If(!(Test-Path $RegAu)) {New-Item -Path $RegAu -Force}
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -Name DisableWindowsUpdateAccess -Value 1 -Force -Passthru
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Value 1 -Force -Passthru

Write-Output ""
Write-Output "====================---------- End of Disk Cleanup ----------===================="
Stop-Transcript
}

#--------------------User Selection Interface--------------------#
#Interface for user to select what tasks they want the script to action
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Windows Patching Script v1.3'
$form.Size = New-Object System.Drawing.Size(600,400)
$form.StartPosition = 'CenterScreen'

$OKButton = New-Object System.Windows.Forms.Button
$OKButton.Location = New-Object System.Drawing.Point(150,240)
$OKButton.Size = New-Object System.Drawing.Size(150,46)
$OKButton.Text = 'OK'
$OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.AcceptButton = $OKButton
$form.Controls.Add($OKButton)

$CancelButton = New-Object System.Windows.Forms.Button
$CancelButton.Location = New-Object System.Drawing.Point(300,240)
$CancelButton.Size = New-Object System.Drawing.Size(150,46)
$CancelButton.Text = 'Cancel'
$CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.CancelButton = $CancelButton
$form.Controls.Add($CancelButton)

$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(20,40)
$label.Size = New-Object System.Drawing.Size(560,40)
$label.Text = 'Choose what to complete. Multiple can be selected at once with ctrl/shift'
$label.Font = New-Object System.Drawing.Font("Cascadia Mono",10,[System.Drawing.FontStyle]::Regular)
$form.Controls.Add($label)

$listBox = New-Object System.Windows.Forms.Listbox
$listBox.Location = New-Object System.Drawing.Point(20,80)
$listBox.Size = New-Object System.Drawing.Size(520,40)
$listBox.Font = New-Object System.Drawing.Font("Cascadia Mono",12,[System.Drawing.FontStyle]::Regular)
$listBox.SelectionMode = 'MultiExtended'

#Task Choice list. Each option is a different choice. Options start with a number as it uses a string match to confirm the choices.
#To add more then 9 options the number format needs changing from 0-9 to 00-99.
[void] $listBox.Items.Add('1. Windows Updates')
[void] $listBox.Items.Add('2. Office Updates')
[void] $listBox.Items.Add('3. Browser Updates')
[void] $listBox.Items.Add('4. Adobe Updates')
[void] $listBox.Items.Add('5. Disk Cleanup')
[void] $listBox.Items.Add('6. Edit Config')

$listBox.Height = 140
$form.Controls.Add($listBox)
$form.Topmost = $true

$result = $form.ShowDialog()

if ($result -eq [System.Windows.Forms.DialogResult]::OK)
{
    $x = $listBox.SelectedItems
	If($x -notmatch "6.") {Invoke-Expression 'CMD /C Start Powershell -Command "C:\Scripts\NoLock.ps1"'}
	#Adds TotalTasks values if choice is selected. Used for setting the progress bars % per task
	If($x -match "1.") {$TotalTasks += 13}
	If($x -match "2.") {$TotalTasks += 2}
	If($x -match "3.") {$TotalTasks += 9}
	If($x -match "4.") {$TotalTasks += 3}
	If($x -match "5.") {$TotalTasks += 7}
	#Runs each function if its chosen and outputs the results to log file
	If($x -match "1.") {WindowsUpdates}
	If($x -match "2.") {OfficeUpdates}
	If($x -match "3.") {BrowserUpdates}
	If($x -match "4.") {AdobeUpdates}
	If($x -match "5.") {DiskCleanup}
	If($x -match "6.") {Start-Process $ConfigFile}
	If($x -notmatch "6.") {
		Write-Progress -Activity "Machine Patching" -Status "Patching Complete. Rebooting in 10s" -Id 1 -PercentComplete 100
		Start-Sleep 10 ; Restart-Computer -Force
	}
}