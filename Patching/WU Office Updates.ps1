<#
-------------WU Office Patching Script V2.0---------------
----------------Created by Kyle Baxter----------------

.Synopsis
Patching Script for windows Office Updates 

.Description
This script is for the installation of windows Office Updates  to a machine autonomously 
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
	If(!(Test-Path -PathType container $LogPath)) {New-Item -ItemType Directory -Path $LogPath} 
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
$TotalTasks = 2

#Start of OfficeUpdate tasks
#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Start-Transcript -Append  -Path "$LogPath$Log - OfficeUpdates.log" 
Write-Output "====================---------- Start of Office Patching ----------===================="
Write-Output ""

#Run Office Updater
	If($Script:IncludeOfficeUpdates -eq "1") {
	Write-Progress -Activity "Office Updates" -Status "Updating Office Applications" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
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
			Write-Progress -Activity "Office Updates" -Status "Disabling Scheduled Tasks" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
			$Tasks = Get-ScheduledTask
			#====================---------- Office Apps ----------====================#
			If($Tasks -match "Office Automatic Updates 2.0") {Disable-ScheduledTask -TaskName "Office Automatic Updates 2.0" -TaskPath "\Microsoft\Office\"}
			If($Tasks -match "Office ClickToRun Service Monitor") {Disable-ScheduledTask -TaskName "Office ClickToRun Service Monitor" -TaskPath "\Microsoft\Office\"}
			If($Tasks -match "Office Feature Updates") {Disable-ScheduledTask -TaskName "Office Feature Updates" -TaskPath "\Microsoft\Office\"}
			If($Tasks -match "Office Feature Updates Logon") {Disable-ScheduledTask -TaskName "Office Feature Updates Logon" -TaskPath "\Microsoft\Office\"}
			If($Tasks -match "Office Serviceability Manager") {Disable-ScheduledTask -TaskName "Office Serviceability Manager" -TaskPath "\Microsoft\Office\"}
			If($Tasks -match "OfficeTelemetryAgentFallBack2016") {Disable-ScheduledTask -TaskName "OfficeTelemetryAgentFallBack2016" -TaskPath "\Microsoft\Office\"}
			If($Tasks -match "OfficeTelemetryAgentLogOn2016") {Disable-ScheduledTask -TaskName "OfficeTelemetryAgentLogOn2016" -TaskPath "\Microsoft\Office\"}
		} Else {Write-Output "Office updater not present. Skipping"}
	} Else {Write-Output "Office Updates are Disabled"}
Write-Output ""
Write-Output "====================---------- End of Office Patching ----------===================="
Stop-Transcript