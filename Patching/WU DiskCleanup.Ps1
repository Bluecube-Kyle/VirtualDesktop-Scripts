<#
--------------WU DiskCleanup Script V2.0---------------
----------------Created by Kyle Baxter----------------

.Synopsis
DiskCleanup Script for windows OS updates 

.Description
This script is for cleaning up unecessary files after patching
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
If($Script:ClearLogs -eq $null) {
	Add-Content -Path $ConfigFile -Value "ClearLogs = 1"
	Clear}		

#Acquire all Variable stored in file
Get-Content -Path $ConfigFile | Where-Object {$_.length -gt 0} | Where-Object {!$_.StartsWith("#")} | ForEach-Object {
    $var = $_.Split('=',2).Trim()
    Set-Variable -Scope Script -Name $var[0] -Value $var[1]
}

#Global Variables.
$CurrentTask = 0
$PercentComplete = 0
$TotalTasks = 6

#Start of DiskCleanup tasks
#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Start-Transcript -Append  -Path "$LogPath$Log - DiskCleanup.log" 
Write-Output "====================---------- Start of Disk Cleanup ----------===================="
Write-Output ""

#Start Services
Write-Progress -Activity "DiskCleanup" -Status "Starting Services" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
$Services = Get-Service
$WUServices = "UsoSvc,Wuauserv,Vss,SmpHost,Uhssvc,DPS,BITS" -Split ","
$Matches = Select-String $WUServices -Input $Services -AllMatches | Foreach {$_.matches} | Select -Expand Value 
	Foreach($Matches in $WUServices) {
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
If(!(Test-Path $RegWu)) {New-Item -Path $RegWu -Force}
If(!(Test-Path $RegAu)) {New-Item -Path $RegAu -Force}
If((Test-Path $RegWuMedic) -eq $true) {Set-ItemProperty -Path $RegWuMedic -Name Start -Value 3 -Force -Passthru}
Set-ItemProperty -Path $RegWu -Name DisableWindowsUpdateAccess -Value 0 -Force -Passthru
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Value 0 -Force -Passthru

#--------------------Disk Cleanup--------------------#
#DiskMgr Cleanup. First sets stateflags to select all options with StateFlag 1
Write-Progress -Activity "DiskCleanup" -Status "Disk Cleanup" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
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
Write-Progress -Activity "DiskCleanup" -Status "EventLog Cleanup" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
If($Script:ClearLogs -eq "1") {
$Logs = Get-EventLog -List
Clear-EventLog -LogName $Logs.Log
Get-Eventlog -List
} Else {Write-Output "Clear Logs on Seal Disabled"}

#--------------------WinSxS Cleanup--------------------#
#First checks the WinSxS store size and will run cleanup based on if it is recommended or not
Write-Progress -Activity "DiskCleanup" -Status "Checking WinSxS Store" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
$AnalyzeStore = Dism /Online /Cleanup-Image /AnalyzeComponentStore /NoRestart
$AnalyzeStore #Run Variable alone so its stored in Logfile
Write-Progress -Activity "DiskCleanup" -Status "Cleaning WinSxS Store" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
	if ($AnalyzeStore -match "Component Store Cleanup Recommended : Yes") {
		Write-Output "Cleanup required. Running cleanup"
		Dism /Online /Cleanup-Image /StartComponentCleanup /NoRestart}
	else {Write-Output "Cleanup not required" }
	
#Stop Services and disable them
Write-Progress -Activity "DiskCleanup" -Status "Stopping Services" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
	Foreach($Matches in $WUServices) {
		If($Services -match $Matches) {
			Set-Service $Matches -StartupType Disabled
			Write-Output "Startup of service $Matches set to Disabled"
		} Else {Write-Output "$Matches not present"}
	}	
If((Test-Path $RegWuMedic) -eq $true) {Set-ItemProperty -Path $RegWuMedic -Name Start -Value 4 -Force -Passthru}
Set-ItemProperty -Path $RegWu -Name DisableWindowsUpdateAccess -Value 1 -Force -Passthru
Set-ItemProperty -Path $RegAu -Name NoAutoUpdate -Value 1 -Force -Passthru

Write-Output ""
Write-Output "====================---------- End of Disk Cleanup ----------===================="
Stop-Transcript
#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#End of DiskCleanup tasks