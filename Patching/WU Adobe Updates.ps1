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
$LogPath = "C:\VDI Tools\Logs\Patching\$Date\"
$ConfigPath = "C:\VDI Tools\Configs\"
$Log = "$ENV:ComputerName - $Time"
	If(!(Test-Path -PathType container $LogPath)) {New-Item -ItemType Directory -Path $LogPath} 
	If(!(Test-Path -PathType Container $ConfigPath)) {New-Item -ItemType Directory -Path $ConfigPath}

#Global Variables.
$CurrentTask = 0
$PercentComplete = 0
$TotalTasks = 3

#Start of Adobe Tasks
#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Start-Transcript -Append  -Path "$LogPath$Log - AdobeUpdates.log" 
Write-Output "====================---------- Start of Adobe Patching ----------===================="
Write-Output ""

Write-Progress -Activity "Adobe Updates" -Status "Updating Adobe Applications" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
#Look for Adobe 32 or 64bit exe file to confirm its installed - Registry not viable as some installs will create it with MSI code and others with application name path. 
$AdobeX32 = Test-Path -Path "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"
$AdobeX64 = Test-Path -Path "C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe"
#Both 32 and 64bit Adobe use the same location to store the updater exe so if either are true run it
	if(($AdobeX32 -eq $true) -or ($AdobeX64 -eq $true)) {
	Write-Progress -Activity "Adobe Updates" -Status "Running Adobe Updater" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bUpdater" -Value 1 -Type Dword -Force -PassThru
	Start-Process "C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\AdobeARM.exe" -Wait 
	Write-Output "Adobe Updated"

	#Disable Auto Updater service
	Write-Progress -Activity "Adobe Updates" -Status "Disabling Adobe Services and Tasks" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
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
#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#End of Adobe Tasks