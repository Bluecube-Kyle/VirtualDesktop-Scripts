<#
------------Maintenance Disk Optimise Script V2.0---------------
----------------Created by Kyle Baxter----------------

.Synopsis
Windows Disk Optimisation Script

.Description
This script completes disk optimisations for windows desktops

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
$LogPath = "C:\VDI Tools\Logs\Maintenance\$Date\"
$Log = "$ENV:ComputerName - $Time"
	If(!(Test-Path -PathType container $LogPath)) {New-Item -ItemType Directory -Path $LogPath} 

#Global Variables.
$CurrentTask = 0
$PercentComplete = 0
$TotalTasks = 3

#Start of Disk Optimise Tasks
#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Start-Transcript -Append -Path "$LogPath$Log - Disk Optimise.log" 
Write-Output "====================---------- Start of Disk Optimisation ----------===================="
Write-Output ""

#--------------------Enable and Start Services--------------------#
Write-Progress -Activity "DiskOptimise" -Status "Starting Services" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
Set-Service DefragSvc -StartupType Manual
Write-Output "Service DefragSvc Set to Manual"

#--------------------Defrag C: Drive--------------------#
Write-Progress -Activity "DiskOptimise" -Status "Defragging C:\" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100 
Defrag C:\

#--------------------Stop and Disable Services--------------------#
Write-Progress -Activity "DiskOptimise" -Status "Stopping Services" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
Stop-Service DefragSvc -Force
Set-Service DefragSvc -StartupType Disabled
Disable-ScheduledTask -TaskName "ScheduledDefrag" -TaskPath "\Microsoft\Windows\Defrag\"

Write-Output ""
Write-Output "====================---------- End of Disk Optimisation ----------===================="
Stop-Transcript
#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#End of Disk Optimise Tasks