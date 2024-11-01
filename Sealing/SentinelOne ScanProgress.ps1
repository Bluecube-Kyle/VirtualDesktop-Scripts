<#
#---------------SentinelOne Scan Checker---------------#

.Synopsis
SentinelOne active scan checker

.Description
This script runs during sealing to check if there is an active scan by SentinelOne running. 
FDCS status must return 2 (complete) before an Image can be promoted to live. Failure to do so will cause high retry counts and degraded PVS performance
#>

#Detect if run as admin and if not request elevation
If(-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	$arguments = "& '" + $myInvocation.MyCommand.Definition + "'"
	Start-Process Powershell -Verb runAs -ArgumentList $arguments
	exit
}

$Date = Get-Date -F yyyy-MM-dd
$Time = Get-Date -F HH-mm
$LogPath = "C:\VDI Tools\Logs\Sealing\$Date\"
$Log = "$ENV:ComputerName - $Time"
Start-Transcript -Append -Path "$LogPath$Log - SentinelOneScan.log"

#Acquires SentinelOne Install path
$basePath = "C:\Program Files\SentinelOne\"
$sentinelDirectory = Get-ChildItem -Path $basePath -Directory
$sentinelName = $sentinelDirectory.Name
$sentinelpath = "$basePath$sentinelName"

# Sets the location to run the command
Set-Location $sentinelPath
# Commands to check FDCS scan and disk scan status
$FDCSStatus = & ".\SentinelCtl.exe" read_fdcs_status
$ScanStatus = & ".\SentinelCtl.exe" is_scan_in_progress

If ($FDCSStatus -ne "FDCS Status: 2") {
	$timer = [Diagnostics.Stopwatch]::StartNew()
	do {
		Write-Host "FDCS Scan is Running"
		Start-Sleep -Seconds 60
		$FDCSStatus = & ".\SentinelCtl.exe" read_fdcs_status
	} until ($FDCSStatus -eq "FDCS Status: 2")
}

If ($ScanStatus -ne "Scan is not in progress") {
	$timer = [Diagnostics.Stopwatch]::StartNew()
	do {
		Write-Host "Sentinel Scan is Running"
		Start-Sleep -Seconds 60
		$ScanStatus = & ".\SentinelCtl.exe" is_scan_in_progress
	} until ($ScanStatus -eq "Scan is not in progress")
}

# Write the Output
Write-Host "Sentinel Scan is Complete"

If($timer.IsRunning -eq $true) {
	$timer.Stop()
	$days = $timer.elapsed.Days
	$hours = $timer.elapsed.Hours
	$minutes = $timer.elapsed.Minutes
	$seconds = $timer.elapsed.Seconds

	If($days -ne 0) {Write-Host "Sentinel Scan took $days days, $hours hours, $minutes minutes, $seconds seconds"}
	elseif ($hours -ne 0) {Write-Host "Sentinel Scan took $hours hours, $minutes minutes, $seconds seconds"}
	elseif ($minutes -ne 0) {Write-Host "Sentinel Scan took $minutes minutes, $seconds seconds"}
	else {Write-Host "Sentinel Scan took $seconds seconds"}
}

Stop-Transcript