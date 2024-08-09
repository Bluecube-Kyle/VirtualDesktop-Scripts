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
$LogPath = "C:\VDI Tools\Logs\Maintenance\$Date\"
$Log = "$ENV:ComputerName - $Time"
	If(!(Test-Path -PathType container $LogPath)) {New-Item -ItemType Directory -Path $LogPath} 

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
$RegWuMedic = 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc'
$RegWu = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
$RegAu = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
If(!(Test-Path $RegWu)) {New-Item -Path $RegWu -Force}
If(!(Test-Path $RegAu)) {New-Item -Path $RegAu -Force}
If((Test-Path $RegWuMedic) -eq $true) {Set-ItemProperty -Path $RegWuMedic -Name Start -Value 3 -Force -Passthru}
Set-ItemProperty -Path $RegWu -Name DisableWindowsUpdateAccess -Value 0 -Force -Passthru
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Value 0 -Force -Passthru
$Services = Get-Service
$WUServices = "UsoSvc,Wuauserv,Vss,SmpHost,Uhssvc,DPS,BITS" -Split ","
$Matches = Select-String $WUServices -Input $Services -AllMatches | Foreach {$_.matches} | Select -Expand Value 
	Foreach($Matches in $WUServices) {
		If($Services -match $Matches) {
			Set-Service $Matches -StartupType Manual
			Restart-Service $Matches -Force
			Write-Output "Startup of service $Matches set to Manual and Started"
		} Else {Write-Output "$Matches not present"}
	}	
Set-Service TrustedInstaller -StartupType Manual
Write-Output "Startup of service TrustedInstaller set to Manual"

#--------------------Disk Cleanup--------------------#
#DiskMgr Cleanup. First sets stateflags to select all options with StateFlag 1
Write-Progress -Activity "DiskCleanup" -Status "Disk Cleanup" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
$VolumeCachesRegDir = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
$CacheDirItemNames = Get-ItemProperty "$VolumeCachesRegDir\*" | select -ExpandProperty PSChildName
$CacheDirItemNames | %{$exists = Get-ItemProperty -Path "$VolumeCachesRegDir\$_" -Name "StateFlags0001" -ErrorAction SilentlyContinue
	If (($exists -ne $null) -and ($exists.Length -ne 0)) {Set-ItemProperty -Path "$VolumeCachesRegDir\$_" -Name StateFlags0001 -Value 2}
	else {New-ItemProperty -Path "$VolumeCachesRegDir\$_" -Name StateFlags0001 -Value 0 -PropertyType DWord}}
	
#Run DismMgr with arguments for Stateflage option 1 and only run on SystemDrive (OS Drive, Almost always C)
Start-Process CleanMgr -ArgumentList "/sagerun:1 /D%SystemDrive%" -PassThru -Wait
Write-Output "Disk Cleanup cleared unecessary files"

#--------------------Event Logs--------------------#
#Clear Event Logs for Application, Security and System
Write-Progress -Activity "DiskCleanup" -Status "EventLog Cleanup" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
$Logs = Get-EventLog -List
Clear-EventLog -LogName $Logs.Log -ErrorAction SilentlyContinue
Get-Eventlog -List

#--------------------WinSxS Cleanup--------------------#
#First checks the WinSxS store size and will run cleanup based on if it is recommended or not
Write-Progress -Activity "DiskCleanup" -Status "Checking WinSxS Store" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
$AnalyzeStore = Dism /Online /Cleanup-Image /AnalyzeComponentStore /NoRestart
$AnalyzeStore #Run Variable alone so its stored in Logfile
Write-Progress -Activity "DiskCleanup" -Status "Cleaning WinSxS Store" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
Dism /Online /Cleanup-Image /StartComponentCleanup /NoRestart
	
#Stop Services and disable them
Write-Progress -Activity "DiskCleanup" -Status "Stopping Services" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
	Foreach($Matches in $WUServices) {
		If($Services -match $Matches) {
			Set-Service $Matches -StartupType Disabled
			Stop-Service $Matches -Force
			Write-Output "Startup of service $Matches set to Disabled and Stopped"
		} Else {Write-Output "$Matches not present"}
	}		
If((Test-Path $RegWuMedic) -eq $true) {Set-ItemProperty -Path $RegWuMedic -Name Start -Value 4 -Force -Passthru}
Set-ItemProperty -Path $RegWu -Name DisableWindowsUpdateAccess -Value 1 -Force -Passthru
Set-ItemProperty -Path $RegAu -Name NoAutoUpdate -Value 1 -Force -Passthru

#Clear SoftwareDistribution Folder
Write-Output "====================---------- Clear Software Distribution Folder ----------===================="
Write-Output ""
Write-Progress -Activity "DiskCleanup" -Status "Clearing SoftwareDistribution Folder" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
$SoftwareDistribution = Test-Path -Path "C:\Windows\SoftwareDistribution"
	If($Services -match "Wuauserv") {Stop-Service Wuauserv -Force}
	If($SoftwareDistribution -eq $true) {Remove-Item -Path "C:\Windows\SoftwareDistribution" -Force -Recurse}

Write-Output ""
Write-Output "====================---------- End of Disk Cleanup ----------===================="
Stop-Transcript
#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#End of DiskCleanup tasks