<#
---------Maintenance Online Repairs Script V2.0---------------
----------------Created by Kyle Baxter----------------

.Synopsis
Windows Online Repairs Scripts

.Description
This script completes Online Repairs of the Windows Image

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
$LogPath = "C:\VDI Tools\Maintenance\$Date\"
$Log = "$ENV:ComputerName - $Time"
	If(!(Test-Path -PathType container $LogPath)) {New-Item -ItemType Directory -Path $LogPath} 

#Global Variables.
$CurrentTask = 0
$PercentComplete = 0
$TotalTasks = 10

#Start of Online Repairs tasks
#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Start-Transcript -Append -Path "$LogPath$Log - OnlineRepairs.log" 
Write-Output "====================---------- Start of Online Repairs ----------===================="
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

#--------------------Wmi Repository Rebuild--------------------#
Write-Progress -Activity "Online System Repair" -Status "Repair WMI Repository" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
Write-Output "---Rebuild WMI Repository---"	
Set-Service WinMgmt -StartupType Disabled
Stop-Service WinMgmt -Force
Start-Sleep 3
WinMgmt /salvagerepository %windir%\System32\wbem
WinMgmt /resetrepository %windir%\System32\wbem
Set-Service WinMgmt -StartupType Manual
Start-Sleep 3

#--------------------SFC Scan and Repair--------------------#
Write-Progress -Activity "Online System Repair" -Status "Scanning System Health" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
Sfc /Scannow 
#--------------------Dism Image Repair--------------------#
Write-Progress -Activity "Online System Repair" -Status "Repairing Image" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100 
Dism /Online /Cleanup-Image /RestoreHealth
Write-Progress -Activity "Online System Repair" -Status "Cleaning Mount Points" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100 
Dism /Cleanup-MountPoints 
Write-Progress -Activity "Online System Repair" -Status "Cleaning Mount Points" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100 
Clear-WindowsCorruptMountPoint

#--------------------Check Disk Scan and Repair--------------------#
Write-Output "Chckdisk scan"
Write-Progress -Activity "Online System Repair" -Status "Repairing C Volume" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100 
Repair-Volume -DriveLetter C -OfflineScanAndFix  
$SystemReserved = Get-Volume
Write-Progress -Activity "Online System Repair" -Status "Repairing Protected Volume" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100 
if ($SystemReserved -match "System Reserved") {
Repair-Volume -FileSystemLabel "System Reserved" -OfflineScanAndFix}

#--------------------Rebuild Performance Counters--------------------#
Write-Progress -Activity "Online System Repair" -Status "Rebuild Perf Counters" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100 
Stop-Service Wuauserv -Force
& "c:\windows\system32\lodctr" /R
& "c:\windows\sysWOW64\lodctr" /R
WinMgmt /RESYNCPERF

#--------------------Stop and Disable Services--------------------#
Write-Output "Stopping OnlineRepair Services"
Write-Progress -Activity "Online System Repair" -Status "Stopping Services" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100 
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

Write-Output ""
Write-Output "====================---------- End of Online Repairs ----------===================="
Stop-Transcript
#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#End Of Offline Repair Tasks