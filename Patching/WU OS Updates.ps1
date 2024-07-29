<#
--------------WU OS Patching Script V2.0---------------
----------------Created by Kyle Baxter----------------

.Synopsis
Patching Script for windows OS updates 

.Description
This script is for the installation of windows os updates to a machine autonomously 
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
$TotalTasks = 15
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#Start of Patching tasks
#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Start-Transcript -Append -Path "$LogPath$Log - WindowsPatching.log" -Force
Write-Output "====================---------- Start of Windows Patching ----------===================="
Write-Output ""

#Start Services needed for updates - Windows Update, Update Orchestrator, Windows Medic Service and Trusted installer.
Write-Progress -Activity "Windows Updates" -Status "Starting Services" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
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

#Check if the PS module is present or not and install it if not
Write-Progress -Activity "Windows Updates" -Status "Checking If Module Is Present" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100 
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
Write-Progress -Activity "Windows Updates" -Status "Checking For Updates" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100 
#Clear BITS queue before starting
bitsadmin.exe /reset /allusers
Import-Module PSWindowsUpdate
Get-WUInstall -MicrosoftUpdate | Out-File "$LogPath$Log - WU KBList.log" 
Write-Progress -Activity "Windows Updates" -Status "Installing Updates" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100 
	If($IncludeOfficeUpdates) {	
		If($ExcludedUpdates) {Install-WindowsUpdate -UpdateType Software -NotKBArticleID $Script:ExcludedUpdates -IgnoreReboot -AcceptAll}  
		Else {Install-WindowsUpdate -UpdateType Software -IgnoreReboot -AcceptAll}
	} Else {
		If($ExcludedUpdates) {Install-WindowsUpdate -UpdateType Software -MicrosoftUpdate -NotKBArticleID $Script:ExcludedUpdates -IgnoreReboot -AcceptAll}  
		Else {Install-WindowsUpdate -UpdateType Software -MicrosoftUpdate -IgnoreReboot -AcceptAll}
	}

#Update Windows Defender Definitions
Write-Progress -Activity "Windows Updates" -Status "Updating Defender Definitions" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100 
$NativeDefender = Test-Path -Path "C:\Program Files\Windows Defender\MpCmdRun.exe"
	If($NativeDefender -eq $true) {
	& "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -DynamicSignatures
	& "C:\Program Files\Windows Defender\MpCmdRun.exe" -SignatureUpdate
	} else { Write-Output "Native Defender Not Presetn. Skipping Definition Update"}

#--------------------INet Framework Queued Items and Update--------------------#
Write-Output "Inet Framework queued items and updates"
Write-Progress -Activity "Windows Updates" -Status "Inet2 Execute Queued Items x32" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
Write-Output "Inet framework v2 x32 Queued Items"
Start-Process "C:\Windows\Microsoft.Net\Framework\v2.0.50727\ngen.exe" -Args "executeQueuedItems" -Wait | Out-Null
Write-Progress -Activity "Windows Updates" -Status "Inet2 Execute Queued Items x64" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
Write-Output "Inet framework v2 x64 Queued Items"
Start-Process "C:\Windows\Microsoft.Net\Framework64\v2.0.50727\ngen.exe" -Args "executeQueuedItems" -Wait | Out-Null
Write-Progress -Activity "Windows Updates" -Status "Inet4 Execute Queued Items x32" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
Write-Output "Inet framework v4 x32 Queued Items"
Start-Process "C:\Windows\Microsoft.Net\Framework\v4.0.30319\ngen.exe" -Args "executeQueuedItems" -Wait | Out-Null
Write-Progress -Activity "Windows Updates" -Status "Inet4 Execute Queued Items x64" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
Write-Output "Inet framework v4 x64 Queued Items"
Start-Process "C:\Windows\Microsoft.Net\Framework64\v4.0.30319\ngen.exe" -Args "executeQueuedItems" -Wait | Out-Null
Write-Progress -Activity "Windows Updates" -Status "Inet2 Update x32" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
Write-Output "Inet framework v2 x32 Updating"
Start-Process "C:\Windows\Microsoft.Net\Framework\v2.0.50727\ngen.exe" -Args "update /force" -Wait | Out-Null
Write-Progress -Activity "Windows Updates" -Status "Inet2 Update x64" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
Write-Output "Inet framework v2 x64 Updating"
Start-Process "C:\Windows\Microsoft.Net\Framework64\v2.0.50727\ngen.exe" -Args "update /force" -Wait | Out-Null
Write-Progress -Activity "Windows Updates" -Status "Inet4 Update x32" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
Write-Output "Inet framework v4 x32 Updating"
Start-Process "C:\Windows\Microsoft.Net\Framework\v4.0.30319\ngen.exe" -Args "update /force" -Wait | Out-Null
Write-Progress -Activity "Windows Updates" -Status "Inet4 Update x64" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
Write-Output "Inet framework v4 x64 Updating"
Start-Process "C:\Windows\Microsoft.Net\Framework64\v4.0.30319\ngen.exe" -Args "update /force" -Wait | Out-Null

#Stop Services and then Disable them
Write-Progress -Activity "Windows Updates" -Status "Disabling Services" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100 
	Foreach($Matches in $WUServices) {
		If($Services -match $Matches) {
			Set-Service $Matches -StartupType Disabled
			Write-Output "Startup of service $Matches set to Disabled"
		} Else {Write-Output "$Matches not present"}
	}	
If((Test-Path $RegWuMedic) -eq $true) {Set-ItemProperty -Path $RegWuMedic -Name Start -Value 4 -Force -Passthru}
Set-ItemProperty -Path $RegWu -Name DisableWindowsUpdateAccess -Value 1 -Force -Passthru
Set-ItemProperty -Path $RegAu -Name NoAutoUpdate -Value 1 -Force -Passthru

Takeown /f "C:\Windows\System32\Tasks\Microsoft\Windows\WindowsUpdate\" /a /r /D y
Takeown /f "C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\" /a /r /D y
Icacls "C:\Windows\System32\Tasks\Microsoft\Windows\WindowsUpdate\" /grant administrators:F /T
Icacls "C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\" /grant administrators:F /T
$Tasks = Get-ScheduledTask
	#====================---------- Windows Updates ----------====================#
	If($Tasks -match "Scheduled Start") {Disable-ScheduledTask -TaskName "Scheduled Start" -TaskPath "\Microsoft\Windows\WindowsUpdate\"}
	If($Tasks -match "PlugScheduler") {Disable-ScheduledTask -TaskName "PlugScheduler" -TaskPath "\Microsoft\Windows\WindowsUpdate\RUXIM\"}
	If($Tasks -match "Schedule Scan") {Disable-ScheduledTask -TaskName "Schedule Scan" -TaskPath "\Microsoft\Windows\UpdateOrchestrator\"}
	If($Tasks -match "Schedule Scan Static Task") {Disable-ScheduledTask -TaskName "Schedule Scan Static Task" -TaskPath "\Microsoft\Windows\UpdateOrchestrator\"}
	If($Tasks -match "UpdateModelTask") {Disable-ScheduledTask -TaskName "UpdateModelTask" -TaskPath "\Microsoft\Windows\UpdateOrchestrator\"}
	If($Tasks -match "USO_UxBroker") {Disable-ScheduledTask -TaskName "USO_UxBroker" -TaskPath "\Microsoft\Windows\UpdateOrchestrator\"}
	If($Tasks -match "Schedule Maintenance Work") {Disable-ScheduledTask -TaskName "Schedule Maintenance Work" -TaskPath "\Microsoft\Windows\UpdateOrchestrator\"}
	If($Tasks -match "Schedule Work") {Disable-ScheduledTask -TaskName "Schedule Work" -TaskPath "\Microsoft\Windows\UpdateOrchestrator\"}
	If($Tasks -match "Schedule Wake To Work") {Disable-ScheduledTask -TaskName "Schedule Wake To Work" -TaskPath "\Microsoft\Windows\UpdateOrchestrator\"}
	If($Tasks -match "Reboot_AC") {Disable-ScheduledTask -TaskName "Reboot_AC" -TaskPath "\Microsoft\Windows\UpdateOrchestrator\"}
	If($Tasks -match "Reboot_Battery") {Disable-ScheduledTask -TaskName "Reboot_Battery" -TaskPath "\Microsoft\Windows\UpdateOrchestrator\"}
	If($Tasks -match "Report Policies") {Disable-ScheduledTask -TaskName "Report Policies" -TaskPath "\Microsoft\Windows\UpdateOrchestrator\"}
	If($Tasks -match "PerformRemediation") {Disable-ScheduledTask -TaskName "PerformRemediation" -TaskPath "\Microsoft\Windows\WaaSMedic\"}
	#====================---------- .Net Framework ----------====================#
	If($Tasks -match ".NET Framework NGEN v4.0.30319") {Disable-ScheduledTask -TaskName ".NET Framework NGEN v4.0.30319" -TaskPath "\Microsoft\Windows\.NET Framework"}
	If($Tasks -match ".NET Framework NGEN v4.0.30319 64") {Disable-ScheduledTask -TaskName ".NET Framework NGEN v4.0.30319 64" -TaskPath "\Microsoft\Windows\.NET Framework"}
	If($Tasks -match ".NET Framework NGEN v4.0.30319 Critical") {Disable-ScheduledTask -TaskName ".NET Framework NGEN v4.0.30319 Critical" -TaskPath "\Microsoft\Windows\.NET Framework"}
	If($Tasks -match ".NET Framework NGEN v4.0.30319 64 Critical") {Disable-ScheduledTask -TaskName ".NET Framework NGEN v4.0.30319 64 Critical" -TaskPath "\Microsoft\Windows\.NET Framework"}
Write-Output ""
Write-Output "====================---------- End of Windows Patching ----------===================="
Stop-Transcript

#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#End of patching tasks