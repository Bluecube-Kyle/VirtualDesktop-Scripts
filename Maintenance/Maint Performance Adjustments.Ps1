<#
-----Maintenance Performance Adjustments Script V2.0---------------
----------------Created by Kyle Baxter----------------

.Synopsis
Windows Performance Optimise Script

.Description
This script completes Performance Optimisations for windows desktops

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

$AutomaticService = "BrokerAgent,WSearch"
$ManualService = "Bits,DsmSvc,ClickToRunSvc"
$DisabledService = "Autotimesvc,CaptureService,CDPSvc,CDPUserSvc,DiagSvc,Defragsvc,DiagTrack,DPS,DusmSvc,icssvc,InstallService,lfsvc,MapsBroker,MessagingService,OneSyncSvc,PimIndexMaintenanceSvc,RmSvc,SEMgrSvc,SmsRouter,SmpHost,SysMain,TabletInputService,UsoSvc,PushToInstall,WMPNetworkSvc,WerSvc,WdiSystemHost,VSS,XblAuthManager,XblGameSave,XboxGipSvc,XboxNetApiSvc,Wuauserv,Uhssvc,gupdate,gupdatem,GoogleChromeElevationService,edgeupdate,edgeupdatem,MicrosoftEdgeElevationService,MozillaMaintenance,imUpdateManagerService"

#Start of Performance Optimisations tasks
#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Start-Transcript -Append  -Path "$LogPath$Log - Performance Tweaks.log" 
Write-Output "====================---------- Start Of Performance Optimisations ----------===================="
Write-Output ""

#Disable Services
Write-Output "====================---------- Disabling Unecessary Services ----------===================="
Write-Output ""
Write-Progress -Activity "Sealing Image" -Status "Disabling Services" -Id 1 -PercentComplete (($global:CurrentTask / $global:TotalTasks) * 100) ; $global:CurrentTask += 1
$Services = Get-Service | Select -Expand Name
$AutomaticService = $AutomaticService -Split ","
$Matches = Select-String $AutomaticService -Input $Services -AllMatches | Foreach {$_.matches} | Select -Expand Value 
Foreach($Matches in $AutomaticService) {
	If($Services -match $Matches) {
		Set-Service $Matches -StartupType Automatic
		Write-Output "Startup of service $Matches set to Automatic"
	} Else {Write-Output "$Matches not present"}
}
$ManualService = $ManualService -Split ","
$Matches = Select-String $ManualService -Input $Services -AllMatches | Foreach {$_.matches} | Select -Expand Value 
Foreach($Matches in $ManualService) {
	If($Services -match $Matches) {
		Set-Service $Matches -StartupType Manual
		Write-Output "Startup of service $Matches set to Manual"
	} Else {Write-Output "$Matches not present"}
}
$DisabledService = $DisabledService -Split ","
$Matches = Select-String $DisabledService -Input $Services -AllMatches | Foreach {$_.matches} | Select -Expand Value 
Foreach($Matches in $DisabledService) {
	If($Services -match $Matches) {
		Set-Service $Matches -StartupType Disabled
		Write-Output "Startup of service $Matches set to Disabled"
	} Else {Write-Output "$Matches not present"}
}
If($DisabledService -match "WaaSMedicSvc") {Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc' -Name Start -Value 4 -Force -PassThru}		
If($DisabledService -match "gupdate") { 
$GoogleUpdaterService = (Get-Service -DisplayName "GoogleUpdater Service*").Name
$GoogleUpdaterIntService = (Get-Service -DisplayName "GoogleUpdater InternalService*").Name
Get-Service -DisplayName "GoogleUpdaterService*" | Set-Service -StartupType Disabled		
Get-Service -DisplayName "GoogleUpdaterInternalService*" | Set-Service -StartupType Disabled
Write-Output "Startup of service $GoogleUpdaterService set to Disabled"
Write-Output "Startup of service $GoogleUpdaterIntService set to Disabled"
}
		
#Disabled Scheduled Tasks
Write-Output "====================---------- Disabling Unecessary Tasks ----------===================="
Write-Output ""
Write-Progress -Activity "Sealing Image" -Status "Disabling Scheduled Tasks" -Id 1 -PercentComplete (($global:CurrentTask / $global:TotalTasks) * 100) ; $global:CurrentTask += 1
Takeown /f "C:\Windows\System32\Tasks" /a /r /D y
Icacls "C:\Windows\System32\Tasks" /grant administrators:F /T
$Tasks = Get-ScheduledTask
	If($Tasks -match "Cellular") {Disable-ScheduledTask -TaskName "Cellular" -TaskPath "\Microsoft\Windows\Management\Provisioning\"}
	If($Tasks -match "Consolidator") {Disable-ScheduledTask -TaskName "Consolidator" -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\"}
	If($Tasks -match "Diagnostics") {Disable-ScheduledTask -TaskName "Diagnostics" -TaskPath "\Microsoft\Windows\DiskFootprint\"}
	If($Tasks -match "FamilySafetyMonitor") {Disable-ScheduledTask -TaskName "FamilySafetyMonitor" -TaskPath "\Microsoft\Windows\Shell\"}
	If($Tasks -match "FamilySafetyRefreshTask") {Disable-ScheduledTask -TaskName "FamilySafetyRefreshTask" -TaskPath "\Microsoft\Windows\Shell\"}
	If($Tasks -match "maintenancetasks") {Disable-ScheduledTask -TaskName "maintenancetasks" -TaskPath "\Microsoft\Windows\capabilityaccessmanager\"}
	If($Tasks -match "ProcessMemoryDiagnosticEvents") {Disable-ScheduledTask -TaskName "ProcessMemoryDiagnosticEvents" -TaskPath "Microsoft\Windows\MemoryDiagnostic"}
	If($Tasks -match "MaintenanceTasks") {Disable-ScheduledTask -TaskName "MaintenanceTasks" -TaskPath "\Microsoft\Windows\StateRepository\"}
	If($Tasks -match "MapsToastTask") {Disable-ScheduledTask -TaskName "MapsToastTask" -TaskPath "\Microsoft\Windows\Maps\"}
	If($Tasks -match "Microsoft-Windows-DiskDiagnosticDataCollector") {Disable-ScheduledTask -TaskName "Microsoft-Windows-DiskDiagnosticDataCollector" -TaskPath "\Microsoft\Windows\DiskDiagnostic\"}
	If($Tasks -match "NotificationTask") {Disable-ScheduledTask -TaskName "NotificationTask" -TaskPath "\Microsoft\Windows\WwanSvc\"}
	If($Tasks -match "ProactiveScan") {Disable-ScheduledTask -TaskName "ProactiveScan" -TaskPath "\Microsoft\Windows\Chkdsk\"}
	If($Tasks -match "ProcessMemoryDiagnosticEvents") {Disable-ScheduledTask -TaskName "ProcessMemoryDiagnosticEvents" -TaskPath "\Microsoft\Windows\MemoryDiagnostic\"}
	If($Tasks -match "Proxy") {Disable-ScheduledTask -TaskName "Proxy" -TaskPath "\Microsoft\Windows\Autochk\"}
	If($Tasks -match "RecommendedTroubleshootingScanner") {Disable-ScheduledTask -TaskName "RecommendedTroubleshootingScanner" -TaskPath "\Microsoft\Windows\Diagnosis\"}
	If($Tasks -match "ReconcileFeatures") {Disable-ScheduledTask -TaskName "ReconcileFeatures" -TaskPath "\Microsoft\Windows\Flighting\FeatureConfig\"}
	If($Tasks -match "ReconcileLanguageResources") {Disable-ScheduledTask -TaskName "ReconcileLanguageResources" -TaskPath "\Microsoft\Windows\LanguageComponentsInstaller\"}
	If($Tasks -match "RefreshCache") {Disable-ScheduledTask -TaskName "RefreshCache" -TaskPath "\Microsoft\Windows\Flighting\OneSettings\"}
	If($Tasks -match "RegIdleBackup") {Disable-ScheduledTask -TaskName "RegIdleBackup" -TaskPath "\Microsoft\Windows\Registry\"}
	If($Tasks -match "ResPriStaticDbSync") {Disable-ScheduledTask -TaskName "ResPriStaticDbSync" -TaskPath "\Microsoft\Windows\Sysmain\"}
	If($Tasks -match "RunFullMemoryDiagnostic") {Disable-ScheduledTask -TaskName "RunFullMemoryDiagnostic" -TaskPath "\Microsoft\Windows\MemoryDiagnostic\"}
	If($Tasks -match "ScanForUpdates") {Disable-ScheduledTask -TaskName "ScanForUpdates" -TaskPath "\Microsoft\Windows\InstallService\"}
	If($Tasks -match "ScanForUpdatesAsUser") {Disable-ScheduledTask -TaskName "ScanForUpdatesAsUser" -TaskPath "\Microsoft\Windows\InstallService\"}
	If($Tasks -match "Scheduled") {Disable-ScheduledTask -TaskName "Scheduled" -TaskPath "\Microsoft\Windows\Diagnosis\"}
	If($Tasks -match "ScheduledDefrag") {Disable-ScheduledTask -TaskName "ScheduledDefrag" -TaskPath "\Microsoft\Windows\Defrag\"}
	If($Tasks -match "SilentCleanup") {Disable-ScheduledTask -TaskName "SilentCleanup" -TaskPath "\Microsoft\Windows\DiskCleanup\"}
	If($Tasks -match "SpaceAgentTask") {Disable-ScheduledTask -TaskName "SpaceAgentTask" -TaskPath "\Microsoft\Windows\SpacePort\"}
	If($Tasks -match "SpaceManagerTask") {Disable-ScheduledTask -TaskName "SpaceManagerTask" -TaskPath "\Microsoft\Windows\SpacePort\"}
	If($Tasks -match "SR") {Disable-ScheduledTask -TaskName "SR" -TaskPath "\Microsoft\Windows\SystemRestore\"}
	If($Tasks -match "StartComponentCleanup") {Disable-ScheduledTask -TaskName "StartComponentCleanup" -TaskPath "\Microsoft\Windows\Servicing\"}
	If($Tasks -match "StartupAppTask") {Disable-ScheduledTask -TaskName "StartupAppTask" -TaskPath "\Microsoft\Windows\Application Experience\"}
	If($Tasks -match "StorageSense") {Disable-ScheduledTask -TaskName "StorageSense" -TaskPath "\Microsoft\Windows\DiskFootprint\"}
	If($Tasks -match "SyspartRepair") {Disable-ScheduledTask -TaskName "SyspartRepair" -TaskPath "\Microsoft\Windows\Chkdsk\"}
	If($Tasks -match "Sysprep Generalize Drivers") {Disable-ScheduledTask -TaskName "Sysprep Generalize Drivers" -TaskPath "\Microsoft\Windows\Plug and Play\"}
	If($Tasks -match "UpdateLibrary") {Disable-ScheduledTask -TaskName "UpdateLibrary" -TaskPath "\Microsoft\Windows\Windows Media Sharing\"}
	If($Tasks -match "UsbCeip") {Disable-ScheduledTask -TaskName "UsbCeip" -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\"}
	If($Tasks -match "Usb-Notifications") {Disable-ScheduledTask -TaskName "Usb-Notifications" -TaskPath "\Microsoft\Windows\USB\"}
	If($Tasks -match "WiFiTask") {Disable-ScheduledTask -TaskName "WiFiTask" -TaskPath "\Microsoft\Windows\WCM\"}
	If($Tasks -match "WindowsActionDialog") {Disable-ScheduledTask -TaskName "WindowsActionDialog" -TaskPath "\Microsoft\Windows\Location\"}
	If($Tasks -match "WinSAT") {Disable-ScheduledTask -TaskName "WinSAT" -TaskPath "\Microsoft\Windows\Maintenance\"}
	If($Tasks -match "WsSwapAssessmentTask") {Disable-ScheduledTask -TaskName "WsSwapAssessmentTask" -TaskPath "\Microsoft\Windows\Sysmain\"}
	If($Tasks -match "XblGameSaveTask") {Disable-ScheduledTask -TaskName "XblGameSaveTask" -TaskPath "\Microsoft\XblGameSave"}
	If($Tasks -match ".NET Framework NGEN v4.0.30319") {Disable-ScheduledTask -TaskName ".NET Framework NGEN v4.0.30319" -TaskPath "\Microsoft\Windows\.NET Framework"}
	If($Tasks -match ".NET Framework NGEN v4.0.30319 64") {Disable-ScheduledTask -TaskName ".NET Framework NGEN v4.0.30319 64" -TaskPath "\Microsoft\Windows\.NET Framework"}
	If($Tasks -match ".NET Framework NGEN v4.0.30319 Critical") {Disable-ScheduledTask -TaskName ".NET Framework NGEN v4.0.30319 Critical" -TaskPath "\Microsoft\Windows\.NET Framework"}
	If($Tasks -match ".NET Framework NGEN v4.0.30319 64 Critical") {Disable-ScheduledTask -TaskName ".NET Framework NGEN v4.0.30319 64 Critical" -TaskPath "\Microsoft\Windows\.NET Framework"}
	If($Tasks -match "Idle Maintenance") {Disable-ScheduledTask -TaskName "Idle Maintenance" -TaskPath "\Microsoft\Windows\TaskScheduler\"}
	If($Tasks -match "Regular Maintenance") {Disable-ScheduledTask -TaskName "Regular Maintenance" -TaskPath "\Microsoft\Windows\TaskScheduler\"}
	If($Tasks -match "Manual Maintenance") {Disable-ScheduledTask -TaskName "Manual Maintenance" -TaskPath "\Microsoft\Windows\TaskScheduler\"}
	If($Tasks -match "Maintenance Configurator") {Disable-ScheduledTask -TaskName "Maintenance Configurator" -TaskPath "\Microsoft\Windows\TaskScheduler\"}
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
	#====================---------- Office Apps ----------====================#
	If($Tasks -match "Office Automatic Updates 2.0") {Disable-ScheduledTask -TaskName "Office Automatic Updates 2.0" -TaskPath "\Microsoft\Office\"}
	If($Tasks -match "Office ClickToRun Service Monitor") {Disable-ScheduledTask -TaskName "Office ClickToRun Service Monitor" -TaskPath "\Microsoft\Office\"}
	If($Tasks -match "Office Feature Updates") {Disable-ScheduledTask -TaskName "Office Feature Updates" -TaskPath "\Microsoft\Office\"}
	If($Tasks -match "Office Feature Updates Logon") {Disable-ScheduledTask -TaskName "Office Feature Updates Logon" -TaskPath "\Microsoft\Office\"}
	If($Tasks -match "Office Serviceability Manager") {Disable-ScheduledTask -TaskName "Office Serviceability Manager" -TaskPath "\Microsoft\Office\"}
	If($Tasks -match "OfficeTelemetryAgentFallBack2016") {Disable-ScheduledTask -TaskName "OfficeTelemetryAgentFallBack2016" -TaskPath "\Microsoft\Office\"}
	If($Tasks -match "OfficeTelemetryAgentLogOn2016") {Disable-ScheduledTask -TaskName "OfficeTelemetryAgentLogOn2016" -TaskPath "\Microsoft\Office\"}
	#====================---------- Browsers ----------====================#
	If($Tasks -match "GoogleUpdateTaskMachineUA*") {Get-ScheduledTask -TaskName "GoogleUpdateTaskMachineUA*" | Disable-ScheduledTask}
	If($Tasks -match "GoogleUpdateTaskMachineCore*") {Get-ScheduledTask -TaskName "GoogleUpdateTaskMachineCore*" | Disable-ScheduledTask}
	If($Tasks -match "GoogleUpdaterTaskSystem*") {Get-ScheduledTask -TaskName "GoogleUpdaterTaskSystem*" | Disable-ScheduledTask}
	If($Tasks -match "MicrosoftEdgeUpdateTaskMachineCore") {Disable-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskMachineCore"}
	If($Tasks -match "MicrosoftEdgeUpdateTaskMachineUA") {Disable-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskMachineUA"}
	If($Tasks -match "MicrosoftEdgeUpdateBrowserReplacement") {Disable-ScheduledTask -TaskName "MicrosoftEdgeUpdateBrowserReplacementTask"}
	#====================---------- Applications ----------====================#
	If($Tasks -match "Adobe Acrobat Update Task") {Disable-ScheduledTask -TaskName "Adobe Acrobat Update Task"}
	If($Tasks -match "AutoRepair") {Get-ScheduledTask -TaskName "AutoRepair*" -TaskPath "\Sentinel\" | Disable-ScheduledTask}

#Setting System Registry Keys
Write-Output "====================---------- Applying Registry Settings ----------===================="
Write-Output ""
Write-Progress -Activity "Service Corrections" -Status "Adding System RegKeys" -Id 1 -PercentComplete (($global:CurrentTask / $global:TotalTasks) * 100) ; $global:CurrentTask += 1

$RegMaint = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance'
$RegDisableTaskOffload = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
$RegDisablePasswordChange = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
$RegNTFSDisableLastAccessUpdate = 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem'
$RegDisableLogonAnimation = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$RegWSearch = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
$RegWu = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
$RegAu = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
$RegFireFox = 'HKLM:\SOFTWARE\Policies\Mozilla\FireFox'
$RegAdobe = 'HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'
$WUUX = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
$WUUP = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings"
$TimeStart = (Get-Date).ToString("yyyy-MM-dd") + "T" +((Get-Date).AddHours(-1)).ToString("hh:mm:ss") + "Z"
$TimeEnd = ((Get-Date).AddYears(1)).ToString("yyyy-MM-dd") + "T12:00:00Z"
If(!(Test-Path $RegMaint)) {New-Item -Path $RegMaint -Force}
If(!(Test-Path $RegDisableTaskOffload)) {New-Item -Path $RegDisableTaskOffload -Force}
If(!(Test-Path $RegDisablePasswordChange)) {New-Item -Path $RegDisablePasswordChange -Force}
If(!(Test-Path $RegNTFSDisableLastAccessUpdate)) {New-Item -Path $RegNTFSDisableLastAccessUpdate -Force}
If(!(Test-Path $RegDisableLogonAnimation)) {New-Item -Path $RegDisableLogonAnimation -Force}
If(!(Test-Path $RegWSearch)) {New-Item -Path $RegWSearch -Force}
If(!(Test-Path $RegWu)) {New-Item -Path $RegWu -Force}
If(!(Test-Path $RegAu)) {New-Item -Path $RegAu -Force}
If(!(Test-Path $RegFireFox)) {New-Item -Path $RegFireFox -Force}
If(!(Test-Path $RegAdobe)) {New-Item -Path $RegAdobe -Force}
If(!(Test-Path $WUUX)) {New-Item -Path $WUUX -Force}
If(!(Test-Path $WUUP)) {New-Item -Path $WUUP -Force}
Set-ItemProperty -Path $RegMaint -Name "MaintenanceDisabled" -Value 1 -Type Dword -Force -PassThru
Set-ItemProperty -Path $RegDisableTaskOffload -Name "DisableTaskOffload" -Value 1 -Type Dword -Force
Set-ItemProperty -Path $RegDisablePasswordChange -Name "DisablePasswordChange" -Value 1 -Type Dword -Force
Set-ItemProperty -Path $RegNTFSDisableLastAccessUpdate -Name "NtfsDisableLastAccessUpdate" -Value 2147483651 -Type Dword -Force
Set-ItemProperty -Path $RegDisableLogonAnimation -Name "EnableFirstLogonAnimation" -Value 0 -Type Dword -Force
Set-ItemProperty -Path $RegWSearch -Name "AllowCortana" -Value 0 -Type Dword -Force -PassThru
Set-ItemProperty -Path $RegWSearch -Name "SetupCompletedSuccessfully" -Value 0 -Type Dword -Force -PassThru
Set-ItemProperty -Path $RegWu -Name "DisableWindowsUpdateAccess" -Value 1 -Type Dword -Force -PassThru
Set-ItemProperty -Path $RegAu -Name "NoAutoUpdate" -Value 1 -Type Dword -Force -PassThru
Set-ItemProperty -Path $RegFireFox -Name "DisableAppUpdate" -Value 1 -Type Dword -Force -PassThru
Set-ItemProperty -Path $RegAdobe -Name "bUpdater" -Value 0 -Type Dword -Force -PassThru	
Set-ItemProperty -Path $WUUX -Name "PauseFeatureUpdatesStartTime" -Type String -Value $TimeStart
Set-ItemProperty -Path $WUUX -Name "PauseQualityUpdatesStartTime" -Type String -Value $TimeStart
Set-ItemProperty -Path $WUUX -Name "PauseUpdatesStartTime" -Type String -Value $TimeStart
Set-ItemProperty -Path $WUUX -Name "PauseFeatureUpdatesEndTime" -Type String -Value $TimeEnd
Set-ItemProperty -Path $WUUX -Name "PauseQualityUpdatesEndTime" -Type String -Value $TimeEnd
Set-ItemProperty -Path $WUUX -Name "PauseUpdatesExpiryTime" -Type String -Value $TimeEnd
Set-ItemProperty -Path $WUUP -Name "PausedFeatureDate" -Type String -Value $TimeStart 
Set-ItemProperty -Path $WUUP -Name "PausedQualityDate" -Type String -Value $TimeStart 
Set-ItemProperty -Path $WUUP -Name "PausedFeatureStatus" -Type Dword -Value 1
Set-ItemProperty -Path $WUUP -Name "PausedQualityStatus" -Type Dword -Value 1

#Adjusts Default Ntuser.Dat settings to set for performance
Write-Output "====================---------- Adjusting Default NTUser.Dat ----------===================="
Write-Output ""
Write-Progress -Activity "Service Corrections" -Status "Adjusting Default NTUser.DAT" -Id 1 -PercentComplete (($global:CurrentTask / $global:TotalTasks) * 100) ; $global:CurrentTask += 1
	Reg Load HKLM\Temp C:\Users\Default\NTUSER.DAT
	Reg Add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer" /v ShellState /t REG_BINARY /d 240000003C2800000000000000000000 /f
	Reg Add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v IconsOnly /t REG_DWORD /d 1 /f
	Reg Add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ListviewAlphaSelect /t REG_DWORD /d 0 /f
	Reg Add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ListviewShadow /t REG_DWORD /d 0 /f
	Reg Add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowCompColor /t REG_DWORD /d 1 /f
	Reg Add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowInfoTip /t REG_DWORD /d 1 /f
	Reg Add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAnimations /t REG_DWORD /d 0 /f
	Reg Add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 3 /f
	Reg Add "HKLM\Temp\Software\Microsoft\Windows\DWM" /v EnableAeroPeek /t REG_DWORD /d 0 /f
	Reg Add "HKLM\Temp\Software\Microsoft\Windows\DWM" /v AlwaysHiberNateThumbnails /t REG_DWORD /d 0 /f
	Reg Add "HKLM\Temp\Control Panel\Desktop" /v DragFullWindows /t REG_SZ /d 0 /f
	Reg Add "HKLM\Temp\Control Panel\Desktop" /v FontSmoothing /t REG_SZ /d 2 /f
	Reg Add "HKLM\Temp\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9032078010000000 /f
	Reg Add "HKLM\Temp\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f
	Reg Add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 01 /t REG_DWORD /d 0 /f
	Reg Add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338393Enabled /t REG_DWORD /d 0 /f
	Reg Add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353694Enabled /t REG_DWORD /d 0 /f
	Reg Add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353696Enabled /t REG_DWORD /d 0 /f
	Reg Add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /t REG_DWORD /d 0 /f
	Reg Add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f
	Reg Add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
	Reg Add "HKLM\Temp\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f
	Reg Add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.Photos_8wekyb3d8bbwe" /v Disabled /t REG_DWORD /d 1 /f
	Reg Add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.Photos_8wekyb3d8bbwe" /v DisabledByUser /t REG_DWORD /d 1 /f
	Reg Add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.SkypeApp_kzf8qxf38zg5c" /v Disabled /t REG_DWORD /d 1 /f
	Reg Add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.SkypeApp_kzf8qxf38zg5c" /v DisabledByUser /t REG_DWORD /d 1 /f
	Reg Add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.YourPhone_8wekyb3d8bbwe" /v Disabled /t REG_DWORD /d 1 /f
	Reg Add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.YourPhone_8wekyb3d8bbwe" /v DisabledByUser /t REG_DWORD /d 1 /f
	Reg Add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" /v Disabled /t REG_DWORD /d 1 /f
	Reg Add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" /v DisabledByUser /t REG_DWORD /d 1 /f
	Reg Add "HKLM\Temp\Software\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f
	Reg Add "HKLM\Temp\Software\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f
	Reg Add "HKLM\Temp\Software\Microsoft\Personalization\Settings" /v AcceptedPrivacyPolicy /t REG_DWORD /d 0 /f
	Reg Add "HKLM\Temp\Software\Microsoft\InputPersonalization\TrainedDataStore" /v HarvestContacts /t REG_DWORD /d 0 /f
	Reg Add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v ScoobeSystemSettingEnabled /t REG_DWORD /d 0 /f
	Reg Unload HKLM\Temp

#Reset Performance Counters
Write-Output "====================---------- Reset System Performance Counters ----------===================="
Write-Output ""
Write-Progress -Activity "Sealing Image" -Status "Rebuild Perf Counters" -Id 1 -PercentComplete (($global:CurrentTask / $global:TotalTasks) * 100) ; $global:CurrentTask += 1
	If($Services -match "WinMgmt") {Stop-Service Wuauserv -Force}
	& "c:\windows\system32\lodctr" /R
	& "c:\windows\sysWOW64\lodctr" /R
	WinMgmt /RESYNCPERF
	
Write-Output ""
Write-Output "====================---------- End of Performance Optimisations ----------===================="
Stop-Transcript
#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#End of Performance Optimisation Tasks