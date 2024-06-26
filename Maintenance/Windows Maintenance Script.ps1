<#
---------------CTS Maintenance Script V1.2---------------
----------------Created by Kyle Baxter----------------

.Synopsis
Windows Patching Script to automatic monthly patching 

.Description


.LogFile
C:\CTS\UpdateLogs\Date\Hostname - Maintenance - Type.log
#>

#Create Required Directories
$Date = Get-Date -F yyyy-MM-dd
$LogPath = "C:\CTS\MaintenanceLogs\$Date\"   
$Log = "$ENV:ComputerName - Maintenance"
$Installs = "C:\CTS\Installers\"
	If(!(test-path -PathType container $LogPath)) {New-Item -ItemType Directory -Path $LogPath ; Write-Output "Created MaintLogs Path"}
	If(!(test-path -PathType container $Installs)) {New-Item -ItemType Directory -Path $Installs ; Write-Output "Created Installers Path"}

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

#Global Variables. Used for Progress bar
$global:CurrentTask = 0
$global:PercentComplete = 0
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Function OnlineRepair {
Start-Transcript -Append -Path "$LogPath$Log.log" 
Write-Output "====================---------- Start of Online Repairs ----------===================="
Write-Output ""

#--------------------Enable and Start Services--------------------#
Write-Output "Enabling OnlineRepair Services"
Write-Progress -Activity "Online System Repair" -Status "Starting Services" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
$Services = Get-Service
$MedicSvc = Test-Path -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc'
$WUAcess = Test-Path -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"
	If($Services -match "UsoSvc") {Set-Service UsoSvc -StartupType Manual -Passthru}
	If($Services -match "UsoSvc") {Start-Service UsoSvc -PassThru}
	If($Services -match "Wuauserv") {Set-Service Wuauserv -StartupType Manual -Passthru}
	If($Services -match "Wuauserv") {Start-Service Wuauserv -PassThru}
	If($Services -match "TrustedInstaller") {Set-Service TrustedInstaller -StartupType Manual -Passthru}
	If($Services -match "VSS") {Set-Service VSS -StartupType Manual -Passthru}
	If($Services -match "VSS") {Start-Service VSS -PassThru}
	If($Services -match "SmpHost") {Set-Service SmpHost -StartupType Manual -Passthru}
	If($Services -match "SmpHost") {Start-Service SmpHost -PassThru}	
	If($MedicSvc -eq $true) {Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc' -Name Start -Value 3 -Force -Passthru}
	If($WUAcess -eq $true) {Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -Name DisableWindowsUpdateAccess -Value 0 -Force -Passthru}

#--------------------Wmi Repository Rebuild--------------------#
Write-Progress -Activity "Online System Repair" -Status "Repair WMI Repository" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
Write-Output "---Rebuild WMI Repository---"	
	If($Services -match "WinMgmt") {Set-Service WinMgmt -StartupType Disabled -Passthru}
	If($Services -match "WinMgmt") {Stop-Service WinMgmt -PassThru -Force}
Start-Sleep 3
Start-Process WinMgmt -Args "/salvagerepository %windir%\System32\wbem" -Wait
Start-Process WinMgmt -Args "/resetrepository %windir%\System32\wbem" -Wait
	If($Services -match "WinMgmt") {Set-Service WinMgmt -StartupType Manual -Passthru}
Start-Sleep 3

#--------------------SFC Scan and Repair--------------------#
Write-Progress -Activity "Online System Repair" -Status "Scanning System Health" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
Sfc /Scannow 
#--------------------Dism Image Repair--------------------#
Write-Progress -Activity "Online System Repair" -Status "Repairing Image" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
Dism /Online /Cleanup-Image /RestoreHealth
Write-Progress -Activity "Online System Repair" -Status "Cleaning Mount Points" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
Dism /Cleanup-MountPoints 
Write-Progress -Activity "Online System Repair" -Status "Cleaning Mount Points" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
Clear-WindowsCorruptMountPoint

#--------------------Check Disk Scan and Repair--------------------#
Write-Output "Chckdisk scan"
Write-Progress -Activity "Online System Repair" -Status "Repairing C Volume" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
Repair-Volume -DriveLetter C -OfflineScanAndFix  
$SystemReserved = Get-Volume
Write-Progress -Activity "Online System Repair" -Status "Repairing Protected Volume" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
if ($SystemReserved -match "System Reserved") {
Repair-Volume -FileSystemLabel "System Reserved" -OfflineScanAndFix}

#--------------------Rebuild Performance Counters--------------------#
Write-Progress -Activity "Online System Repair" -Status "Rebuild Perf Counters" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
Start-Process "c:\windows\system32\lodctr" -Args "/R" -Wait
Start-Process "c:\windows\sysWOW64\lodctr" -Args "/R" -Wait
Start-Process WinMgmt -Args "/RESYNCPERF" -Wait

#--------------------Stop and Disable Services--------------------#
Write-Output "Stopping OnlineRepair Services"
Write-Progress -Activity "Online System Repair" -Status "Stopping Services" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
	If($Services -match "UsoSvc") {Set-Service UsoSvc -StartupType Disabled -Passthru}
	If($Services -match "UsoSvc") {Stop-Service UsoSvc -PassThru -Force}
	If($Services -match "Wuauserv") {Set-Service Wuauserv -StartupType Disabled -Passthru}
	If($Services -match "Wuauserv") {Stop-Service Wuauserv -PassThru -Force}
	If($Services -match "TrustedInstaller") {Set-Service TrustedInstaller -StartupType Disabled -Passthru}
	If($Services -match "VSS") {Set-Service VSS -StartupType Disabled -Passthru}
	If($Services -match "VSS") {Stop-Service VSS -PassThru -Force}
	If($Services -match "SmpHost") {Set-Service SmpHost -StartupType Disabled -Passthru}
	If($Services -match "SmpHost") {Stop-Service SmpHost -PassThru -Force}	
	If($MedicSvc -eq $true) {Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc' -Name Start -Value 4 -Force -Passthru}
	If($WUAcess -eq $true) {Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -Name DisableWindowsUpdateAccess -Value 1 -Force -Passthru}

Write-Output ""
Write-Output "====================---------- End of Online Repairs ----------===================="
Stop-Transcript
}

Function OfflineRepair {
Start-Transcript -Append -Path "$LogPath$Log.log" 
Write-Output "====================---------- Start of Offline Repairs ----------===================="
Write-Output ""

#--------------------Enable and Start Services--------------------#
Write-Output "Enabling OfflineRepair Services"
Write-Progress -Activity "Offline System Repair" -Status "Starting Services" -Id 1 -PercentComplete 0 ; $global:CurrentTask += 1 ; $PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
$Services = Get-Service
$MedicSvc = Test-Path -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc'
$WUAcess = Test-Path -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"
	If($Services -match "UsoSvc") {Set-Service UsoSvc -StartupType Manual -Passthru}
	If($Services -match "UsoSvc") {Start-Service UsoSvc -PassThru}
	If($Services -match "Wuauserv") {Set-Service Wuauserv -StartupType Manual -Passthru}
	If($Services -match "Wuauserv") {Start-Service Wuauserv -PassThru}
	If($Services -match "TrustedInstaller") {Set-Service TrustedInstaller -StartupType Manual -Passthru}
	If($Services -match "VSS") {Set-Service VSS -StartupType Manual -Passthru}
	If($Services -match "VSS") {Start-Service VSS -PassThru}
	If($Services -match "SmpHost") {Set-Service SmpHost -StartupType Manual -Passthru}
	If($Services -match "SmpHost") {Start-Service SmpHost -PassThru}	
	If($MedicSvc -eq $true) {Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc' -Name Start -Value 3 -Force -Passthru}
	If($WUAcess -eq $true) {Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -Name DisableWindowsUpdateAccess -Value 0 -Force -Passthru}

#--------------------Wmi Repository Rebuild--------------------#
Write-Progress -Activity "Online System Repair" -Status "Repair WMI Repository" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
Write-Output "---Rebuild WMI Repository---"	
	If($Services -match "WinMgmt") {Set-Service WinMgmt -StartupType Disabled -Passthru}
	If($Services -match "WinMgmt") {Stop-Service WinMgmt -PassThru -Force}
Start-Sleep 3
Start-Process WinMgmt -Args "/salvagerepository %windir%\System32\wbem" -Wait
Start-Process WinMgmt -Args "/resetrepository %windir%\System32\wbem" -Wait
	If($Services -match "WinMgmt") {Set-Service WinMgmt -StartupType Manual -Passthru}
Start-Sleep 3

#--------------------SFC Scan and Repair--------------------#	
Write-Progress -Activity "Offline System Repair" -Status "Scanning System Health" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
Sfc /Scannow	
#--------------------Dism Image Repair--------------------#
Write-Progress -Activity "Offline System Repair" -Status "Acquiring OS information" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
$OperatingSystem = systeminfo | findstr /B /C:"OS Name" /B /C:"OS Version"
$OperatingSystem
Write-Progress -Activity "Offline System Repair" -Status "Downloading OS Iso File" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
$ProgressPreference = 'SilentlyContinue'
	#Dism Repair using local Iso file (Win2016)
	If($OperatingSystem -match "Windows Server 2016") {
	Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/p/?LinkID=2195174&clcid=0x409&culture=en-us&country=US" -OutFile "C:\CTS\Installers\WinServer2016.iso"
	$IsoPath = "C:\CTS\Installers\WinServer2016.iso"
	}	
	#Dism Repair using local Iso file (Win2019)
	If($OperatingSystem -match "Windows Server 2019") {
	Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/p/?LinkID=2195167&clcid=0x409&culture=en-us&country=US" -OutFile "C:\CTS\Installers\WinServer2019.iso"	
	$IsoPath = "C:\CTS\Installers\WinServer2019.iso"	
	}
	#Dism Repair using local Iso file (Win2022)
	If($OperatingSystem -match "Windows Server 2022") {
	Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/p/?LinkID=2195280&clcid=0x409&culture=en-us&country=US" -OutFile "C:\CTS\Installers\WinServer2022.iso"	
	$IsoPath = "C:\CTS\Installers\WinServer2022.iso"	
	}
	#Dism Repair using local Iso file (Win10 Enterprise)
	If($OperatingSystem -match "Windows 10 Enterprise") {
	Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/p/?LinkID=2208844&clcid=0x409&culture=en-us&country=US" -OutFile "C:\CTS\Installers\Win10E.iso"	
	$IsoPath = "C:\CTS\Installers\Win10E.iso"	
	}
	#Dism Repair using local Iso file (Win10 Pro)
	If($OperatingSystem -match "Windows 10 Pro") {
	Invoke-WebRequest -Uri "https://www.itechtics.com/?dl_id=173" -OutFile "C:\CTS\Installers\Win10Pro.iso"	
	$IsoPath = "C:\CTS\Installers\Win10Pro.iso"	
	}	
$ProgressPreference = 'Continue'
Write-Output "Mounting Iso Image"
Write-Progress -Activity "Offline System Repair" -Status "Mounting Iso" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
$IsoDrive = Mount-DiskImage -ImagePath $IsoPath -PassThru
$IsoLetter = ($IsoDrive | Get-Volume).DriveLetter
Write-Output "Beginning Repair with local ISO"
Write-Progress -Activity "Offline System Repair" -Status "Repairing Image with Iso" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
Dism /Online /Cleanup-Image /RestoreHealth /Source:"$IsoLetter":\Sources\Install.Wim /LimitAccess
Write-Progress -Activity "Machine Maintenance" -Status "Removing Files" -Id 1 -PercentComplete 100
Dismount-DiskImage -ImagePath $IsoPath
Remove-Item -Path $IsoPath -Force
#Dism Clear MountPoints
Write-Progress -Activity "Offline System Repair" -Status "Cleaning System Mountpoints" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
Dism /Cleanup-MountPoints
Clear-WindowsCorruptMountPoint

#--------------------Check Disk Scan and Repair--------------------#
Write-Progress -Activity "Offline System Repair" -Status "Repairing C Volume" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
Write-Output "Chckdisk scan"
Repair-Volume -DriveLetter C -OfflineScanAndFix
$SystemReserved = Get-Volume
Write-Progress -Activity "Offline System Repair" -Status "Repairing Protected Volume" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
if ($SystemReserved -match "System Reserved") {
Repair-Volume -FileSystemLabel "System Reserved" -OfflineScanAndFix }

#--------------------Rebuild Performance Counters--------------------#
Write-Progress -Activity "Offline System Repair" -Status "Rebuild Perf Counters" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
Start-Process "c:\windows\system32\lodctr" -Args "/R" -Wait
Start-Process "c:\windows\sysWOW64\lodctr" -Args "/R" -Wait
Start-Process WinMgmt -Args "/RESYNCPERF" -Wait

#--------------------Stop and Disable Services--------------------#
Write-Output "Stopping OfflineRepair Services"
Write-Progress -Activity "Offline System Repair" -Status "Stopping Services" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
	If($Services -match "UsoSvc") {Set-Service UsoSvc -StartupType Disabled -Passthru}
	If($Services -match "UsoSvc") {Stop-Service UsoSvc -PassThru -Force}
	If($Services -match "Wuauserv") {Set-Service Wuauserv -StartupType Disabled -Passthru}
	If($Services -match "Wuauserv") {Stop-Service Wuauserv -PassThru -Force}
	If($Services -match "TrustedInstaller") {Set-Service TrustedInstaller -StartupType Disabled -Passthru}
	If($Services -match "VSS") {Set-Service VSS -StartupType Disabled -Passthru}
	If($Services -match "VSS") {Stop-Service VSS -PassThru -Force}
	If($Services -match "SmpHost") {Set-Service SmpHost -StartupType Disabled -Passthru}
	If($Services -match "SmpHost") {Stop-Service SmpHost -PassThru -Force}	
	If($MedicSvc -eq $true) {Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc' -Name Start -Value 4 -Force -Passthru}
	If($WUAcess -eq $true) {Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -Name DisableWindowsUpdateAccess -Value 1 -Force -Passthru}

Write-Output ""
Write-Output "====================---------- End of Offline Repairs ----------===================="
Stop-Transcript
}

Function ServiceCorrections {
Start-Transcript -Append -Path "$LogPath$Log.log" 
Write-Output "====================---------- Start of Service Corrections ----------===================="
Write-Output ""

#--------------------Disable Unecessary Services--------------------#
Write-Output "Disabling Services For VDI Performance"
Write-Progress -Activity "Service Corrections" -Status "Disabling Services" -Id 1 -PercentComplete 0 ; $global:CurrentTask += 1 ; $PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
$Services = Get-Service
	if($Services -match "autotimesvc") {Set-Service autotimesvc -StartupType Disabled -PassThru}
	if($Services -match "autotimesvc") {Stop-Service autotimesvc -Force -PassThru}
	if($Services -match "CaptureService") {Set-Service CaptureService -StartupType Disabled -PassThru}
	if($Services -match "CaptureService") {Stop-Service CaptureService -Force -PassThru}
	if($Services -match "CDPSvc") {Set-Service CDPSvc -StartupType Disabled -PassThru}
	if($Services -match "CDPSvc") {Stop-Service CDPSvc -Force -PassThru}
	if($Services -match "CDPUserSvc") {Set-Service CDPUserSvc -StartupType Disabled -PassThru}
	if($Services -match "CDPUserSvc") {Stop-Service CDPUserSvc -Force -PassThru}
	if($Services -match "DiagSvc") {Set-Service DiagSvc -StartupType Disabled -PassThru}
	if($Services -match "DiagSvc") {Stop-Service DiagSvc -Force -PassThru}
	if($Services -match "Defragsvc") {Set-Service Defragsvc -StartupType Disabled -PassThru}
	if($Services -match "Defragsvc") {Stop-Service Defragsvc -Force -PassThru}
	if($Services -match "DiagTrack") {Set-Service DiagTrack -StartupType Disabled -PassThru}
	if($Services -match "DiagTrack") {Stop-Service DiagTrack -Force -PassThru}
	if($Services -match "DsmSvc") {Set-Service DsmSvc -StartupType Manual -PassThru}
	if($Services -match "DPS") {Set-Service DPS -StartupType Disabled -PassThru}
	if($Services -match "DPS") {Stop-Service DPS -Force -PassThru}
	if($Services -match "DusmSvc") {Set-Service DusmSvc -StartupType Disabled -PassThru}
	if($Services -match "DusmSvc") {Stop-Service DusmSvc -Force -PassThru}
	if($Services -match "icssvc") {Set-Service icssvc -StartupType Disabled -PassThru}
	if($Services -match "icssvc") {Stop-Service icssvc -Force -PassThru}
	if($Services -match "InstallService") {Set-Service InstallService -StartupType Disabled -PassThru}
	if($Services -match "InstallService") {Stop-Service InstallService -Force -PassThru}
	if($Services -match "lfsvc") {Set-Service lfsvc -StartupType Disabled -PassThru}
	if($Services -match "lfsvc") {Stop-Service lfsvc -Force -PassThru}
	if($Services -match "MapsBroker") {Set-Service MapsBroker -StartupType Disabled -PassThru}
	if($Services -match "MapsBroker") {Stop-Service MapsBroker -Force -PassThru}
	if($Services -match "MessagingService") {Set-Service MessagingService -StartupType Disabled -PassThru}
	if($Services -match "MessagingService") {Stop-Service MessagingService -Force -PassThru}
	if($Services -match "OneSyncSvc") {Set-Service OneSyncSvc -StartupType Disabled -PassThru}
	if($Services -match "OneSyncSvc") {Stop-Service OneSyncSvc -Force -PassThru}
	if($Services -match "PimIndexMaintenanceSvc") {Set-Service PimIndexMaintenanceSvc -StartupType Disabled -PassThru}
	if($Services -match "PimIndexMaintenanceSvc") {Stop-Service PimIndexMaintenanceSvc -Force -PassThru}
	if($Services -match "RmSvc") {Set-Service RmSvc -StartupType Disabled -PassThru}
	if($Services -match "RmSvc") {Stop-Service RmSvc -Force -PassThru}
	if($Services -match "SEMgrSvc") {Set-Service SEMgrSvc -StartupType Disabled -PassThru}
	if($Services -match "SEMgrSvc") {Stop-Service SEMgrSvc -Force -PassThru}
	if($Services -match "SmsRouter") {Set-Service SmsRouter -StartupType Disabled -PassThru}
	if($Services -match "SmsRouter") {Stop-Service SmsRouter -Force -PassThru}
	if($Services -match "SmpHost") {Set-Service VSS -StartupType Disabled -PassThru}
	if($Services -match "SmpHost") {Stop-Service SmpHost -Force -PassThru}
	if($Services -match "SysMain") {Set-Service SysMain -StartupType Disabled -PassThru}
	if($Services -match "SysMain") {Stop-Service SysMain -Force -PassThru}
	if($Services -match "TabletInputService") {Set-Service TabletInputService -StartupType Disabled -PassThru}
	if($Services -match "TabletInputService") {Stop-Service TabletInputService -Force -PassThru}
	if($Services -match "UsoSvc") {Set-Service UsoSvc -StartupType Disabled -PassThru}
	if($Services -match "UsoSvc") {Stop-Service UsoSvc -Force -PassThru}
	if($Services -match "WSearch") {Set-Service WSearch -StartupType Disabled -PassThru}
	if($Services -match "WSearch") {Stop-Service WSearch -Force -PassThru}
	if($Services -match "WMPNetworkSvc") {Set-Service WMPNetworkSvc -StartupType Disabled -PassThru}
	if($Services -match "WMPNetworkSvc") {Stop-Service WMPNetworkSvc -Force -PassThru}
	if($Services -match "WerSvc") {Set-Service WerSvc -StartupType Disabled -PassThru}
	if($Services -match "WerSvc") {Stop-Service WerSvc -Force -PassThru}
	if($Services -match "WdiSystemHost") {Set-Service WdiSystemHost -StartupType Disabled -PassThru}
	if($Services -match "WdiSystemHost") {Stop-Service WdiSystemHost -Force -PassThru}
	if($Services -match "VSS") {Set-Service VSS -StartupType Disabled -PassThru}
	if($Services -match "VSS") {Stop-Service VSS -Force -PassThru}
	if($Services -match "XblAuthManager") {Set-Service XblAuthManager -StartupType Disabled -PassThru}
	if($Services -match "XblAuthManager") {Stop-Service XblAuthManager -Force -PassThru}
	if($Services -match "XblGameSave") {Set-Service XblGameSave -StartupType Disabled -PassThru}
	if($Services -match "XblGameSave") {Stop-Service XblGameSave -Force -PassThru}
	if($Services -match "XboxGipSvc") {Set-Service XboxGipSvc -StartupType Disabled -PassThru}
	if($Services -match "XboxGipSvc") {Stop-Service XboxGipSvc -Force -PassThru}
	if($Services -match "XboxNetApiSvc") {Set-Service XboxNetApiSvc -StartupType Disabled -PassThru}
	if($Services -match "XboxNetApiSvc") {Stop-Service XboxNetApiSvc -Force -PassThru}
	if($Services -match "Wuauserv") {Set-Service Wuauserv -StartupType Disabled -PassThru}
	if($Services -match "Wuauserv") {Stop-Service Wuauserv -Force -PassThru}
	if($Services -match "WaaSMedicSvc") {Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc' -Name Start -Value 4 -Force -PassThru}

#--------------------Disable Unecessary Tasks--------------------#
Write-Output "Disabling Automatic Tasks Not Required For VDI"
Write-Progress -Activity "Service Corrections" -Status "Disabling Scheduled Tasks" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
$Tasks = Get-ScheduledTask
	if($Tasks -match "Cellular") {Disable-ScheduledTask -TaskName "Cellular" -TaskPath "\Microsoft\Windows\Management\Provisioning\"}
	if($Tasks -match "Consolidator") {Disable-ScheduledTask -TaskName "Consolidator" -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\"}
	if($Tasks -match "Diagnostics") {Disable-ScheduledTask -TaskName "Diagnostics" -TaskPath "\Microsoft\Windows\DiskFootprint\"}
	if($Tasks -match "FamilySafetyMonitor") {Disable-ScheduledTask -TaskName "FamilySafetyMonitor" -TaskPath "\Microsoft\Windows\Shell\"}
	if($Tasks -match "FamilySafetyRefreshTask") {Disable-ScheduledTask -TaskName "FamilySafetyRefreshTask" -TaskPath "\Microsoft\Windows\Shell\"}
	#if($Tasks -match "maintenancetasks") {Disable-ScheduledTask -TaskName "maintenancetasks" -TaskPath "\Microsoft\Windows\capabilityaccessmanager\"}
	if($Tasks -match "ProcessMemoryDiagnosticEvents") {Disable-ScheduledTask -TaskName "ProcessMemoryDiagnosticEvents" -TaskPath "Microsoft\Windows\MemoryDiagnostic"}
	if($Tasks -match "MaintenanceTasks") {Disable-ScheduledTask -TaskName "MaintenanceTasks" -TaskPath "\Microsoft\Windows\StateRepository\"}
	if($Tasks -match "MapsToastTask") {Disable-ScheduledTask -TaskName "MapsToastTask" -TaskPath "\Microsoft\Windows\Maps\"}
	if($Tasks -match "Microsoft-Windows-DiskDiagnosticDataCollector") {Disable-ScheduledTask -TaskName "Microsoft-Windows-DiskDiagnosticDataCollector" -TaskPath "\Microsoft\Windows\DiskDiagnostic\"}
	if($Tasks -match "NotificationTask") {Disable-ScheduledTask -TaskName "NotificationTask" -TaskPath "\Microsoft\Windows\WwanSvc\"}
	if($Tasks -match "ProactiveScan") {Disable-ScheduledTask -TaskName "ProactiveScan" -TaskPath "\Microsoft\Windows\Chkdsk\"}
	if($Tasks -match "ProcessMemoryDiagnosticEvents") {Disable-ScheduledTask -TaskName "ProcessMemoryDiagnosticEvents" -TaskPath "\Microsoft\Windows\MemoryDiagnostic\"}
	if($Tasks -match "Proxy") {Disable-ScheduledTask -TaskName "Proxy" -TaskPath "\Microsoft\Windows\Autochk\"}
	if($Tasks -match "RecommendedTroubleshootingScanner") {Disable-ScheduledTask -TaskName "RecommendedTroubleshootingScanner" -TaskPath "\Microsoft\Windows\Diagnosis\"}
	if($Tasks -match "ReconcileFeatures") {Disable-ScheduledTask -TaskName "ReconcileFeatures" -TaskPath "\Microsoft\Windows\Flighting\FeatureConfig\"}
	if($Tasks -match "ReconcileLanguageResources") {Disable-ScheduledTask -TaskName "ReconcileLanguageResources" -TaskPath "\Microsoft\Windows\LanguageComponentsInstaller\"}
	if($Tasks -match "RefreshCache") {Disable-ScheduledTask -TaskName "RefreshCache" -TaskPath "\Microsoft\Windows\Flighting\OneSettings\"}
	if($Tasks -match "RegIdleBackup") {Disable-ScheduledTask -TaskName "RegIdleBackup" -TaskPath "\Microsoft\Windows\Registry\"}
	if($Tasks -match "ResPriStaticDbSync") {Disable-ScheduledTask -TaskName "ResPriStaticDbSync" -TaskPath "\Microsoft\Windows\Sysmain\"}
	if($Tasks -match "RunFullMemoryDiagnostic") {Disable-ScheduledTask -TaskName "RunFullMemoryDiagnostic" -TaskPath "\Microsoft\Windows\MemoryDiagnostic\"}
	if($Tasks -match "ScanForUpdates") {Disable-ScheduledTask -TaskName "ScanForUpdates" -TaskPath "\Microsoft\Windows\InstallService\"}
	if($Tasks -match "ScanForUpdatesAsUser") {Disable-ScheduledTask -TaskName "ScanForUpdatesAsUser" -TaskPath "\Microsoft\Windows\InstallService\"}
	if($Tasks -match "Scheduled") {Disable-ScheduledTask -TaskName "Scheduled" -TaskPath "\Microsoft\Windows\Diagnosis\"}
	if($Tasks -match "ScheduledDefrag") {Disable-ScheduledTask -TaskName "ScheduledDefrag" -TaskPath "\Microsoft\Windows\Defrag\"}
	if($Tasks -match "SilentCleanup") {Disable-ScheduledTask -TaskName "SilentCleanup" -TaskPath "\Microsoft\Windows\DiskCleanup\"}
	if($Tasks -match "SpaceAgentTask") {Disable-ScheduledTask -TaskName "SpaceAgentTask" -TaskPath "\Microsoft\Windows\SpacePort\"}
	if($Tasks -match "SpaceManagerTask") {Disable-ScheduledTask -TaskName "SpaceManagerTask" -TaskPath "\Microsoft\Windows\SpacePort\"}
	if($Tasks -match "SR") {Disable-ScheduledTask -TaskName "SR" -TaskPath "\Microsoft\Windows\SystemRestore\"}
	if($Tasks -match "StartComponentCleanup") {Disable-ScheduledTask -TaskName "StartComponentCleanup" -TaskPath "\Microsoft\Windows\Servicing\"}
	if($Tasks -match "StartupAppTask") {Disable-ScheduledTask -TaskName "StartupAppTask" -TaskPath "\Microsoft\Windows\Application Experience\"}
	if($Tasks -match "StorageSense") {Disable-ScheduledTask -TaskName "StorageSense" -TaskPath "\Microsoft\Windows\DiskFootprint\"}
	#if($Tasks -match "SyspartRepair") {Disable-ScheduledTask -TaskName "SyspartRepair" -TaskPath "\Microsoft\Windows\Chkdsk\"}
	if($Tasks -match "Sysprep Generalize Drivers") {Disable-ScheduledTask -TaskName "Sysprep Generalize Drivers" -TaskPath "\Microsoft\Windows\Plug and Play\"}
	if($Tasks -match "UpdateLibrary") {Disable-ScheduledTask -TaskName "UpdateLibrary" -TaskPath "\Microsoft\Windows\Windows Media Sharing\"}
	if($Tasks -match "UsbCeip") {Disable-ScheduledTask -TaskName "UsbCeip" -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\"}
	if($Tasks -match "Usb-Notifications") {Disable-ScheduledTask -TaskName "Usb-Notifications" -TaskPath "\Microsoft\Windows\USB\"}
	if($Tasks -match "WiFiTask") {Disable-ScheduledTask -TaskName "WiFiTask" -TaskPath "\Microsoft\Windows\WCM\"}
	if($Tasks -match "WindowsActionDialog") {Disable-ScheduledTask -TaskName "WindowsActionDialog" -TaskPath "\Microsoft\Windows\Location\"}
	if($Tasks -match "WinSAT") {Disable-ScheduledTask -TaskName "WinSAT" -TaskPath "\Microsoft\Windows\Maintenance\"}
	if($Tasks -match "WsSwapAssessmentTask") {Disable-ScheduledTask -TaskName "WsSwapAssessmentTask" -TaskPath "\Microsoft\Windows\Sysmain\"}
	if($Tasks -match "XblGameSaveTask") {Disable-ScheduledTask -TaskName "XblGameSaveTask" -TaskPath "\Microsoft\XblGameSave"}
	if($Tasks -match ".NET Framework NGEN v4.0.30319") {Disable-ScheduledTask -TaskName ".NET Framework NGEN v4.0.30319" -TaskPath "\Microsoft\Windows\.NET Framework"}
	if($Tasks -match ".NET Framework NGEN v4.0.30319 64") {Disable-ScheduledTask -TaskName ".NET Framework NGEN v4.0.30319 64" -TaskPath "\Microsoft\Windows\.NET Framework"}
	if($Tasks -match ".NET Framework NGEN v4.0.30319 Critical") {Disable-ScheduledTask -TaskName ".NET Framework NGEN v4.0.30319 Critical" -TaskPath "\Microsoft\Windows\.NET Framework"}
	if($Tasks -match ".NET Framework NGEN v4.0.30319 64 Critical") {Disable-ScheduledTask -TaskName ".NET Framework NGEN v4.0.30319 64 Critical" -TaskPath "\Microsoft\Windows\.NET Framework"}
	if($Tasks -match "Idle Maintenance") {Disable-ScheduledTask -TaskName "Idle Maintenance" -TaskPath "\Microsoft\Windows\TaskScheduler\"}
	if($Tasks -match "Regular Maintenance") {Disable-ScheduledTask -TaskName "Regular Maintenance" -TaskPath "\Microsoft\Windows\TaskScheduler\"}
	if($Tasks -match "Manual Maintenance") {Disable-ScheduledTask -TaskName "Manual Maintenance" -TaskPath "\Microsoft\Windows\TaskScheduler\"}
	if($Tasks -match "Maintenance Configurator") {Disable-ScheduledTask -TaskName "Maintenance Configurator" -TaskPath "\Microsoft\Windows\TaskScheduler\"}
	if($Tasks -match "Office Automatic Updates 2.0") {Disable-ScheduledTask -TaskName "Office Automatic Updates 2.0" -TaskPath "\Microsoft\Office\"}
	if($Tasks -match "Office ClickToRun Service Monitor") {Disable-ScheduledTask -TaskName "Office ClickToRun Service Monitor" -TaskPath "\Microsoft\Office\"}
	if($Tasks -match "Office Feature Updates") {Disable-ScheduledTask -TaskName "Office Feature Updates" -TaskPath "\Microsoft\Office\"}
	if($Tasks -match "Office Feature Updates Logon") {Disable-ScheduledTask -TaskName "Office Feature Updates Logon" -TaskPath "\Microsoft\Office\"}
	if($Tasks -match "Office Serviceability Manager") {Disable-ScheduledTask -TaskName "Office Serviceability Manager" -TaskPath "\Microsoft\Office\"}
	if($Tasks -match "OfficeTelemetryAgentFallBack2016") {Disable-ScheduledTask -TaskName "OfficeTelemetryAgentFallBack2016" -TaskPath "\Microsoft\Office\"}
	if($Tasks -match "OfficeTelemetryAgentLogOn2016") {Disable-ScheduledTask -TaskName "OfficeTelemetryAgentLogOn2016" -TaskPath "\Microsoft\Office\"}
$TaskName1Google = "GoogleUpdateTaskMachineCore" + "*"
$TaskName2Google = "GoogleUpdateTaskMachineUA" + "*"
$GoogleUpdateTaskMachineCore = Get-ScheduledTask -TaskName $TaskName1Google
$GoogleUpdateTaskMachineUA = Get-ScheduledTask -TaskName $TaskName2Google
	if($Tasks -match "GoogleUpdateTaskMachineCore") {Disable-ScheduledTask $GoogleUpdateTaskMachineCore}
	if($Tasks -match "GoogleUpdateTaskMachineUA") {Disable-ScheduledTask $GoogleUpdateTaskMachineUA}
	if($Tasks -match "MicrosoftEdgeUpdateTaskMachineCore") {Disable-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskMachineCore"}
	if($Tasks -match "MicrosoftEdgeUpdateTaskMachineUA") {Disable-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskMachineUA"}
	if($Tasks -match "MicrosoftEdgeUpdateBrowserReplacement") {Disable-ScheduledTask -TaskName "MicrosoftEdgeUpdateBrowserReplacementTask"}
	if($Tasks -match "Adobe Acrobat Update Task") {Disable-ScheduledTask -TaskName "Adobe Acrobat Update Task"}

#--------------------Disable systems through registry--------------------#
Write-Output "Modifying Registry"
Write-Progress -Activity "Service Corrections" -Status "Adding System RegKeys" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "MaintenanceDisabled" -Value 1 -Type Dword -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableTaskOffload" -Value 1 -Type Dword -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "DisablePasswordChange" -Value 1 -Type Dword -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "NtfsDisableLastAccessUpdate" -Value 2147483651 -Type Dword -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -Value 0 -Type Dword -Force
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -Name DisableWindowsUpdateAccess -Value 1 -Type Dword -Force
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Value 1 -Type Dword -Force
$Cortana = Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" 
	If($Cortana -eq $true) {Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Type Dword -Force}

#--------------------Defualt NTUserDat file config for Performance--------------------#
Write-Output "Editing NTUser.dat To Apply Perf Config"
Write-Progress -Activity "Service Corrections" -Status "Adjusting Default NTUser.DAT" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
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

#--------------------INet Framework v4 Queued Items and Update--------------------#
Write-Output "Inet Framework v4 queued items and updates"
Write-Progress -Activity "Service Corrections" -Status "Inet4 Execute Queued Items x32" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
Write-Output "Inet framework v4 x32 Queued Items"
Start-Process "C:\Windows\Microsoft.Net\Framework\v4.0.30319\ngen.exe" -Args "executeQueuedItems" -Wait | Out-Null
Write-Progress -Activity "Service Corrections" -Status "Inet4 Execute Queued Items x64" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
Write-Output "Inet framework v4 x64 Queued Items"
Start-Process "C:\Windows\Microsoft.Net\Framework64\v4.0.30319\ngen.exe" -Args "executeQueuedItems" -Wait | Out-Null
Write-Progress -Activity "Service Corrections" -Status "Inet4 Update x32" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
Write-Output "Inet framework v4 x32 Updating"
Start-Process "C:\Windows\Microsoft.Net\Framework\v4.0.30319\ngen.exe" -Args "update /force" -Wait | Out-Null
Write-Progress -Activity "Service Corrections" -Status "Inet4 Update x64" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
Write-Output "Inet framework v4 x64 Updating"
Start-Process "C:\Windows\Microsoft.Net\Framework64\v4.0.30319\ngen.exe" -Args "update /force" -Wait | Out-Null
#--------------------INet Framework v2 Queued Items and Update--------------------#
Write-Output "Inet Framework v2 queued items and updates"
Write-Progress -Activity "Service Corrections" -Status "Inet2 Execute Queued Items x32" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
Write-Output "Inet framework v2 x32 Queued Items"
Start-Process "C:\Windows\Microsoft.Net\Framework\v2.0.50727\ngen.exe" -Args "executeQueuedItems" -Wait | Out-Null
Write-Progress -Activity "Service Corrections" -Status "Inet2 Execute Queued Items x62" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
Write-Output "Inet framework v2 x64 Queued Items"
Start-Process "C:\Windows\Microsoft.Net\Framework64\v2.0.50727\ngen.exe" -Args "executeQueuedItems" -Wait | Out-Null
Write-Progress -Activity "Service Corrections" -Status "Inet2 Update x32" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
Write-Output "Inet framework v2 x32 Updating"
Start-Process "C:\Windows\Microsoft.Net\Framework\v2.0.50727\ngen.exe" -Args "update /force" -Wait | Out-Null
Write-Progress -Activity "Service Corrections" -Status "Inet2 Update x64" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
Write-Output "Inet framework v2 x64 Updating"
Start-Process "C:\Windows\Microsoft.Net\Framework64\v2.0.50727\ngen.exe" -Args "update /force" -Wait | Out-Null


#--------------------Native Defender Definitions Update--------------------#
Write-Output "Updating Defender Definitions"
Write-Progress -Activity "Service Corrections" -Status "Defender Definitions Update" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100
$NativeDefender = Test-Path -Path "C:\Program Files\Windows Defender\MpCmdRun.exe"
	If($NativeDefender -eq $true) {
	Start-Process "C:\Program Files\Windows Defender\MpCmdRun.exe" -Args "-RemoveDefinitions -DynamicSignatures" -Wait -PassThru ;  Write-Output "Defender Definitions Purged"
	Start-Process "C:\Program Files\Windows Defender\MpCmdRun.exe" -Args "-SignatureUpdate" -Wait -PassThru ;  Write-Output "Defender Definitions Updated"
	} else { Write-Output "Native Defender Not Present. Skipping Definition Update"}

Write-Output ""
Write-Output "====================---------- End of Service Corrections ----------===================="
Stop-Transcript
}

Function DiskCleanup {
Start-Transcript -Append -Path "$LogPath$Log.log" 
Write-Output "====================---------- Start of Disk Cleanup ----------===================="
Write-Output ""

#--------------------Enable and Start Services--------------------#
Write-Progress -Activity "DiskCleanup" -Status "Starting Services" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
$Services = Get-Service
$MedicSvc = Test-Path -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc'
$WUAcess = Test-Path -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"
	If($Services -match "UsoSvc") {Set-Service UsoSvc -StartupType Manual -Passthru}
	If($Services -match "UsoSvc") {Start-Service UsoSvc -PassThru}
	If($Services -match "Wuauserv") {Set-Service Wuauserv -StartupType Manual -Passthru}
	If($Services -match "Wuauserv") {Start-Service Wuauserv -PassThru}
	If($Services -match "TrustedInstaller") {Set-Service TrustedInstaller -StartupType Manual -Passthru}
	If($MedicSvc -eq $true) {Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc' -Name Start -Value 3 -Force -Passthru}
	If($WUAcess -eq $true) {Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -Name DisableWindowsUpdateAccess -Value 0 -Force -Passthru}

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

#Set the task priority for DiskMgr to high - Without this Windows can make it a low priority background task and take a lot longer. Sleep required as DismHost doesn't start right away
Get-WmiObject Win32_process -filter 'name = "CleanMgr.exe"' | foreach-object { $_.SetPriority(128) } ; Start-Sleep 5
Get-WmiObject Win32_process -filter 'name = "DismHost.exe"' | foreach-object { $_.SetPriority(128) }
#Wait for CleanMgr process to end before progressing
$Processes = Get-Process
	if ($Processes -Match "CleanMgr") {Wait-Process -Name CleanMgr}

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
		Dism /Online /Cleanup-Image /StartComponentCleanup /ResetBase /NoRestart}
	else {Write-Output "Cleanup not required" }

#--------------------Software Distribution folder--------------------#
#Makes sure Windows Update service is stopped and deletes the Software distribution folder if present
Write-Progress -Activity "DiskCleanup" -Status "Clearing SoftwareDistribution Folder" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
$SoftwareDistribution = Test-Path -Path "C:\Windows\SoftwareDistribution"
	If($Services -match "Wuauserv") {Stop-Service Wuauserv -Force -PassThru}
	if($SoftwareDistribution -eq $true) {Remove-Item -Path "C:\Windows\SoftwareDistribution" -Force -Recurse}
	else {Write-Output "SoftwareDistribution Already Cleared"}

#--------------------Stop and Disable Services--------------------#
Write-Progress -Activity "DiskCleanup" -Status "Stopping Services" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
	If($Services -match "UsoSvc") {Set-Service UsoSvc -StartupType Disabled -Passthru}
	If($Services -match "UsoSvc") {Stop-Service UsoSvc -Force -PassThru}
	If($Services -match "Wuauserv") {Set-Service Wuauserv -StartupType Disabled -Passthru}
	If($Services -match "Wuauserv") {Stop-Service Wuauserv -Force -PassThru}
	If($MedicSvc -eq $true) {Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc' -Name Start -Value 4 -Force -Passthru}
	If($WUAcess -eq $true) {Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -Name DisableWindowsUpdateAccess -Value 1 -Force -Passthru}

Write-Output ""
Write-Output "====================---------- End of Disk Cleanup ----------===================="
Stop-Transcript
}

Function DiskOptimise {
Start-Transcript -Append -Path "$LogPath$Log.log" 
Write-Output "====================---------- Start of Disk Optimisation ----------===================="
Write-Output ""

#--------------------Enable and Start Services--------------------#
Write-Progress -Activity "DiskOptimise" -Status "Starting Services" -Id 1 -PercentComplete 0 ; $global:CurrentTask += 1 ; $PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
$Services = Get-Service
	If($Services -match "DefragSvc") {Set-Service DefragSvc -StartupType Manual -Passthru}
	If($Services -match "DefragSvc") {Start-Service DefragSvc -PassThru}

#--------------------Defrag C: Drive--------------------#
Write-Progress -Activity "DiskOptimise" -Status "Defragging C:\" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
Defrag C:\

#--------------------Stop and Disable Services--------------------#
Write-Progress -Activity "DiskOptimise" -Status "Stopping Services" -Id 1 -PercentComplete $global:PercentComplete ; $global:CurrentTask += 1 ; $global:PercentComplete = ($global:CurrentTask / $TotalTasks) * 100 
	If($Services -match "DefragSvc") {Set-Service DefragSvc -StartupType Disabled -Passthru}
	If($Services -match "DefragSvc") {Stop-Service DefragSvc -Force -PassThru}

Write-Output ""
Write-Output "====================---------- End of Disk Optimisation ----------===================="
Stop-Transcript
}

#--------------------User Selection Interface--------------------#
#Interface for user to select what tasks they want the script to action
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Windows Maintenance Script v1.2'
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

[void] $listBox.Items.Add('1. System Repairs')
[void] $listBox.Items.Add('2. System Repairs (Offline)')
[void] $listBox.Items.Add('3. Service Corrections')
[void] $listBox.Items.Add('4. Disk Cleanups')
[void] $listBox.Items.Add('5. Disk Optimisation (MergeBase and MCS ONLY)')

$listBox.Height = 140
$form.Controls.Add($listBox)
$form.Topmost = $true

$result = $form.ShowDialog()

if ($result -eq [System.Windows.Forms.DialogResult]::OK)
{
    $x = $listBox.SelectedItems
	Invoke-Expression 'CMD /C Start Powershell -Command "C:\Scripts\NoLock.ps1"'	
	If($x -match "1.") {$TotalTasks += 10}
	If($x -match "2.") {$TotalTasks += 12}
	If($x -match "3.") {$TotalTasks += 13}
	If($x -match "4.") {$TotalTasks += 6}
	If($x -match "5.") {$TotalTasks += 3}
	If($x -match "1.") {OnlineRepair}
	If($x -match "2.") {OfflineRepair}
	If($x -match "3.") {ServiceCorrections}
	If($x -match "4.") {DiskCleanup}
	If($x -match "5.") {DiskOptimise}
		Write-Progress -Activity "Machine Maintenance" -Status "Maintenance Complete. Rebooting in 60s" -Id 1 -PercentComplete 100
		Start-Sleep 60 ; Restart-Computer -Force   
}

