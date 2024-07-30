<#
---------Maintenance Offline Repairs Script V2.0---------------
----------------Created by Kyle Baxter----------------

.Synopsis
Windows Offline Repairs Scripts

.Description
This script completes Offline Repairs of the Windows Image

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
$Installs = "C:\VDI Tools\Installers"
$Log = "$ENV:ComputerName - $Time"
	If(!(Test-Path -PathType container $LogPath)) {New-Item -ItemType Directory -Path $LogPath} 
	If(!(Test-Path -PathType container $Installs)) {New-Item -ItemType Directory -Path $Installs} 	

#Global Variables.
$CurrentTask = 0
$PercentComplete = 0
$TotalTasks = 12

#Start of Offline Repairs tasks
#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Start-Transcript -Append -Path "$LogPath$Log - OfflineRepairs.log" 
Write-Output "====================---------- Start of Offline Repairs ----------===================="
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
Write-Progress -Activity "Offline System Repair" -Status "Repair WMI Repository" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
Write-Output "---Rebuild WMI Repository---"	
Set-Service WinMgmt -StartupType Disabled
Stop-Service WinMgmt -Force
Start-Sleep 3
WinMgmt /salvagerepository %windir%\System32\wbem
WinMgmt /resetrepository %windir%\System32\wbem
Set-Service WinMgmt -StartupType Manual
Start-Sleep 3

#--------------------SFC Scan and Repair--------------------#
Write-Progress -Activity "Offline System Repair" -Status "Scanning System Health" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
Sfc /Scannow 
#--------------------Dism Image Repair--------------------#
Write-Progress -Activity "Offline System Repair" -Status "Acquiring OS information" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100 
$OperatingSystem = systeminfo | findstr /B /C:"OS Name" /B /C:"OS Version"
$OperatingSystem
Write-Progress -Activity "Offline System Repair" -Status "Downloading OS Iso File" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100 
$ProgressPreference = 'SilentlyContinue'
	#Dism Repair using local Iso file (Win2016)
	If($OperatingSystem -match "Windows Server 2016") {
	Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/p/?LinkID=2195174&clcid=0x409&culture=en-us&country=US" -OutFile "$Installs\WinServer2016.iso"
	$IsoPath = "$Installs\WinServer2016.iso"
	}	
	#Dism Repair using local Iso file (Win2019)
	If($OperatingSystem -match "Windows Server 2019") {
	Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/p/?LinkID=2195167&clcid=0x409&culture=en-us&country=US" -OutFile "$Installs\WinServer2019.iso"	
	$IsoPath = "$Installs\WinServer2019.iso"	
	}
	#Dism Repair using local Iso file (Win2022)
	If($OperatingSystem -match "Windows Server 2022") {
	Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/p/?LinkID=2195280&clcid=0x409&culture=en-us&country=US" -OutFile "$Installs\WinServer2022.iso"	
	$IsoPath = "$Installs\WinServer2022.iso"	
	}
	#Dism Repair using local Iso file (Win10 Enterprise)
	If($OperatingSystem -match "Windows 10 Enterprise") {
	Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/p/?LinkID=2208844&clcid=0x409&culture=en-us&country=US" -OutFile "$Installs\Win10E.iso"	
	$IsoPath = "$Installs\Win10E.iso"	
	}
	#Dism Repair using local Iso file (Win10 Pro)
	If($OperatingSystem -match "Windows 10 Pro") {
	Invoke-WebRequest -Uri "https://www.itechtics.com/?dl_id=173" -OutFile "$Installs\Win10Pro.iso"	
	$IsoPath = "$Installs\Win10Pro.iso"	
	}	
$ProgressPreference = 'Continue'
Write-Output "Mounting Iso Image"
Write-Progress -Activity "Offline System Repair" -Status "Mounting Iso" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100 
$IsoDrive = Mount-DiskImage -ImagePath $IsoPath -PassThru
$IsoLetter = ($IsoDrive | Get-Volume).DriveLetter
Write-Output "Beginning Repair with local ISO"
Write-Progress -Activity "Offline System Repair" -Status "Repairing Image with Iso" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100 
Dism /Online /Cleanup-Image /RestoreHealth /Source:"$IsoLetter":\Sources\Install.Wim /LimitAccess
Write-Progress -Activity "Machine Maintenance" -Status "Removing Files" -Id 1 -PercentComplete 100
Dismount-DiskImage -ImagePath $IsoPath
Remove-Item -Path $IsoPath -Force
#Dism Clear MountPoints
Write-Progress -Activity "Offline System Repair" -Status "Cleaning System Mountpoints" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100 
Dism /Cleanup-MountPoints

#--------------------Check Disk Scan and Repair--------------------#
Write-Output "Chckdisk scan"
Write-Progress -Activity "Offline System Repair" -Status "Repairing C Volume" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100 
Repair-Volume -DriveLetter C -OfflineScanAndFix  
$SystemReserved = Get-Volume
Write-Progress -Activity "Offline System Repair" -Status "Repairing Protected Volume" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100 
if ($SystemReserved -match "System Reserved") {
Repair-Volume -FileSystemLabel "System Reserved" -OfflineScanAndFix}

#--------------------Rebuild Performance Counters--------------------#
Write-Progress -Activity "Offline System Repair" -Status "Rebuild Perf Counters" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100 
Stop-Service Wuauserv -Force
& "c:\windows\system32\lodctr" /R
& "c:\windows\sysWOW64\lodctr" /R
WinMgmt /RESYNCPERF

#--------------------Stop and Disable Services--------------------#
Write-Output "Stopping Offline Repair Services"
Write-Progress -Activity "Offline System Repair" -Status "Stopping Services" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100 
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
Write-Output "====================---------- End of Offline Repairs ----------===================="
Stop-Transcript
#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#End Of Offline Repair Tasks