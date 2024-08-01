<#
------------WU Browser Updates Script V2.0---------------
----------------Created by Kyle Baxter----------------

.Synopsis
Patching Script for windows Browser Updates

.Description
This script is for the installation of windows Browser Updates to a machine autonomously 
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
$TotalTasks = 0

#Start of Browser Tasks
#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Start-Transcript -Append  -Path "$LogPath$Log - BrowserUpdates.log" 
Write-Output "====================---------- Start of Browser Patching ----------===================="
Write-Output ""


Write-Progress -Activity "Browser Updates" -Status "Updating Browsers" -Id 1 -PercentComplete 0
#Checking if Edge exists and clearing directory. (Running latest installer doesn't overwrite the existing exe's to latest version)
$Edge = Test-Path -Path "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
$Chrome = Test-Path -Path "C:\Program Files\Google\Chrome\Application\Chrome.exe"
$Chrome64 = Test-Path -Path "C:\Program Files (x86)\Google\Chrome\Application\Chrome.exe"
$FireFox = Test-Path -Path "C:\Program Files\Mozilla Firefox"
$FireFox64 = Test-Path -Path "C:\Program Files (x86)\Mozilla Firefox"
	If($Edge -eq $true) {$TotalTasks += 5}
	If(($Chrome -eq $true) -or ($Chrome64 -eq $true)) {$TotalTasks += 5}
	If(($FireFox -eq $true) -or ($FireFox64 -eq $true))  {$TotalTasks += 5}
	
	#--------------------Edge--------------------#
	If($Edge -eq $true) {
		Write-Progress -Activity "Browser Updates - Edge" -Status "Enabling Edge Services" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
		Stop-Process -Name MsEdge -Verbose -Force -ErrorAction SilentlyContinue	
		$Services = Get-Service
		$EdgeServices = "edgeupdate,edgeupdatem,MicrosoftEdgeElevationService" -Split ","
		$Matches = Select-String $EdgeServices -Input $Services -AllMatches | Foreach {$_.matches} | Select -Expand Value 
			Foreach($Matches in $EdgeServices) {
				If($Services -match $Matches) {
				Set-Service $Matches -StartupType Manual | Restart-Service -Force
				Write-Output "Startup of service $Matches set to Manual and Started"
				} Else {Write-Output "$Matches not present"}
			}
		Write-Progress -Activity "Browser Updates - Edge" -Status "Running Edge Updater" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
		Start-Process msEdge
		Start-Sleep 5
		$wshell = New-Object -ComObject wscript.shell;
		$wshell.AppActivate("msEdge")
		Start-Sleep 1
		$wshell.SendKeys("Edge://help")
		Start-Sleep 1
		$wshell.SendKeys("{ENTER}")
		Start-Sleep 10
		
		Write-Progress -Activity "Browser Updates - Edge" -Status "Waiting for Update completion" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
		$Processes = Get-Process
			If($Processes -Match "MicrosoftEdgeUpdate") {Wait-Process -Name MicrosoftEdgeUpdate}
		Stop-Process -Name MsEdge -Verbose -Force
		Start-Sleep 5

		Write-Progress -Activity "Browser Updates - Edge" -Status "Applying Update" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
		Start-Process msEdge
		Start-Sleep 5
		$wshell = New-Object -ComObject wscript.shell;
		$wshell.AppActivate("msEdge")
		Start-Sleep 1
		$wshell.SendKeys("Edge://help")
		Start-Sleep 1
		$wshell.SendKeys("{ENTER}")
		Start-Sleep 10

		Write-Progress -Activity "Browser Updates - Edge" -Status "Disabling Services" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
			Foreach($Matches in $EdgeServices) {
				If($Services -match $Matches) {
				Set-Service $Matches -StartupType Disabled | Stop-Service -Force
				Write-Output "Startup of service $Matches set to Disabled and Stopped"
				} Else {Write-Output "$Matches not present"}
			}
		$ScheduledTask = Get-ScheduledTask
			If($ScheduledTask -match "MicrosoftEdgeUpdateBrowserReplacement") {Disable-ScheduledTask -TaskName "MicrosoftEdgeUpdateBrowserReplacementTask"}
			If($ScheduledTask -match "MicrosoftEdgeUpdateTaskMachineCore") {Disable-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskMachineCore"}
			If($ScheduledTask -match "MicrosoftEdgeUpdateTaskMachineUA") {Disable-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskMachineUA"}
			
		Stop-Process -Name MsEdge -Verbose -Force -ErrorAction SilentlyContinue	
	} Else {Write-Output "Edge not present, skipping"}

	#--------------------Chrome--------------------#
	If(($Chrome -eq $true) -or ($Chrome64 -eq $true))  {
		Write-Progress -Activity "Browser Updates - Chrome" -Status "Enabling Services" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
		Stop-Process -Name Chrome -Verbose -Force -ErrorAction SilentlyContinue	
		$Services = Get-Service
		If($Services -match "gupdate") {Set-Service gupdate -StartupType Manual | Start-Service}
		If($Services -match "gupdatem") {Set-Service gupdatem -StartupType Manual | Start-Service}
		$GoogleUpdaterService = (Get-Service -DisplayName "GoogleUpdater Service*").Name
		$GoogleUpdaterIntService = (Get-Service -DisplayName "GoogleUpdater InternalService*").Name
		Get-Service -DisplayName "GoogleUpdaterService*" | Set-Service -StartupType Manual | Start-Service	
		Get-Service -DisplayName "GoogleUpdaterInternalService*" | Set-Service -StartupType Manual | Start-Service
		Write-Output "Startup of service $GoogleUpdaterService set to Manual"
		Write-Output "Startup of service $GoogleUpdaterIntService set to Manual"
		If($Services -match "GoogleChromeElevationService") {Set-Service GoogleChromeElevationService -StartupType Manual | Start-Service}

		Write-Progress -Activity "Browser Updates - Chrome" -Status "Running Updater" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
		Start-Process Chrome
		Start-Sleep 5
		$wshell = New-Object -ComObject wscript.shell;
		$wshell.AppActivate("Chrome")
		Start-Sleep 1
		$wshell.SendKeys("Chrome://help")
		Start-Sleep 1
		$wshell.SendKeys("{ENTER}")
		Start-Sleep 10

		Write-Progress -Activity "Browser Updates - Chrome" -Status "Waiting for Update completion" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
		$Processes = Get-Process
		If($Processes -Match "GoogleUpdate") {Wait-Process -Name GoogleUpdate}
		Stop-Process -Name Chrome -Verbose -Force
		Start-Sleep 5

		Write-Progress -Activity "Browser Updates - Chrome" -Status "Applying Update" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
		Start-Process Chrome
		Start-Sleep 5
		$wshell = New-Object -ComObject wscript.shell;
		$wshell.AppActivate("Chrome")
		Start-Sleep 1
		$wshell.SendKeys("Chrome://help")
		Start-Sleep 1
		$wshell.SendKeys("{ENTER}")
		Start-Sleep 10

		Write-Progress -Activity "Browser Updates - Chrome" -Status "Disabling Services" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
		$Services = Get-Service
			If($Services -match "gupdate") {Set-Service gupdate -StartupType Disabled | Stop-Service -Force}
			If($Services -match "gupdatem") {Set-Service gupdatem -StartupType Disabled | Stop-Service -Force}
			$GoogleUpdaterService = (Get-Service -DisplayName "GoogleUpdater Service*").Name
			$GoogleUpdaterIntService = (Get-Service -DisplayName "GoogleUpdater InternalService*").Name
			Get-Service -DisplayName "GoogleUpdaterService*" | Set-Service -StartupType Disabled | Stop-Service	-Force
			Get-Service -DisplayName "GoogleUpdaterInternalService*" | Set-Service -StartupType Disabled | Stop-Service -Force
			Write-Output "Startup of service $GoogleUpdaterService set to Disabled"
			Write-Output "Startup of service $GoogleUpdaterIntService set to Disabled"
			If($Services -match "GoogleChromeElevationService") {Set-Service GoogleChromeElevationService -StartupType Disabled | Stop-Service -Force}
			
		Stop-Process -Name Chrome -Verbose -Force -ErrorAction SilentlyContinue	
		} Else { Write-Output "Chrome Not installed. Skipping Update" }

	#--------------------Firefox--------------------#
	If(($FireFox -eq $true) -or ($FireFox64 -eq $true))  {
		Write-Progress -Activity "Browser Updates - FireFox" -Status "Enabling Services" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
		Stop-Process -Name FireFox -Verbose -Force -ErrorAction SilentlyContinue	
		$Services = Get-Service
			If($Services -match "MozillaMaintenance") {Set-Service MozillaMaintenance -StartupType Manual | Restart-Service}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\FireFox" -Name "DisableAppUpdate" -Value 0 -Type Dword -Force -PassThru

		Write-Progress -Activity "Browser Updates - FireFox" -Status "Running Updater" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
		Start-Process FireFox
		Start-Sleep 5
		$wshell = New-Object -ComObject wscript.shell;
		$wshell.AppActivate("FireFox")
		Start-Sleep 1
		$wshell.SendKeys("About:Settings")
		Start-Sleep 1
		$wshell.SendKeys("{ENTER}")
		Start-Sleep 10

		Write-Progress -Activity "Browser Updates - FireFox" -Status "Waiting for Update completion" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
		$Processes = Get-Process
			If($Processes -Match "Updater") {Wait-Process -Name Updater}
		Stop-Process -Name FireFox -Verbose -Force -ErrorAction SilentlyContinue
		Start-Sleep 5

		Write-Progress -Activity "Browser Updates - FireFox" -Status "Applying Update" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
		Start-Process FireFox
		Start-Sleep 5
		$wshell = New-Object -ComObject wscript.shell;
		$wshell.AppActivate("FireFox")
		Start-Sleep 1
		$wshell.SendKeys("About:Settings")
		Start-Sleep 1
		$wshell.SendKeys("{ENTER}")
		Start-Sleep 10

		Write-Progress -Activity "Browser Updates - FireFox" -Status "Disabling Services" -Id 1 -PercentComplete $PercentComplete ; $CurrentTask += 1 ; $PercentComplete = ($CurrentTask / $TotalTasks) * 100
			If($Services -match "MozillaMaintenance") {Set-Service MozillaMaintenance -StartupType Disabled | Stop-Service -Force}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\FireFox" -Name "DisableAppUpdate" -Value 1 -Type Dword -Force -PassThru	
		
		Stop-Process -Name FireFox -Verbose -Force -ErrorAction SilentlyContinue
	} Else {Write-Output "Firefox not present, skipping"}

Write-Output ""
Write-Output "====================---------- End of Browser Patching ----------===================="
Stop-Transcript
#End of Browser Tasks
#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------