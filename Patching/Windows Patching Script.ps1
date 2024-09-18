<#
--------------Master Patching Script V2.0---------------
----------------Created by Kyle Baxter----------------

.Synopsis
Master script used for manually patching servers

.Description
This script is a control script to manually run individual patching tasks. When running it will download and install the latest version of scripts before running them
#>

#Detect if run as admin and if not request elevation
If(-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	$arguments = "& '" + $myInvocation.MyCommand.Definition + "'"
	Start-Process Powershell -Verb runAs -ArgumentList $arguments
	exit
}

#--------------------User Selection Interface--------------------#
#Interface for user to select what tasks they want the script to action
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Windows Patching Script v2.0'
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

#Task Choice list. Each option is a different choice. Options start with a number as it uses a string match to confirm the choices.
#To add more then 9 options the number format needs changing from 0-9 to 00-99.
[void] $listBox.Items.Add('1. Windows Updates')
[void] $listBox.Items.Add('2. Office Updates')
[void] $listBox.Items.Add('3. Browser Updates')
[void] $listBox.Items.Add('4. Adobe Updates')
[void] $listBox.Items.Add('5. Disk Cleanup Updates')
[void] $listBox.Items.Add('6. Edit Config')

$listBox.Height = 140
$form.Controls.Add($listBox)
$form.Topmost = $true

$result = $form.ShowDialog()

if ($result -eq [System.Windows.Forms.DialogResult]::OK)
{
    $x = $listBox.SelectedItems

	#Create directory for scripts
	$Paths = @(
		"C:\VDI Tools\Patching\"
	)
	Foreach($Path in $Paths) {If(!(Test-Path -PathType container $Path)) {New-Item -ItemType Directory -Path $Path}}

	#Check if Proxy Server is present. Disable it for download if it is
	$ProxyServer = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -ErrorAction SilentlyContinue
	If ($ProxyServer -eq "1") {
		Set-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyEnable" -Value 0
		Start-Process "ms-settings:network-proxy"
		Start-Sleep 2
		Stop-Process -Name SystemSettings
	}

	#Download Live Script files
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	Invoke-WebRequest -Uri "https://github.com/Bluecube-Kyle/VirtualDesktop-Scripts/archive/refs/heads/main.zip" -OutFile "C:\VDI Tools\Scripts.zip"
	Expand-Archive "C:\VDI Tools\Scripts.zip" -DestinationPath "C:\VDI Tools\" -Force
	Get-ChildItem -Path "C:\VDI Tools\VirtualDesktop-Scripts-main\Patching\" | Copy-Item -Destination "C:\VDI Tools\Patching\" -Force -Recurse
	Remove-Item "C:\VDI Tools\Scripts.zip" -Force
	Remove-Item "C:\VDI Tools\VirtualDesktop-Scripts-main\" -Recurse -Force

	#Re-Enable Proxy
	If ($ProxyServer -eq "1") {
		Set-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyEnable" -Value 1
		Start-Process "ms-settings:network-proxy"
		Start-Sleep 2
		Stop-Process -Name SystemSettings
	}

	#Directory where scripts are stored
	$Scripts = Get-ChildItem "C:\VDI Tools\Patching" -Filter "*.ps1" -Recurse
	#Bind certificate to all .ps1 files in scripts folder
	$codeCertificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -eq "CN=VDI Tools"}
	Foreach($Script in $Scripts) {
		$Path = $Script.Directory
		$Name = $Script.Name
		Set-AuthenticodeSignature -FilePath "$Path\$Name" -Certificate $codeCertificate -TimeStampServer "http://timestamp.digicert.com"
	}
	
	#Running Windows OS Updates
	If($x -match "1.") {Powershell -F "C:\VDI Tools\Patching\WU OS Updates.ps1"}
	If($x -match "2.") {Powershell -F "C:\VDI Tools\Patching\WU Office Updates.ps1"}
	If($x -match "3.") {Powershell -F "C:\VDI Tools\Patching\WU Browser Updates.ps1"}
	If($x -match "4.") {Powershell -F "C:\VDI Tools\Patching\WU Adobe Updates.ps1"}
	If($x -match "5.") {Powershell -F "C:\VDI Tools\Patching\WU DiskCleanup.ps1"}
	If($x -match "6.") {Start-Process "C:\VDI Tools\Configs\PatchingConf.txt"}
	If($x -notmatch "6.") {
		Write-Progress -Activity "Machine Patching" -Status "Patching Complete. Rebooting in 10s" -Id 1 -PercentComplete 100
		Start-Sleep 10 ; Restart-Computer -Force
	}
}