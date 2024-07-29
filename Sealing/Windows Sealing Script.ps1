<#
---------------Ekco Sealing Script V1.5---------------
----------------Created by Kyle Baxter----------------

.Synopsis
Virtual Desktop Sealing Script to be used as template device

.Description
Sealing script used to remove machine specific configurations and unecessary items to be applied for non persistent virtual desktops.
Split into 2 functions for PVS or MCS images 



.LogFile
C:\VDI Tools\SealingLogs\Date\Hostname - Sealing.log
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
$form.Text = 'Image Sealing Script v1.5'
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
$label.Text = 'Select what the machine type is to Seal'
$label.Font = New-Object System.Drawing.Font("Cascadia Mono",10,[System.Drawing.FontStyle]::Regular)
$form.Controls.Add($label)

$listBox = New-Object System.Windows.Forms.Listbox
$listBox.Location = New-Object System.Drawing.Point(20,80)
$listBox.Size = New-Object System.Drawing.Size(520,40)
$listBox.Font = New-Object System.Drawing.Font("Cascadia Mono",12,[System.Drawing.FontStyle]::Regular)
$listBox.SelectionMode = 'MultiExtended'

[void] $listBox.Items.Add('1. Seal Image')
[void] $listBox.Items.Add('2. Edit Config')

$listBox.Height = 140
$form.Controls.Add($listBox)
$form.Topmost = $true

$result = $form.ShowDialog()

if ($result -eq [System.Windows.Forms.DialogResult]::OK)
{
    $x = $listBox.SelectedItems
	#Create directory for scripts
	$Paths = @(
		"C:\VDI Tools\Sealing\"
	)
	Foreach($Path in $Paths) {If(!(Test-Path -PathType container $Path)) {New-Item -ItemType Directory -Path $Path}}

	#Download Live Script files
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	Invoke-WebRequest -Uri "https://github.com/Bluecube-Kyle/VirtualDesktop-Scripts/archive/refs/heads/main.zip" -OutFile "C:\VDI Tools\Scripts.zip"
	Expand-Archive "C:\VDI Tools\Scripts.zip" -DestinationPath "C:\VDI Tools\" -Force
	Get-ChildItem -Path "C:\VDI Tools\VirtualDesktop-Scripts-main\Sealing\" | Copy-Item -Destination "C:\VDI Tools\Sealing\" -Force -Recurse
	
	#Directory where scripts are stored
	$Scripts = Get-ChildItem "C:\VDI Tools\Sealing" -Filter "*.ps1" -Recurse
	#Bind certificate to all .ps1 files in scripts folder
	$codeCertificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -eq "CN=VDI Tools"}
	Foreach($Script in $Scripts) {
		$Path = $Script.Directory
		$Name = $Script.Name
		Set-AuthenticodeSignature -FilePath "$Path\$Name" -Certificate $codeCertificate -TimeStampServer "http://timestamp.digicert.com"
	}
	If($x -match "1.") {Powershell -F "C:\VDI Tools\Sealing\Sealer.ps1"}
	If($x -match "2.") {Start-Process "C:\VDI Tools\Configs\SealingConf.txt"}
	If($x -match "1.") {
		Write-Progress -Activity "Machine Sealing" -Status "Sealing Complete. Shuting Down in 10s" -Id 1 -PercentComplete 100
		Start-Sleep 10 ; Shutdown /s /t 1
	}
}