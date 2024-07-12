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
	#Runs each function if its chosen and outputs the results to log file	
	If($x -match "1.") {Start-Process Powershell -Args "-F C:\VDI Tools\Patching\Sealer.ps1" -Wait}
	If($x -match "2.") {Start-Process $ConfigFile}
	If($x -match "1.") {
		Write-Progress -Activity "Machine Sealing" -Status "Sealing Complete. Shuting Down in 10s" -Id 1 -PercentComplete 100
		Start-Sleep 10 ; Shutdown /s /t 1
	}
}