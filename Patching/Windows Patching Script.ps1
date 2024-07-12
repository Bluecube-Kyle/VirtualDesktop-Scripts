<#
---------------CTS Patching Script V1.3---------------
----------------Created by Kyle Baxter----------------

.Synopsis
Windows Patching Script to automatic monthly patching 

.Description
This script will perform automated patching of a number of applications. Upon running this script will prompt a user selection interfacte to choose what tasks are to be completed
The list of available functions is as follows; Windows Updates, Office Updates, Browser Updates, Adobe Updates and Disk Cleanup of patch files.
Each task is isolated into its own function and creates its own block inside the log file.
To complete each task first the required services will be enabled and then disabled at the end -
	Windows Updates: Imports the PSWIndowsUpdate module and then first runs a get updates command and then an install updates command skipping KB890830. Following Windows updates will update Defender Definitions
	Microsoft Office Updates: Runs the Click to Run updater with force close of applications. As normal -Wait does not work a loop is created that waits for the process to report up to date before progressing
	Browser Updates: First checks if that browser is installed by looking for the application.exe / registry keys. If it is present will download the latest online installer and run it silently before removing it.
For edge specifically installed the latest version does not overwrite the existing version. To resolve this it first kills all edge processes and wipes the directory, then runs the installer.
Following Installation disables services and ScheduledTasks used to enable automatic elevation and updating of the application
	Adobe: First checks installed type and then runs the AdobeARM which will update the current Reader version to the latest version. Following update disables manual check for updates.
	DiskCleanup: Disk Cleanup runs 4 different cleanup tasks. First will set Stateflags for DiskMgr cleanup to clean all options on drive C, Cleans up Windows Event Logs, Analyzes WinSxS store and performs cleanup if windows reports cleanup recommended
Lastly clears the Software distribution  folder.
This script does not use an erroraction silent continue conditions as it always checks for its present first before attempting to modify.

.Requirements 
Requires the PSWIndowsUpdate Module to be installed. This can be done with the following command (Requires changing execution policy)
Install-Module -Name PSWindowsUpdate -Force

.LogFile
C:\CTS\UpdateLogs\Hostname - Date - Patching.log
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
$form.Text = 'Windows Patching Script v1.3'
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
[void] $listBox.Items.Add('6. Edit Config')

$listBox.Height = 140
$form.Controls.Add($listBox)
$form.Topmost = $true

$result = $form.ShowDialog()

if ($result -eq [System.Windows.Forms.DialogResult]::OK)
{
    $x = $listBox.SelectedItems
	If($x -match "1.") {
		Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Bluecube-Kyle/VirtualDesktop-Scripts/main/Patching/WU%20OS%20Updates.ps1" -OutFile "C:\VDI Tools\Patching\WU OS Updates.ps1"
		Start-Process Powershell -Args '-F "C:\VDI Tools\Patching\WU OS Updates.ps1"' -Wait
		}
	If($x -match "6.") {Start-Process $ConfigFile}
	If($x -notmatch "6.") {
		Write-Progress -Activity "Machine Patching" -Status "Patching Complete. Rebooting in 10s" -Id 1 -PercentComplete 100
		Start-Sleep 10 ; Restart-Computer -Force
	}
}