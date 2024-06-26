Do {
[void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[System.Windows.Forms.SendKeys]::SendWait("{F13}")
Start-Sleep -Seconds 120
} While ("$true")
