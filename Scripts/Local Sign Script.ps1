If(-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	$arguments = "& '" + $myInvocation.MyCommand.Definition + "'"
	Start-Process Powershell -Verb runAs -ArgumentList $arguments
	exit
}

$Path = "C:\Bluecube\Scripts\"
$Scripts = Get-ChildItem $Path -Filter "*.ps1"

Write-Output "Create and Sign or only Sign"
$Signing = Read-Host -Prompt "Enter 1 for create and Sign. Else leave blank"

If($Signing -eq "1") {
$authenticode = New-SelfSignedCertificate -Subject "ATA Authenticode" -CertStoreLocation Cert:\LocalMachine\My -Type CodeSigningCert
$rootStore = [System.Security.Cryptography.X509Certificates.X509Store]::new("Root","LocalMachine")
$rootStore.Open("ReadWrite")
$rootStore.Add($authenticode)
$rootStore.Close()
$publisherStore = [System.Security.Cryptography.X509Certificates.X509Store]::new("TrustedPublisher","LocalMachine")
$publisherStore.Open("ReadWrite")
$publisherStore.Add($authenticode)
$publisherStore.Close()
}

$codeCertificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -eq "CN=ATA Authenticode"}
Foreach($Script in $Scripts) {Set-AuthenticodeSignature -FilePath "$Path$Script" -Certificate $codeCertificate -TimeStampServer "http://timestamp.digicert.com"}