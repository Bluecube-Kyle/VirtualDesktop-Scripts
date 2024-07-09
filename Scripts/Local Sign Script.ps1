#Force Admin elevation prompt if not ran as administrator
If(-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	$arguments = "& '" + $myInvocation.MyCommand.Definition + "'"
	Start-Process Powershell -Verb runAs -ArgumentList $arguments
	exit
}

#Directory where scripts are stored
$Path = "C:\VDI Tools\Scripts\"
$Scripts = Get-ChildItem $Path -Filter "*.ps1"

#Look for existing Certificate and delete it
Get-ChildItem "Cert:\LocalMachine\My" | Where-Object { $_.Subject -match 'ATA Authenticode' } | Remove-Item

#Create new certificate
$authenticode = New-SelfSignedCertificate -Subject "ATA Authenticode" -CertStoreLocation Cert:\LocalMachine\My -Type CodeSigningCert
$rootStore = [System.Security.Cryptography.X509Certificates.X509Store]::new("Root","LocalMachine")
$rootStore.Open("ReadWrite")
$rootStore.Add($authenticode)
$rootStore.Close()
$publisherStore = [System.Security.Cryptography.X509Certificates.X509Store]::new("TrustedPublisher","LocalMachine")
$publisherStore.Open("ReadWrite")
$publisherStore.Add($authenticode)
$publisherStore.Close()

#Bind certificate to all .ps1 files in scripts folder
$codeCertificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -eq "CN=ATA Authenticode"}
Foreach($Script in $Scripts) {Set-AuthenticodeSignature -FilePath "$Path$Script" -Certificate $codeCertificate -TimeStampServer "http://timestamp.digicert.com"}