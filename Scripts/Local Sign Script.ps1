#Force Admin elevation prompt if not ran as administrator
If(-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	$arguments = "& '" + $myInvocation.MyCommand.Definition + "'"
	Start-Process Powershell -Verb runAs -ArgumentList $arguments
	exit
}

#Directory where scripts are stored
$Scripts = Get-ChildItem "C:\VDI Tools\" -Filter "*.ps1" -Recurse


#Look for existing Certificate and delete it
Get-ChildItem "Cert:\*" -Recurse | Where-Object {$_.Subject -match "VDI Tools"} | Remove-Item -Recurse -Verbose

#Create new certificate
$authenticode = New-SelfSignedCertificate -Subject "VDI Tools" -CertStoreLocation Cert:\LocalMachine\My -Type CodeSigningCert
$rootStore = [System.Security.Cryptography.X509Certificates.X509Store]::new("Root","LocalMachine")
$rootStore.Open("ReadWrite")
$rootStore.Add($authenticode)
$rootStore.Close()
$publisherStore = [System.Security.Cryptography.X509Certificates.X509Store]::new("TrustedPublisher","LocalMachine")
$publisherStore.Open("ReadWrite")
$publisherStore.Add($authenticode)
$publisherStore.Close()

#Bind certificate to all .ps1 files in scripts folder
$codeCertificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -eq "CN=VDI Tools"}
Foreach($Script in $Scripts) {
	$Path = $Script.Directory
	$Name = $Script.Name
	Set-AuthenticodeSignature -FilePath "$Path\$Name" -Certificate $codeCertificate -TimeStampServer "http://timestamp.digicert.com"
}