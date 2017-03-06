OnCommand-Insight
=================

OnCommand-Insight PowerShell Module

Installation
------------

The recommended way to install the PowerShell Module is through the new Install-Module Cmdlet available in PowerShell 5. Consider installing PowerShell 5 from https://www.microsoft.com/en-us/download/details.aspx?id=50395. Then run

```powershell
Install-Module OnCommand-Insight
```

The OnComamnd Insight PowerShell Cmdlets require at least PowerShell 3.0 and .NET 4.5. Microsoft has documented the required procedures to install PowerShell 3.0 in the article [Installing Windows PowerShell](https://technet.microsoft.com/de-de/library/hh847837.aspx?f=255&MSPPError=-2147217396).

If you can't install via `Install-Module` you can download the latest version of OnCommand-Insight.zip from https://github.com/ffeldhaus/OnCommand-Insight/releases/latest. Then extract OnCommand-Insight.zip to your preferred PowerShell Module location (e.g. for current user to `$HOME\WindowsPowershell\Documents\WindowsPowerShell\Modules` or for all users to `C:\Windows\System32\WindowsPowerShell\v1.0\Modules`).

Usage
-----

Check if OnCommand-Insight Module can be found by PowerShell

    Get-Module -ListAvailable OnCommand-Insight
    
Import PowerShell Module
	
    Import-Module OnCommand-Insight
    
List all Cmdlets included in the OnCommand-Insight Module
	
    Get-Command -Module OnCommand-Insight
	
Show help for Cmdlet to connect to OnCommand-Insight Server
    
    Get-Help Connect-OciServer -Detailed
	
Connect to OnCommand Insight Server using the `-Insecure` Switch to skip checking the certificate of the server
    
    $Credential = Get-Credential
    Connect-OciServer -Name myserver.mydomain.tld -Credential $Credential -Insecure
    
List all Storage Arrays

    Get-OciStorages

Trusting the Publisher of the OnCommand Insight Cmdlets
-------------------------------------------------------

This PowerShell Module is signed with a code signing certificate issued by the *NetApp Corp Issuing CA 1*. If the PowerShell execution policy requires powershell scripts to be signed (see [about_Execution_Policies](https://technet.microsoft.com/library/hh847748.aspx) for details), two steps are required to run this PowerShell Module

1. Trust the NetApp Root Certification Authority. This can be done with the following command executed in PowerShell `Start-Process powershell -Verb RunAs -ArgumentList '-nologo -command (New-Object System.Net.WebClient).DownloadFile(\"http://pki2.netapp.com/pki/NetApp%20Corp%20Root%20CA.crt\",\"$env:TEMP\netapp.crt\");certutil -addstore root $env:TEMP\netapp.crt;rm $env:TEMP\netapp.cr*;PAUSE'` or manually via the following steps:
  1. download the NetApp Root CA certificate from (http://pki1.netapp.com/pki/NetApp%20Corp%20Root%20CA.crt)
  2. double click on the downloaded file
  3. click on *Install Certificate...*
  4. click on *Next >*
  5. Select *Place all certificates in the following store*
  6. Click *Browse*
  7. Select *Trusted Root Certification Authorities*
  8. Click *OK*
  9. Click *Next >*
  10. Click Finish
  11. A *Security Warning* will be displayed. Click *Yes* to install the certificate. The *Thumbprint (sha1)* should be **9FFB6F1A 06BC0245 27368705 2E7309D3 6FF2CFD0**
  12. Click twice on *OK* to close the dialogs.
2. When importing the PowerShell module via `Import-Module OnCommand-Insight` a dialog is displayed asking if the publisher *CN=florianf-Florian-Feldhaus, OU=Users, OU=EMEA, OU=Sites, DC=hq, DC=netapp, DC=com* should be trusted. Select *[A] Always run* to permanently trust this publisher.