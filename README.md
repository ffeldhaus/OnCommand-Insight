OnCommand-Insight
=================

OnCommand-Insight PowerShell Module

Installation
------------

The recommended way to install the PowerShell Module is through the new Install-Module Cmdlet available in PowerShell 5. Consider installing PowerShell 5 from https://www.microsoft.com/en-us/download/details.aspx?id=50395. Then run

```powershell
Install-Module OnCommand-Insight
```

or, if you don't have admin rights just install for the current user

```powershell
Install-Module OnCommand-Insight -Scope CurrentUser
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