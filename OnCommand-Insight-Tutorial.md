# OnCommand Insight (OCI) PowerShell Cmdlet Tutorial

This tutorial will give an introduction to the OnCommand Insight PowerShell Cmdlets

## Discovering the available Cmdlets

Load the OCI Module

    Import-Module OnCommand-Insight

Show all available Cmdlets from the OCI Module

    Get-Command -Module OnCommand-Insight

Show the syntax of all Cmdlets from the OCI Module

    Get-Command -Module OnCommand-Insight

To get detailed help including examples for a specific Cmdlet (e.g. for Connect-OciServer) run

    Get-Help Connect-OciServer -Detailed

## Connecting to an OCI Server

For data retrieval a connection to the OCI Server is required. The Connect-OciServer Cmdlet expects the hostname or IP and the credentials for authentication

    $ServerName = 'ociserver.example.com'
    $Credential = Get-Credential
    Connect-OciServer -Name $ServerName -Credential $Credential

If the login fails, it is often due to an untrusted certificate of the OCI Server. You can ignore the certificate check with the -insecure option

	Connect-OciServer -Name $ServerName -Credential $Credential -Insecure