<!-- language: lang-powershell -->

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

If the login fails, it is often due to an untrusted certificate of the OCI Server. You can ignore the certificate check with the `-insecure` option

    Connect-OciServer -Name $ServerName -Credential $Credential -Insecure

By default the connection to the OCI server is established through HTTPS. If that doesn't work, HTTP will be tried. 

To force connections via HTTPS use the `-HTTPS` switch

    Connect-OciServer -Name $ServerName -Credential $Credential -HTTPS

To force connections via HTTP use the `-HTTP` switch

    Connect-OciServer -Name $ServerName -Credential $Credential -HTTP
    
As the Timezone of the OCI Server is not available via the REST API, it needs to be manually set. By default the Timezone will be set to the local timezone of the PowerShell environment.

The currently configured timezone of the OCI Server can be checked with

    $CurrentOciServer.Timezone
    
A list of all available timezones can be shown with

    [System.TimeZoneInfo]::GetSystemTimeZones()

To set a different timezone (e.g. CEST or PST), the following command can be used

    $CurrentOciServer.Timezone = [System.TimeZoneInfo]::FindSystemTimeZoneById("Central Europe Standard Time")
    $CurrentOciServer.Timezone = [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time")
