# OnCommand Insight (OCI) PowerShell Cmdlet Tutorial

This tutorial will give an introduction to the OnCommand Insight PowerShell Cmdlets

## Discovering the available Cmdlets

Load the OCI Module

```powershell
Import-Module OnCommand-Insight
```

Show all available Cmdlets from the OCI Module

```powershell
Get-Command -Module OnCommand-Insight
```

Show the syntax of all Cmdlets from the OCI Module

```powershell
Get-Command -Module OnCommand-Insight
```

To get detailed help including examples for a specific Cmdlet (e.g. for Connect-OciServer) run

```powershell
Get-Help Connect-OciServer -Detailed
```

## Connecting to an OCI Server

For data retrieval a connection to the OCI Server is required. The Connect-OciServer Cmdlet expects the hostname or IP and the credentials for authentication

```powershell
$ServerName = 'ociserver.example.com'
$Credential = Get-Credential
Connect-OciServer -Name $ServerName -Credential $Credential
```

If the login fails, it is often due to an untrusted certificate of the OCI Server. You can ignore the certificate check with the `-insecure` option

```powershell
Connect-OciServer -Name $ServerName -Credential $Credential -Insecure
```

By default the connection to the OCI server is established through HTTPS. If that doesn't work, HTTP will be tried. 

To force connections via HTTPS use the `-HTTPS` switch

```powershell
Connect-OciServer -Name $ServerName -Credential $Credential -HTTPS
```

To force connections via HTTP use the `-HTTP` switch

```powershell
Connect-OciServer -Name $ServerName -Credential $Credential -HTTP
```

## Timezone setting for connections to OCI Servers

As the timezone of the OCI Server is not available via the REST API, it needs to be manually set so that all timestamps are displayed with the correct timezone. By default the timezone will be set to the local timezone of the PowerShell environment.

The currently configured timezone of the OCI Server can be checked with

```powershell
$CurrentOciServer.Timezone
```
    
A list of all available timezones can be shown with

```powershell
[System.TimeZoneInfo]::GetSystemTimeZones()
```

To set a different timezone (e.g. CEST or PST), the following command can be used

```powershell
$CurrentOciServer.Timezone = [System.TimeZoneInfo]::FindSystemTimeZoneById("Central Europe Standard Time")
$CurrentOciServer.Timezone = [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time")
```

## Simple workflow for retrieving data from OCI Servers

In this simple workflow the available storage systems will be retrieved, a NetApp FAS system will be choosen and then all internal volumes for this system will be retrieved.

```powershell
$Storages = Get-OciStorages
$NetAppStorage = $Storages | ? { $_.vendor -eq "NetApp" -and $_.family -eq "FAS" } | Select-Object -First 1
Get-OciInternalVolumesByStorage -id $Storage.id
```

As the OCI Cmdlets support pipelining, the above statements can be combined into one statement:

```powershell
Get-OciStorages | ? { $_.vendor -eq "NetApp" -and $_.family -eq "FAS" } | Select-Object -First 1 | Get-OciInternalVolumesByStorage
```

## Examples

### Retrieve all devices of all datasources

To retrieve all devices of all datasources, first get a list of all datasources and then get the devices of all datasources
```powershell
$Datasources = Get-OciDatasources
$Datasources | Get-OciDatasourceDevices
```

The following command combines getting the datasources and then getting their devices and also adds the datasource name to each device

```powershell
Get-OciDatasources | % { Get-OciDatasourceDevices $_.id | Add-Member -MemberType NoteProperty -Name Datasource -Value $_.Name -PassThru }
```

### Retrieve Performance data

Get-OciStorages | Get-OciVolumesByStorage | Get-OciVolume -Performance | % { New-Object -TypeName PSObject -Property @{Name=$_.Name;"Min total IOPS"=$_.performance.iops.total.min;"Max total IOPS"=$_.performance.iops.total.max; "Avg total IOPS"=$_.performance.iops.total.avg} } | ft -Wrap

### Update annotation

Retrieve a volume
```powershell
$Volume = Get-OciStorages | Get-OciVolumesByStorage | select -first 1
```

Show all annotations of the volume
```powershell
$Volume | Get-OciAnnotationsByVolume
```

Get the _note_ annotation and update the annotation value associated with the volume
```powershell
Get-OciAnnotations | ? { $_.name -eq "note" } | Update-OciAnnotationValues -objectType "Volume" -rawValue "Test" -targets $Volume.id
```

### Retrieve OCI Server health status

```powershell
Get-OciHealth
```

### Export to CSV

Retrieve OCI data (e.g. Storage Arrays)
```powershell
$Storages = Get-OciStorages
```

Specify filename, encording and delimiter for CSV file, then export to CSV
```powershell
$FileName = 'C:\tmp\test.csv'
$Encoding = 'UTF8'
$Delimiter = ';'
$Storages | Export-Csv -NoTypeInformation -Path $FileName -Encoding $Encoding -Delimiter $Delimiter
```

### Export to Excel

Retrieve OCI data (e.g. Storage Arrays)
```powershell
$Storages = Get-OciStorages
```

Specify filename, worksheet name and optionally a password to encrypt the Excel file. Then export to Excel
```powershell
$FileName = "$HOME\Documents\OCItest.xlsx"
$WorksheetName = 'Storage Arrays'
$Password = 'password'
$Storages | Export-Excel -FileName $FileName -WorksheetName $WorksheetName -Password $Password
```

You can easily add another worksheet to an existing Excel file with
```powershell
$FileName = "$HOME\Documents\OCItest.xlsx"
$WorksheetName = 'Additional worksheet'
$Password = 'password'
$Storages | Export-Excel -FileName $FileName -WorksheetName $WorksheetName -Password $Password
```

To create a single Excel file with many OCI objects, run the following commands
```powershell
$FileName = "$HOME\Documents\OCIOverview.xlsx"
Get-OciAcquisitionUnits | Export-Excel -FileName $FileName -WorksheetName 'Acquisition Units'
Get-OciAnnotations | Export-Excel -FileName $FileName -WorksheetName 'Annotations'
Get-OciApplications | Export-Excel -FileName $FileName -WorksheetName 'Applications'
Get-OciDatasources | Export-Excel -FileName $FileName -WorksheetName 'Datasources'
Get-OciDatastores | Export-Excel -FileName $FileName -WorksheetName 'Datastores'
Get-OciStorages | Get-OciDisksByStorage | Export-Excel -FileName $FileName -WorksheetName 'Disks'
Get-OciFabrics | Export-Excel -FileName $FileName -WorksheetName 'Fabrics'
Get-OciHosts | Get-OciFileSystemsByHost | Export-Excel -FileName $FileName -WorksheetName 'Filesystems'
Get-OciHealth | Export-Excel -FileName $FileName -WorksheetName 'Health'
Get-OciHosts | Export-Excel -FileName $FileName -WorksheetName 'Hosts'
Get-OciStorages | Get-OciInternalVolumesByStorage | Export-Excel -FileName $FileName -WorksheetName 'Internal Volumes'
Get-OciLicenses | Export-Excel -FileName $FileName -WorksheetName 'Licenses'
Get-OciPatches | Export-Excel -FileName $FileName -WorksheetName 'Patches'
Get-OciStorages | Get-OciStorageNodesByStorage | Export-Excel -FileName $FileName -WorksheetName 'Storage Nodes'
Get-OciStorages | Get-OciStoragePoolsByStorage | Export-Excel -FileName $FileName -WorksheetName 'Storage Pools'
Get-OciStorages | Export-Excel -FileName $FileName -WorksheetName 'Storages'
Get-OciSwitches | Export-Excel -FileName $FileName -WorksheetName 'Switches'
Get-OciUsers | Export-Excel -FileName $FileName -WorksheetName 'Users'
Get-OciVirtualMachines | Export-Excel -FileName $FileName -WorksheetName 'Virtual Machines'
Get-OciVirtualMachines | Get-OciVmdksByVirtualMachine | Export-Excel -FileName $FileName -WorksheetName 'VMDKs'
Get-OciStorages | Get-OciVolumesByStorage | Export-Excel -FileName $FileName -WorksheetName 'Volumes'
```

The output created above is helpful, but the capacity values are not properly displayed in Excel and relations between objects are not shown. The following section will show how to create Excel views similar to the views available in the OnCommand Insight Java GUI.

To format the Storage Arrays, 
```powershell
$FileName = "$HOME\Documents\OCIDetails.xlsx"
$Storages = foreach ($Storage in Get-OciStorages) {
	$Ports = $Storage | Get-OciPortsByStorage
	[PSCustomObject]@{Name=$Storage.name;IP=$Storage.ip;"Capacity (GB)"=[Math]::Round($Storage.capacity.total.value/1024);Vendor=$Storage.vendor;Family=$Storage.family;Model=$Storage.model;"Serial Number"=$Storage.serialNumber;"Microcode Version"=$Storage.microcodeVersion;"FC Port Count"=$Ports.count}
} 
$Storages | Export-Excel -FileName $FileName -WorksheetName 'Storages'
```