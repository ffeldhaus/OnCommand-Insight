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
Get-Command -Module OnCommand-Insight -Syntax
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

To force connections via HTTP use the `-HTTP` switch (HTTP is not available in OCI 7.2 and later)

```powershell
Connect-OciServer -Name $ServerName -Credential $Credential -HTTP
```

## Timezone setting for connections to OCI Servers

As the timezone of the OCI Server is not available via the REST API, it needs to be manually set so that all timestamps are displayed with the correct timezone. By default the timezone will be set to the local timezone of the PowerShell environment.

A list of all available timezones can be shown with

```powershell
[System.TimeZoneInfo]::GetSystemTimeZones()
```

You can set a different than the local timezone when connecting to the OCI server with e.g.
```powershell
Connect-OciServer -Name $ServerName -Timezone "Pacific Standard Time"
```

The currently configured timezone of the OCI Server can be checked with

```powershell
$CurrentOciServer.Timezone
```

To manually set a different timezone (e.g. CEST or PST), the following command can be used

```powershell
$CurrentOciServer.Timezone = [System.TimeZoneInfo]::FindSystemTimeZoneById("Central Europe Standard Time")
$CurrentOciServer.Timezone = [System.TimeZoneInfo]::FindSystemTimeZoneById("Pacific Standard Time")
```

## Simple workflow for retrieving data from OCI Servers

In this simple workflow the available storage systems will be retrieved, a NetApp FAS system will be choosen and then all internal volumes for this system will be retrieved.

```powershell
$Storages = Get-OciStorages
$NetAppStorages = $Storages | ? { $_.vendor -eq "NetApp" -and $_.family -match "FAS" } | Select-Object -First 1
$NetAppStorages | Get-OciInternalVolumesByStorage
```

As the OCI Cmdlets support pipelining, the above statements can be combined into one statement:

```powershell
Get-OciStorages | ? { $_.vendor -eq "NetApp" -and $_.family -match "FAS" } | Select-Object -First 1 | Get-OciInternalVolumesByStorage
```

## Managing OCI Credentials

The OCI PowerShell Cmdlets allow to securely store credentials in and retrieve credentials from the Windows Credential Manager. Please keep in mind that only the user who stored the credentials has access to them (especially important for automation) and that the user can retrieve the password in plain text.

To add a credential for an OCI server use the following command
```powershell
$ServerName = 'localhost'
Add-OciCredential -Name $ServerName -Credential (Get-Credential)
```

You can list all stored credentials with
```powershell
Get-OciCredentials
```

After a credential has been added, it is not necessary to supply the credential when connecting to the server
```powershell
Connect-OciServer -Name $ServerName
```

## Examples

### Retrieve all devices of all datasources

To retrieve all devices of all datasources you can use the following command. For large environments, especially with a large number of ESX Hosts, this command can take some time:
```powershell
Get-OciDatasources -Devices
```

### Retrieve Performance data

The following command will get all Volumes with all Performance Data. For everything else then small test environments this can result in huge amounts of data. Make sure to either only get the volumes for one storage system or restrict the timeframe for which you want to retrieve performance data with `-fromTime` and `-toTime`:

```powershell
$VolumesWithPerformance = Get-OciStorages | Get-OciVolumesByStorage -Performance -fromTime (Get-Date).addDays(-1)
```

To extract just the Minimum, Maximum and Average IOPS and pretty print the data use:
```powershell
$VolumesWithPerformance | % { New-Object -TypeName PSObject -Property @{Name=$_.Name;"Min total IOPS"=$_.performance.iops.total.min;"Max total IOPS"=$_.performance.iops.total.max; "Avg total IOPS"=$_.performance.iops.total.avg} } | ft -Wrap
```

### Get related objects

The OCI API allows to get related objects. E.g. for the internal volume it is possible to get related storage, performance, dataStores, computeResources, storagePool, volumes, storageNodes, applications, annotations, replicaSources, performancehistory. The related objects can be retrieved by specifying paramter switches. These can be shown with get-help:
```powershell
get-help Get-OciInternalVolume -Detailed
```

To retrieve all related objects for e.g. internal volumes use
```powershell
Get-OciStorages | Get-OciInternalVolumesByStorage | Select -first 1 | Get-OciInternalVolume -storage -performance -dataStores -computeResources -storagePool -volumes -storageNodes -applications -annotations -replicaSources -performancehistory -datasources -qtrees
```

### Annotations

#### Add new annotation

Applications can be of type DATE, TEXT, FIXED_ENUM, FLEXIBLE_ENUM, BOOLEAN or NUMBER. TEXT is the most flexible, but FLEXIBLE_ENUM may also be a good choice if the number of different values is low. FLEXIBLE_ENUM will automatically extend the list of values if a new value is added. FIXED_ENUM will only allow the predefined values and will give an error if an undefined value is added.

Add an application of type FLEXIBLE_ENUM
```powershell
Add-OciAnnotation -Name "Enum test" -Type FLEXIBLE_ENUM -Description "Enum test description" -enumValues @{name="Item name";label="Item label"}
```

#### Get annotations

Get all annotations
```powershell
Get-OciAnnotations
```

Get the previously added annotation
```powershell
$Annotation = Get-OciAnnotations | ? { $_.Name -eq "Enum test" }
```

#### Add an annotation value to an OCI object

Retrieve a volume
```powershell
$Volume = Get-OciStorages | Get-OciVolumesByStorage | select -first 1
```

Show all annotations of the volume
```powershell
$Volume | Get-OciAnnotationsByVolume
```

Add the previously defined annotation to the volume with a new value
```powershell
$Annotation | Update-OciAnnotationValues -objectType "Volume" -rawValue "New item" -targets $Volume.id
```

Check the annotation values of the annotation
```powershell
$Annotation | Get-OciAnnotationValues
```

Get the annotation and check that it contains the new value "New item"
```powershell
$Annotation | Get-OciAnnotation | Select -expandProperty enumValues
```

#### Delete all values of an annotation

OCI does not support deleting all annotation values out of the box, but the PowerShell Cmdlets do by first getting all values of an annotation and then removing them. Just run
```powershell
$Annotation | Remove-OciAnnotationValues
```

Check that the values have been deleted
```powershell
$Annotation | Get-OciAnnotationValues
```

### Retrieve OCI Server health status

```powershell
Get-OciHealth
```

### Show Information with Grid-View

An easy way to show tabular data and to filter columns is included in PowerShell with the Grid-View.

To show output in the Grid-View use
```powershell
Get-OciStorages | Out-Gridview -Title 'Storages'
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

Install PSExcel from https://github.com/RamblingCookieMonster/PSExcel and load PSExcel Module
```
Import-Module PSExcel
```

Retrieve OCI data (e.g. Storage Arrays)
```powershell
$Storages = Get-OciStorages
```

Specify filename and worksheet name for the Excel file. Then export to Excel
```powershell
$FileName = "$HOME\Documents\Ocitest.xlsx"
$WorksheetName = 'Storage Arrays'
$Storages | Export-XLSX -Path $FileName -WorksheetName $WorksheetName -Table -TableStyle Light1 -AutoFit
```

You can easily add another worksheet to an existing Excel file with
```powershell
$WorksheetName = 'Additional worksheet'
$Storages | Export-XLSX -Path $FileName -WorksheetName $WorksheetName -Table -TableStyle Light1 -AutoFit
```

To create a single Excel file with many OCI objects, run the following commands
```powershell
$FileName = "$HOME\Documents\OciOverview.xlsx"
Get-OciAcquisitionUnits | Export-XLSX -Path $FileName -WorksheetName 'Acquisition Units' -Table -TableStyle Light1 -AutoFit
Get-OciAnnotations | Export-XLSX -Path $FileName -WorksheetName 'Annotations' -Table -TableStyle Light1 -AutoFit
Get-OciApplications | Export-XLSX -Path $FileName -WorksheetName 'Applications' -Table -TableStyle Light1 -AutoFit
Get-OciDatasources | Export-XLSX -Path $FileName -WorksheetName 'Datasources' -Table -TableStyle Light1 -AutoFit
Get-OciDatastores | Export-XLSX -Path $FileName -WorksheetName 'Datastores' -Table -TableStyle Light1 -AutoFit
Get-OciStorages | Get-OciDisksByStorage | Export-XLSX -Path $FileName -WorksheetName 'Disks' -Table -TableStyle Light1 -AutoFit
Get-OciFabrics | Export-XLSX -Path $FileName -WorksheetName 'Fabrics' -Table -TableStyle Light1 -AutoFit
Get-OciHosts | Get-OciFileSystemsByHost | Export-XLSX -Path $FileName -WorksheetName 'Filesystems' -Table -TableStyle Light1 -AutoFit
Get-OciHealth | Export-XLSX -Path $FileName -WorksheetName 'Health' -Table -TableStyle Light1 -AutoFit
Get-OciHosts | Export-XLSX -Path $FileName -WorksheetName 'Hosts' -Table -TableStyle Light1 -AutoFit
Get-OciStorages | Get-OciInternalVolumesByStorage | Export-XLSX -Path $FileName -WorksheetName 'Internal Volumes' -Table -TableStyle Light1 -AutoFit
Get-OciLicenses | Export-XLSX -Path $FileName -WorksheetName 'Licenses' -Table -TableStyle Light1 -AutoFit
Get-OciPatches | Export-XLSX -Path $FileName -WorksheetName 'Patches' -Table -TableStyle Light1 -AutoFit
Get-OciStorages | Get-OciStorageNodesByStorage | Export-XLSX -Path $FileName -WorksheetName 'Storage Nodes' -Table -TableStyle Light1 -AutoFit
Get-OciStorages | Get-OciStoragePoolsByStorage | Export-XLSX -Path $FileName -WorksheetName 'Storage Pools' -Table -TableStyle Light1 -AutoFit
Get-OciStorages | Export-XLSX -Path $FileName -WorksheetName 'Storages' -Table -TableStyle Light1 -AutoFit
Get-OciSwitches | Export-XLSX -Path $FileName -WorksheetName 'Switches' -Table -TableStyle Light1 -AutoFit
Get-OciUsers | Export-XLSX -Path $FileName -WorksheetName 'Users' -Table -TableStyle Light1 -AutoFit
Get-OciVirtualMachines | Export-XLSX -Path $FileName -WorksheetName 'Virtual Machines' -Table -TableStyle Light1 -AutoFit
Get-OciVirtualMachines | Get-OciVmdksByVirtualMachine | Export-XLSX -Path $FileName -WorksheetName 'VMDKs' -Table -TableStyle Light1 -AutoFit
Get-OciStorages | Get-OciVolumesByStorage | Export-XLSX -Path $FileName -WorksheetName 'Volumes' -Table -TableStyle Light1 -AutoFit
```

The output created above is helpful, but the capacity values are not properly displayed in Excel and relations between objects are not shown. The following section will show how to create Excel views similar to the views available in the OnCommand Insight Java GUI.

To format the Storage Arrays the following commands can be used
```powershell
$FileName = "$HOME\Documents\OCIDetails.xlsx"
$Storages = foreach ($Storage in Get-OciStorages) {
	$StorageData = [ordered]@{	
		'Name'=$Storage.name;
		'IP'=$Storage.ip;
		'Capacity (GB)'='not available via API';
		'Raw Capacity (GB)'=$Storage.capacity.total.value/1024;
		'Protocols'='not available via API';
		'Array Virtualization Type'='not available via API';
		'Vendor'=$Storage.vendor;
		'Family'=$Storage.family;
		'Model'=$Storage.model;
		'Serial Number'=$Storage.serialNumber;
		'Microcode Version'=$Storage.microcodeVersion;
		'FC Port Count'='not available via API';
		'Last Report Time'='not available via API';
		'Is the device offline?'='not available via API';
		'Tenant'='not available via API';
		'Line of Business'='not available via API';
		'Business Unit'='not available via API';
		'Project'='not available via API';
	}
	foreach ($Annotation in ($Storage | Get-OciAnnotationsByStorage)) {
		$StorageData[$Annotation.label] = $Annotation.displayValue
	}
	[PSCustomObject]$StorageData
} 
$Storages | Sort-Object -Property @{Expression={$_.psobject.properties | Measure-Object | Select-Object -ExpandProperty Count};Descending=$true} | Export-XLSX -Path $FileName -WorksheetName 'Storages'
```

To format the Internal Volumes, the following commands can be used
```powershell
$FileName = "$HOME\Documents\OCIDetails.xlsx"
$InternalVolumes = foreach ($Storage in Get-OciStorages) {
	foreach ($InternalVolume in ($Storage | Get-OciInternalVolumesByStorage -storage -storagePool -volumes -storageNodes -Datastores -applications -annotations -replicaSources)) {
		$InternalVolumeData = [ordered]@{
			Name=$InternalVolume.name;
			Storage=$InternalVolume.storage.name;
			'SVM/vFiler'=$InternalVolume.virtualStorage;
			Nodes=$InternalVolume.storageNodes.name -join ',';
			'HA Partner'='not available via API';
			'Capacity (GB)'=$InternalVolume.capacity.total.value/1024;
			'RAW Capacity (GB)'=$InternalVolume.capacity.rawToUsableRatio*$InternalVolume.capacity.total.value/1024;
			'Used Capacity (GB)'=$InternalVolume.capacity.used.value/1024;
			'Used Capacity (%)'=[Math]::Round($InternalVolume.capacity.used.value/$InternalVolume.capacity.total.value*100);
			'Consumed Capacity (GB)'=$(if ($InternalVolume.capacity.isThinProvisioned) { $InternalVolume.capacity.total.value/1024 } else { $InternalVolume.capacity.used.value/1024 });
			'Storage Pool'=$InternalVolume.storagePool.name;
			Type=$InternalVolume.type;
			'Flash Pool Eligibility'=$InternalVolume.flashPoolEligibility;
			'Thin Provisioned'=$InternalVolume.capacity.isThinProvisioned;
			'Volume Count'=$InternalVolume.volumes.count;
			'Share Count'='not available via API';
			Datastore=$InternalVolume.dataStores.name -join ',';
			'Storage Guarantee'=$InternalVolume.spaceGuarantee;
			'Deduplication Savings'=$InternalVolume.dedupeSavings.value;
			'Clone Source'='not available via API';
			'Clone Shared Capacity (GB)'='not available via API';
			'Replication Technology'='not available via API';
			'Replication Mode'='not available via API';
			'Replica Source Storage'='not available via API';
			'Replica Source Internal Volume'=$InternalVolume.replicaSources.name -join ',';
			'Status'=$InternalVolume.status;
			'Snapshot Reserve (GB)'='not available via API';
			'Snapshot Used (%)'='not available via API';
			'Snapshot Overflow (GB)'='not available via API';
			'Snapstots Count'='not available via API';
			'Last Snapshot'='not available via API';
			'Disk Types'='not available via API';
			'Disk Size'='not available via API';
			'Disk Speed (RPM)'='not available via API';
			'Application'=$InternalVolume.applications.name -join ',';
			'Application Priority'=$InternalVolume.applications.priority -join ',';
			'Tenant'=$InternalVolume.applications.businessEntity.tenant -join ',';
			'Line of Business'=$InternalVolume.applications.businessEntity.lob -join ',';
			'Business Unit'=$InternalVolume.applications.businessEntity.businessUnit -join ',';
			'Project'=$InternalVolume.applications.businessEntity.project -join ',';
		}
		foreach ($Annotation in ($InternalVolume.annotations)) {
			$InternalVolumeData[$Annotation.label] = $Annotation.displayValue
		}
		[PSCustomObject]$InternalVolumeData
	}
} 
$InternalVolumes | Sort-Object -Property @{Expression={$_.psobject.properties | Measure-Object | Select-Object -ExpandProperty Count};Descending=$true} |  Export-XLSX -Path $FileName -WorksheetName 'Internal Volumes'
```

### List devices discovered via multiple datasources

```powershell
$Datasources = Get-OciDatasources -devices
$DuplicateDevices = $Datasources.devices.Name | Group-Object | ? { $_.Count -gt 1 } | Select -ExpandProperty Name
foreach ($Device in $DuplicateDevices) {
    "$Device," + (($Datasources | ? { $_.Devices.name -match $Device } | select -ExpandProperty Name) -join ',')
}
```powershell

### Create new Datasource`

First get a list of all supported datasource types
```powershell
Get-OciDatasourceTypes
```

Select the datasource type you want to configure:
```powershell
$type = Get-OciDatasourceTypes | ? { $_.description -match "CMode" }
```

Select the acquisition unit to use for the datasource:
```powershell
$acquisitionUnit = Get-OciAcquisitionUnits | Select -first 1
```

Now create a new datasource from the type to work with locally (this does not create anything on the server yet!):
```powershell
$Datasource = New-OciDatasource -name "test" -acquisitionUnit $acquisitionUnit -type $type
```

Regardless of the datasource type, all datasources will have a foundation package. Other packages like storageperformance, cloud, hostvirtualization are datasource type specific. Check the available packages and their attributes with
```powershell
$Datasource.config.packages
$Datasource.config.foundation.attributes
$Datasource.config.storageperformance.attributes
```

The attributes are filled with the default values from the type definition. You may now change some of the attributes
```powershell
$Datasource.config.foundation.attributes.forceTLS = $true
$Datasource.config.foundation.attributes.ip = "192.168.1.100"
```

To set username and password, it is recommended to use `Get-Credential`:
```powershell
$Credential = Get-Credential
$Datasource.config.foundation.attributes.user = $Credential.UserName
$Datasource.config.foundation.attributes.password = $Credential.GetNetworkCredential().password
```

Most additional packages like storageperformance are disabled by default and need to be enabled
```powershell
$Datasource.config.storageperformance.attributes.enabled = $true
```

Now the datasource can be added to the OCI server
```powershell
$Datasource = $Datasource | Add-OciDatasource
```

Check that the status of the datasource changes to success which indicates successfull collection of data
```powershell
$Datasource | Get-OciDatasource
```

To remove the datasource, use
```powershell
$Datasource | Remove-OciDatasource
```

### Manage Datasource Configuration

Get all datasources including its configuration
```powershell
Get-OciDatasources -config
```

Get a single datasource including its configuration
```powershell
Get-OciDatasource -id 1 -config
```

The configuration contains packages (e.g. foundation, performance, cloud) and each package has several attributes which can be modified. 

Here's an example to change the password of a single datasource:
```powershell
$Datasource = Get-OciDatasources | Select -first 1 | Get-OciDatasource -config
# modify password attribute
$Datasource.config.packages.foundation.attributes.password = "test"
# update datasource
$Datasource | Update-OciDatasource
```

Here's an example to change the password of all datasources:
```powershell
$Datasources = Get-OciDatasources -config
# modify password attribute
$Datasources | % { $_.config.packages.foundation.attributes.password = "test" }
# update datasources
$Datasources | Update-OciDatasource
```

### Creating and restoring OCI

All available Backups on the OCI Server can be retrieved with
```powershell
Get-OciBackups
```

A backup can be created with and stored under C:\tmp
```powershell
$Path = "C:\tmp"
Get-OciBackup -Path $Path
```

A backup can be restored with
```powershell
$BackupLocation = "C:\tmp\Backup_Lab_NetApp_Munich_V7-2-0_B773_D20160417_2300_4959387166860292236.zip
Restore-OciBackup -FilePath $BackupLocation
```

The latest Backup available on the OCI Server can be restored with
```powershell
Get-OciBackups | Sort -Property Date -Descending | select -first 1 | Restore-OciBackup
```

## Manage Applications and Business Entities

You can create a Business Entity with
```powershell
$BusinessUnity = Add-OciBusinessEntity -Tenant "tenant" -LineOfBusiness "lof" -BusinessUnit "bu" -Project "project"
```

You can get all Business Entities with
```powershell
Get-OciBusinessEntities
```

You can remove all Business Entities with
```powershell
Get-OciBusinessEntities | Remove-OciBusinessEntities
```

You can create a Application with
```powershell
$Application = Add-OciApplication -name "application" -priority Critical -businessEntity $BusinessEntity.id -ignoreShareViolations
```

You can update an application with 
```powershell
$Application | Update-OciApplication -priority Low
```

Remove all applications
```powershell
Get-OciApplications | Remove-OciApplication
```

## Troubleshooting

If you encounter issues with timeouts, this may be due to slow OCI Servers or very large environments. Try increasing the Timout from the default of 600 seconds (10 minutes) when connecting to the OCI Server

```powershell
$ServerName = 'localhost'
$Timeout = 1200
Connect-OciServer -Name $ServerName -Timeout $Timeout
```

Alternatively you can configure the timeout direcly using the $CurrentOciServer variable
```powershell
$CurrentOciServer.Timeout = 1200
```