# Workaround to allow Powershell to accept untrusted certificates
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
       public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
 
# Using .NET JSON Serializer as JSON serialization included in Invoke-RestMethod has a length restriction for JSON content
Add-Type -AssemblyName System.Web.Extensions
$global:javaScriptSerializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$global:javaScriptSerializer.MaxJsonLength = [System.Int32]::MaxValue
$global:javaScriptSerializer.RecursionLimit = 99
 
# Functions necessary to parse JSON output from .NET serializer to PowerShell Objects
function ParseItem($jsonItem) {
    if($jsonItem.PSObject.TypeNames -match "Array") {
        return ParseJsonArray($jsonItem)
    }
    elseif($jsonItem.PSObject.TypeNames -match "Dictionary") {
        return ParseJsonObject([HashTable]$jsonItem)
    }
    else {
        return $jsonItem
    }
}
 
function ParseJsonObject($jsonObj) {
    $result = New-Object -TypeName PSCustomObject
    foreach ($key in $jsonObj.Keys) {
        $item = $jsonObj[$key]
        if ($item) {
            if ($key -eq "history") {
                $parsedItem = $item | % { ParseJsonObject(($_[1]+@{time=($_[0] | ConvertFrom-UnixDate)})) }
            } else {
                $parsedItem = ParseItem $item
            }
        } else {
            $parsedItem = $null
        }
        $result | Add-Member -MemberType NoteProperty -Name $key -Value $parsedItem
    }
    return $result
}
 
function ParseJsonArray($jsonArray) {
    $result = @()
    $jsonArray | ForEach-Object {
        $result += ,(ParseItem $_)
    }
    return $result
}
 
function ParseJsonString($json) {
    $config = $javaScriptSerializer.DeserializeObject($json)
    if ($config -is [Array]) {
        return ParseJsonArray($config)       
    }
    else {
        return ParseJsonObject($config)
    }
}

# helper function to convert datetime to unix timestamp
function ConvertTo-UnixTimestamp {
       $epoch = Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0  
      $input | % { 
        if ($_ -is [datetime]) {
                  $milliSeconds = [math]::truncate($_.ToUniversalTime().Subtract($epoch).TotalMilliSeconds)
        }
        else {
            $milliSeconds = $_
        }
              Write-Output $milliSeconds
       }     
}
 
# helper function to convert unix timestamp to datetime
function ConvertFrom-UnixDate {
    $input | % {
        $date = $CurrentOciServer.Timezone.ToLocalTime(([datetime]'1/1/1970').AddMilliseconds($_))
        Write-Output $date
    }
}

# OCI Examples
$OciExamples=@{}

$OciExamples['Add-OciPatches'] = @"
"@

$OciExamples['Add-OciUsers'] = @"
"@

$OciExamples['Approve-OciPatch'] = @"
    .EXAMPLE
    Approve-OciPatch -Id 1
"@

$OciExamples['Delete-OciUser'] = @"
    .EXAMPLE
    Delete-OciUser -id 1
"@

$OciExamples['Get-OciAcquisitionUnit'] = @"
    .EXAMPLE
    Get-OciAcquisitionUnit -id 1

    id               : 1
    self             : /rest/v1/admin/acquisitionUnits/1
    name             : local
    ip               : 192.168.222.138
    status           : CONNECTED
    isActive         : True
    leaseContract    : 120000
    nextLeaseRenewal : 2015-08-17T21:19:46+0200
    lastReported     : 2015-08-17T21:17:41+0200
"@

$OciExamples['Get-OciAcquisitionUnits'] = @"
    .EXAMPLE
    Get-OciAcquisitionUnits

    id               : 1
    self             : /rest/v1/admin/acquisitionUnits/1
    name             : local
    ip               : 192.168.222.138
    status           : CONNECTED
    isActive         : True
    leaseContract    : 120000
    nextLeaseRenewal : 2015-08-17T21:18:46+0200
    lastReported     : 2015-08-17T21:16:52+0200
"@

$OciExamples['Get-OciActivePatchByDatasource'] = @"
    .EXAMPLE
    Get-OciActivePatchByDatasource -id 1
    .EXAMPLE
    Get-OciDatasources | Get-OciActivePatchByDatasource
"@

$OciExamples['Get-OciActivePatchByDatasource'] = @"
    .EXAMPLE
    Get-OciActivePatchByDatasource -id 1
    .EXAMPLE
    Get-OciDatasources | Get-OciActivePatchByDatasource
"@

$OciExamples['Get-OciAnnotation'] = @"
    .EXAMPLE
    Get-OciAnnotation -id 4977

    id                   : 4977
    self                 : /rest/v1/assets/annotations/4977
    name                 : Rack
    type                 : TEXT
    label                : Rack
    isUserDefined        : False
    enumValues           : {}
    supportedObjectTypes : {Host, Switch, Storage}
"@

<#
.EXAMPLE
Connect-OciServer -Name ociserver.example.com -Credential (Get-Credential)

Name       : ociserver.example.com
BaseURI    : https://ociserver.example.com
Credential : System.Management.Automation.PSCredential
Headers    : {Authorization}
APIVersion : 1.2
Timezone   : System.CurrentSystemTimeZone
#>
function global:Connect-OciServer {
    [CmdletBinding()]
 
    PARAM (
        [parameter(Mandatory=$True,
                   Position=0,
                   HelpMessage="The name of the OCI Server. This value may also be a string representation of an IP address. If not an address, the name must be resolvable to an address.")][String]$Name,
        [parameter(Mandatory=$True,
                   Position=1,
                   HelpMessage="A System.Management.Automation.PSCredential object containing the credentials needed to log into the OCI server.")][System.Management.Automation.PSCredential]$Credential,
        [parameter(Mandatory=$False,
                   Position=2,
                   HelpMessage="This cmdlet always tries to establish a secure HTTPS connection to the OCI server, but it will fall back to HTTP if necessary. Specify -HTTP to skip the HTTPS connection attempt and only try HTTP.")][Switch]$HTTP,
        [parameter(Mandatory=$False,
                   Position=2,
                   HelpMessage="This cmdlet always tries to establish a secure HTTPS connection to the OCI server, but it will fall back to HTTP if necessary. Specify -HTTPS to fail the connection attempt in that case rather than fall back to HTTP.")][Switch]$HTTPS,
        [parameter(Mandatory=$False,
                   Position=3,
                   HelpMessage="If the OCI server certificate cannot be verified, the connection will fail. Specify -Insecure to ignore the validity of the OCI server certificate.")][Switch]$Insecure,
        [parameter(Position=4,
                   Mandatory=$False,
                   HelpMessage="Specify -Transient to not set the global variable `$CurrentOciServer.")][Switch]$Transient
    )
 
    # Issue with jBoss see http://alihamdar.com/2010/06/19/expect-100-continue/
    [System.Net.ServicePointManager]::Expect100Continue = $false
 
    $EncodedAuthorization = [System.Text.Encoding]::UTF8.GetBytes($Credential.UserName + ':' + $Credential.GetNetworkCredential().Password)
    $EncodedPassword = [System.Convert]::ToBase64String($EncodedAuthorization)
    $Headers = @{"Authorization"="Basic $($EncodedPassword)"}
 
    if ($Insecure) {
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    }
 
    if ($HTTPS) {
        Try {
            $BaseURI = "https://$Name"
            $Response = Invoke-RestMethod -Method Post -Uri "$BaseURI/rest/v1/login" -TimeoutSec 10 -Headers $Headers
            $APIVersion = $Response.apiVersion
        }
        Catch {
            if ($_.Exception.Message -match "Unauthorized") {
                Write-Error "Authorization for $BaseURI/rest/v1/login with user $($Credential.UserName) failed"
                return
            }
            else {
                Write-Error "Login to $BaseURI/rest/v1/login failed via HTTPS protocol, but HTTPS was enforced"
                return
            }
        }
    }
    elseif ($HTTP) {
        Try {
            $BaseURI = "https://$Name"
            $Response = Invoke-RestMethod -Method Post -Uri "$BaseURI/rest/v1/login" -TimeoutSec 10 -Headers $Headers
            $APIVersion = $Response.apiVersion
        }
        Catch {
            if ($_.Exception.Message -match "Unauthorized") {
                Write-Error "Authorization for $BaseURI/rest/v1/login with user $($Credential.UserName) failed"
                return
            }
            else {
                Write-Error "Login to $BaseURI/rest/v1/login failed via HTTP protocol, but HTTP was enforced"
                return
            }
        }
    }
    else {
        Try {
            $BaseURI = "https://$Name"
            $Response = Invoke-RestMethod -Method Post -Uri "$BaseURI/rest/v1/login" -TimeoutSec 10 -Headers $Headers
            $APIVersion = $Response.apiVersion
            $HTTPS = $True
        }
        Catch {
            if ($_.Exception.Message -match "Unauthorized") {
                Write-Error "Authorization for $BaseURI/rest/v1/login with user $($Credential.UserName) failed"
                return
            }
            else {
                Write-Warning "Login to $BaseURI/rest/v1/login failed via HTTPS protocol, falling back to HTTP protocol."
                Try {
                    $BaseURI = "http://$Name"
                    $Response = Invoke-RestMethod -Method Post -Uri "$BaseURI/rest/v1/login" -TimeoutSec 10 -Headers $Headers
                    $APIVersion = $Response.apiVersion
                    $HTTP = $True
                }
                Catch {
                    if ($_.Exception.Message -match "Unauthorized") {
                        Write-Error "Authorization for $BaseURI/rest/v1/login with user $($Credential.UserName) failed"
                        return
                    }
                    else {
                        Write-Error "Login to $BaseURI/rest/v1/login failed via HTTP protocol."
                        return
                    }
                }
            }
        }
    }
 
    $Server = New-Object -TypeName psobject
    $Server | Add-Member -MemberType NoteProperty -Name Name -Value $Name
    $Server | Add-Member -MemberType NoteProperty -Name BaseURI -Value $BaseURI
    $Server | Add-Member -MemberType NoteProperty -Name Credential -Value $Credential
    $Server | Add-Member -MemberType NoteProperty -Name Headers -Value $Headers
    $Server | Add-Member -MemberType NoteProperty -Name APIVersion -Value $APIVersion
    $Server | Add-Member -MemberType NoteProperty -Name Timezone -Value $([timezone]::CurrentTimeZone)
 
    if (!$Transient) {
        Set-Variable -Name CurrentOciServer -Value $Server -Scope Global
    }
 
    if (!$APIVersion -eq "1.2") {
        Generate-OciCmdlets -BaseURI $BaseURI
    }
 
    return $Server
}
 
function Get-OciCmdlets {
    [CmdletBinding()]
 
    PARAM (
        [parameter(Mandatory=$True,
                   Position=0,
                   HelpMessage="Base URI of the OCI Server.")][String]$BaseURI,
        [parameter(Mandatory=$False,
                   Position=1,
                   HelpMessage="Path for filename to store Cmdlets in.")][String]$FilePath)

    $DocumentationURI = $BaseURI + "/rest/v1/documentation/sections"
    Write-Verbose "Retrieving REST API Documentation from $DocumentationURI"
    $Sections = Invoke-RestMethod -Uri $DocumentationURI -Headers $CurrentOciServer.Headers
 
    Write-Verbose "Generating OCI Cmdlets for each section of the API documentation"
    foreach ($Section in $($Sections.APIs  | ? { $_.path -notmatch '/login|/search' })) {
        Write-Verbose "Retrieving details for section $($Section.description)"
        $Section = Invoke-RestMethod -Uri ($($Sections.BasePath) + $Section.path) -Headers $CurrentOciServer.Headers
        foreach ($API in $($Section.APIs)) {
            foreach ($Operation in $($API.Operations)) {
                $Name = $Operation.Nickname -replace ".*_",""
                $Name = $Name -creplace '^([a-z]*)([A-Z])','$1-Oci$2'
                $Name = [Regex]::Replace($Name, '\b(\w)', { param($m) $m.Value.ToUpper() })
                $Name = $Name -replace '-OciOne|-OciAll','-Oci'
                $Name = $Name -replace 'Delete-','Remove-'
                $Name = $Name -replace 'Suspend-','Remove-'
 
                ### Fixing of wrong nicknames
                switch -Exact ($Operation.httpMethod + ' ' + $API.path) {
                    'GET /rest/v1/admin/datasources' {
                        $Name = "Get-OciDatasources"
                    }
                    'DELETE /rest/v1/admin/datasources/{id}' {
                        $Name = "Remove-OciDatasource"
                    }
                    'GET /rest/v1/admin/datasources/{id}' {
                        $Name = "Get-OciDatasource"
                    }
                    'GET /rest/v1/admin/datasources/{id}/activePatch' {
                        $Name = "Get-OciActivePatchByDatasource"
                    }
                    'POST /rest/v1/admin/datasources/{id}/poll' {
                        $Name = "Poll-OciDatasource"
                    }
                    'POST /rest/v1/admin/datasources/{id}/postpone' {
                        $Name = "Suspend-OciDatasource"
                    }
                    'POST /rest/v1/admin/datasources/{id}/resume' {
                        $Name = "Resume-OciDatasource"
                    }
                    'POST /rest/v1/admin/datasources/{id}/test' {
                        $Name = "Test-OciDatasource"
                    }
                    'GET /rest/v1/admin/licenses' {
                        $Name = "Get-OciLicenses"
                    }
                    'POST /rest/v1/admin/licenses' {
                        $Name = "Replace-OciLicenses"
                    }
                    'PUT /rest/v1/admin/licenses' {
                        $Name = "Update-OciLicenses"
                    }
                    'POST /rest/v1/admin/licenses' {
                        $Name = "Replace-OciLicenses"
                    }
                    'GET /rest/v1/admin/patches' {
                        $Name = "Get-OciPatches"
                    }
                    'POST /rest/v1/admin/patches' {
                        $Name = "Add-OciPatches"
                    }
                    'GET /rest/v1/admin/patches/{id}' {
                        $Name = "Get-OciPatch"
                    }
                    'GET /rest/v1/admin/patches/{id}' {
                        $Name = "Update-OciPatch"
                    }
                    'GET /rest/v1/admin/users' {
                        $Name = "Get-OciUsers"
                    }
                    'POST /rest/v1/admin/users' {
                        $Name = "Add-OciUsers"
                    }
                    'DELETE /rest/v1/admin/users/{id}' {
                        $Name = "Delete-OciUser"
                    }
                    'GET /rest/v1/admin/users/{id}' {
                        $Name = "Get-OciUser"
                    }
                    'PUT /rest/v1/admin/users/{id}' {
                        $Name = "Update-OciUser"
                    }
                    'GET /rest/v1/assets/annotations' {
                        $Name = "Get-OciAnnotations"
                    }
                    'GET /rest/v1/assets/annotations/{id}' {
                        $Name = "Get-OciAnnotation"
                    }
                    'GET /rest/v1/assets/annotations/{id}/values' {
                        $Name = "Get-OciAnnotationValues"
                    }
                    'PUT /rest/v1/assets/annotations/{id}/values' {
                        $Name = "Update-OciAnnotationValues"
                    }
                    'GET /rest/v1/assets/annotations/{id}/values/{objectType}' {
                        $Name = "Get-OciAnnotationValuesByObjectType"
                    }
                    'GET /rest/v1/assets/annotations/{id}/values/{objectType}/{value}' {
                        $Name = "Update-OciAnnotationValuesByObjectTypeAndValue"
                    }
                    'GET /rest/v1/assets/applications' {
                        $Name = "Get-OciApplications"
                    }
                    'GET /rest/v1/assets/applications/{id}' {
                        $Name = "Get-OciApplication"
                    }
                    'GET /rest/v1/assets/dataStores' {
                        $Name = "Get-OciDatastores"
                    }
                    'GET /rest/v1/assets/dataStores/{id}' {
                        $Name = "Get-OciDatastore"
                    }
                    'DELETE /rest/v1/assets/dataStores/{id}/annotations' {
                        $Name = "Remove-OciAnnotationsByDatastore"
                    }
                    'GET /rest/v1/assets/dataStores/{id}/annotations' {
                        $Name = "Get-OciAnnotationsByDatastore"
                    }
                    'PUT /rest/v1/assets/dataStores/{id}/annotations' {
                        $Name = "Update-OciAnnotationsByDatastore"
                    }
                    'GET /rest/v1/assets/dataStores/{id}/hosts' {
                        $Name = "Get-OciHostsByDatastore"
                    }
                    'GET /rest/v1/assets/dataStores/{id}/performance' {
                        $Name = "Get-OciDatastorePerformance"
                    }
                    'GET /rest/v1/assets/dataStores/{id}/storageResources' {
                        $Name = "Get-OciStorageResourcesByDatastore"
                    }
                    'GET /rest/v1/assets/dataStores/{id}/vmdks' {
                        $Name = "Get-OciVmdksByDatastore"
                    }
                    'GET /rest/v1/assets/disks/{id}' {
                        $Name = "Get-OciDisk"
                    }
                    'DELETE /rest/v1/assets/disks/{id}/annotations' {
                        $Name = "Remove-OciAnnotationsByDisk"
                    }
                    'GET /rest/v1/assets/disks/{id}/annotations' {
                        $Name = "Get-OciAnnotationsByDisk"
                    }
                    'PUT /rest/v1/assets/disks/{id}/annotations' {
                        $Name = "Update-OciAnnotationsByDisk"
                    }
                    'GET /rest/v1/assets/disks/{id}/backendVolumes' {
                        $Name = "Get-OciBackendVolumesByDisk"
                    }
                    'GET /rest/v1/assets/disks/{id}/performance' {
                        $Name = "Get-OciDiskPerformance"
                    }
                    'GET /rest/v1/assets/fabrics' {
                        $Name = "Get-OciFabrics"
                    }
                    'GET /rest/v1/assets/fabrics/{id}' {
                        $Name = "Get-OciFabric"
                    }
                    'GET /rest/v1/assets/fileSystems/{id}' {
                        $Name = "Get-OciFilesystem"
                    }
                    'GET /rest/v1/assets/fileSystems/{id}' {
                        $Name = "Get-OciFilesystem"
                    }
                    'GET /rest/v1/assets/hosts' {
                        $Name = "Get-OciHosts"
                    }
                    'DELETE /rest/v1/assets/hosts/{id}/annotations' {
                        $Name = "Remove-OciAnnotationsByHosts"
                    }
                    'GET /rest/v1/assets/hosts/{id}/annotations' {
                        $Name = "Get-OciAnnotationsByHosts"
                    }
                    'PUT /rest/v1/assets/hosts/{id}/annotations' {
                        $Name = "Update-OciAnnotationsByHost"
                    }
                    'GET /rest/v1/assets/hosts/{id}/performance' {
                        $Name = "Get-OciHostPerformance"
                    }
                    'GET /rest/v1/assets/hosts/{id}/performance' {
                        $Name = "Get-OciHostPerformance"
                    }
                    'GET /rest/v1/assets/hosts/{id}/ports' {
                        $Name = "Get-OciPortsByHost"
                    }
                    'GET /rest/v1/assets/internalVolumes/{id}' {
                        $Name = "Get-OciInternalVolume"
                    }
                    'DELETE /rest/v1/assets/internalVolumes/{id}/annotations' {
                        $Name = "Remove-OciAnnotationsByInternalVolume"
                    }
                   'GET /rest/v1/assets/internalVolumes/{id}/annotations' {
                        $Name = "Get-OciAnnotationsByInternalVolume"
                    }
                    'PUT /rest/v1/assets/internalVolumes/{id}/annotations' {
                        $Name = "Update-OciAnnotationsByInternalVolume"
                    }
                    'GET /rest/v1/assets/internalVolumes/{id}/performance' {
                        $Name = "Get-OciInternalVolumePerformance"
                    }
                    'GET /rest/v1/assets/ports/{id}' {
                        $Name = "Get-OciPorts"
                    }
                    'DELETE /rest/v1/assets/ports/{id}/annotations' {
                        $Name = "Remove-OciAnnotationsByPort"
                    }
                    'GET /rest/v1/assets/ports/{id}/annotations' {
                        $Name = "Get-OciAnnotationsByPort"
                    }
                    'PUT /rest/v1/assets/ports/{id}/annotations' {
                        $Name = "Update-OciAnnotationsByPort"
                    }
                    'GET /rest/v1/assets/ports/{id}/device' {
                        $Name = "Get-OciDeviceByPort"
                    }
                    'GET /rest/v1/assets/ports/{id}/fabrics' {
                        $Name = "Get-OciFabricsByPort"
                    }
                    'GET /rest/v1/assets/ports/{id}/performance' {
                        $Name = "Get-OciPortPerformance"
                    }
                    'GET /rest/v1/assets/storageNodes/{id}' {
                        $Name = "Get-OciStorageNode"
                    }
                    'DELETE /rest/v1/assets/storageNodes/{id}/annotations' {
                        $Name = "Remove-OciAnnotationsByStorageNode"
                    }
                    'GET /rest/v1/assets/storageNodes/{id}/annotations' {
                        $Name = "Get-OciAnnotationsByStorageNode"
                    }
                    'PUT /rest/v1/assets/storageNodes/{id}/annotations' {
                        $Name = "Update-OciAnnotationsByStorageNode"
                    }
                    'GET /rest/v1/assets/storageNodes/{id}/performance' {
                        $Name = "Get-OciStorageNodePerformance"
                    }
                    'GET /rest/v1/assets/storagePools/{id}' {
                        $Name = "Get-OciStoragePool"
                    }
                    'DELETE /rest/v1/assets/storagePools/{id}/annotations' {
                        $Name = "Remove-OciAnnotationsByStoragePool"
                    }
                    'GET /rest/v1/assets/storagePools/{id}/annotations' {
                        $Name = "Get-OciAnnotationsByStoragePool"
                    }
                    'PUT /rest/v1/assets/storagePools/{id}/annotations' {
                        $Name = "Update-OciAnnotationsByStoragePool"
                    }
                    'GET /rest/v1/assets/storagePools/{id}/disks' {
                        $Name = "Get-OciDisksByStoragePool"
                    }
                    'GET /rest/v1/assets/storagePools/{id}/performance' {
                        $Name = "Get-OciStoragePoolPerformance"
                    }
                    'GET /rest/v1/assets/storagePools/{id}/storage' {
                        $Name = "Get-OciStorageByStoragePool"
                    }
                    'GET /rest/v1/assets/storagePools/{id}/storageNodes' {
                        $Name = "Get-OciStorageNodesByStoragePool"
                    }
                    'GET /rest/v1/assets/storagePools/{id}/storageResources' {
                        $Name = "Get-OciStorageResourcesByStoragePool"
                    }
                    'GET /rest/v1/assets/storages' {
                        $Name = "Get-OciStorages"
                    }
                    'GET /rest/v1/assets/storages/{id}' {
                        $Name = "Get-OciStorage"
                    }
                    'GET /rest/v1/assets/storages/{id}/performance' {
                        $Name = "Get-OciStoragePerformance"
                    }
                    'DELETE /rest/v1/assets/storages/{id}/annotations' {
                        $Name = "Remove-OciAnnotationsByStorage"
                    }
                    'GET /rest/v1/assets/storages/{id}/annotations' {
                        $Name = "Get-OciAnnotationsByStorage"
                    }
                    'PUT /rest/v1/assets/storages/{id}/annotations' {
                        $Name = "Update-OciAnnotationsByStorage"
                    }
                    'GET /rest/v1/assets/switches' {
                        $Name = "Get-OciSwitches"
                    }
                    'GET /rest/v1/assets/switches/{id}' {
                        $Name = "Get-OciSwitch"
                    }
                    'DELETE /rest/v1/assets/switches/{id}/annotations' {
                        $Name = "Remove-OciAnnotationsBySwitch"
                    }
                    'GET /rest/v1/assets/switches/{id}/annotations' {
                        $Name = "Get-OciAnnotationsBySwitch"
                    }
                    'PUT /rest/v1/assets/switches/{id}/annotations' {
                        $Name = "Update-OciAnnotationsBySwitch"
                    }
                    'GET /rest/v1/assets/switches/{id}/performance' {
                        $Name = "Get-OciSwitchPerformance"
                    }
                    'GET /rest/v1/assets/virtualMachines' {
                        $Name = "Get-OciVirtualMachines"
                    }
                    'GET /rest/v1/assets/virtualMachines/{id}' {
                        $Name = "Get-OciVirtualMachine"
                    }
                    'DELETE /rest/v1/assets/virtualMachines/{id}/annotations' {
                        $Name = "Remove-OciAnnotationsByVirtualMachine"
                    }
                    'GET /rest/v1/assets/virtualMachines/{id}/annotations' {
                        $Name = "Get-OciAnnotationsByVirtualMachine"
                    }
                    'PUT /rest/v1/assets/virtualMachines/{id}/annotations' {
                        $Name = "Update-OciAnnotationsByVirtualMachine"
                    }
                    'GET /rest/v1/assets/virtualMachines/{id}/applications' {
                        $Name = "Get-OciApplicationsByVirtualMachine"
                    }
                    'GET /rest/v1/assets/virtualMachines/{id}/performance' {
                        $Name = "Get-OciVirtualMachinePerformance"
                    }
                    'GET /rest/v1/assets/virtualMachines/{id}/vmdks' {
                        $Name = "Get-OciVmdksByVirtualMachine"
                    }
                    'DELETE /rest/v1/assets/vmdks/{id}/annotations' {
                        $Name = "Remove-OciAnnotationsByVmdk"
                    }
                    'GET /rest/v1/assets/vmdks/{id}/annotations' {
                        $Name = "Get-OciAnnotationsByVmdk"
                    }
                    'PUT /rest/v1/assets/vmdks/{id}/annotations' {
                        $Name = "Update-OciAnnotationsByVmdk"
                    }
                    'GET /rest/v1/assets/vmdks/{id}/performance' {
                        $Name = "Get-OciVmdkPerformance"
                    }
                    'GET /rest/v1/assets/volumes/{id}' {
                        $Name = "Get-OciVolume"
                    }
                    'DELETE /rest/v1/assets/volumes/{id}/annotations' {
                        $Name = "Remove-OciAnnotationsByVolume"
                    }
                    'GET /rest/v1/assets/volumes/{id}/annotations' {
                        $Name = "Get-OciAnnotationsByVolume"
                    }
                    'PUT /rest/v1/assets/volumes/{id}/annotations' {
                        $Name = "Update-OciAnnotationsByVolume"
                    }
                    'GET /rest/v1/assets/volumes/{id}/applications' {
                        $Name = "Get-OciApplicationsByVolume"
                    }
                    'GET /rest/v1/assets/volumes/{id}/autoTierPolicy' {
                        $Name = "Get-OciAutoTierPolicyByVolume"
                    }
                    'GET /rest/v1/assets/volumes/{id}/dataStores' {
                        $Name = "Get-OciDatastoresByVolume"
                    }
                    'GET /rest/v1/assets/volumes/{id}/internalVolume' {
                        $Name = "Get-OciInternalVolumeByVolume"
                    }
                    'GET /rest/v1/assets/volumes/{id}/performance' {
                        $Name = "Get-OciVolumePerformance"
                    }
                    'GET /rest/v1/assets/volumes/{id}/ports' {
                        $Name = "Get-OciPortsByVolume"
                    }
                    'GET /rest/v1/assets/volumes/{id}/replicaSources' {
                        $Name = "Get-OciSourceVolumesByVolume"
                    }
                    'GET /rest/v1/assets/volumes/{id}/storage' {
                        $Name = "Get-OciStorageByVolume"
                    }
                    'GET /rest/v1/assets/volumes/{id}/storageNodes' {
                        $Name = "Get-OciStorageNodesByVolume"
                    }
                    'GET /rest/v1/assets/volumes/{id}/storagePools' {
                        $Name = "Get-OciStoragePoolsByVolume"
                    }
                }
 
                Write-Verbose "Generating parameters"
 
                $Position = 0
                $Body = ''
                $CmdletParameters = ''
                $CmdletParametersDescription = ''
 
                # POST / PUT parameters
                switch -Exact ($Operation.httpMethod + ' ' + $API.path) {
                    'POST /rest/v1/admin/datasources/{id}/postpone' {
                        $operation.parameters += New-Object -TypeName PSCustomObject -Property @{Name="Days";Required=$True;Description="Number of days to postpone datasource polling";DataType="Long";AllowMultiple=$False}
                        $body = '{`"days`":$days}'
                    }
                    'PUT /rest/v1/admin/datasources/{id}/note' {
                        $operation.parameters += New-Object -TypeName PSCustomObject -Property @{Name="value";Required=$True;Description="Note to be added to datasource";DataType="String";AllowMultiple=$False}
                        $body = '{`"value`":$value}'
                    }
                    'POST /rest/v1/admin/datasources/{id}/test' {
                        $operation.parameters += New-Object -TypeName PSCustomObject -Property @{Name="id";Required=$True;Description="Id of data source to test";DataType="Long";AllowMultiple=$True}
                        $body = ''
                    }
                    'PUT /rest/v1/admin/licenses' {
                        $operation.parameters += New-Object -TypeName PSCustomObject -Property @{Name="Licenses";Required=$True;Description="String with License keys separated by ,";DataType="String";AllowMultiple=$False}
                        $body = '$licenses'
                    }
                }
               
                foreach ($Parameter in $($operation.parameters)) {
                    if ($Position -gt 0) {
                        $CmdletParameters += ",`n"
                        $CmdletParametersDescription += "`n"
                    }
 
                    if ($Parameter.Name -eq "id") {
                        $CmdletParameters += @"
        [parameter(Mandatory=`$$($Parameter.required),
                    Position=$Position,
                    HelpMessage="$($Parameter.description)",
                    ValueFromPipeline=`$True,
                    ValueFromPipelineByPropertyName=`$True)][$($Parameter.dataType)[]]`$$($Parameter.Name)
"@
                    }
                    elseif ($Parameter.Name -eq "fromTime" -or $Parameter.Name -eq "toTime") {
                        $CmdletParameters += @"
        [parameter(Mandatory=`$$($Parameter.required),
                    Position=$Position,
                    HelpMessage="$($Parameter.description)")][PSObject]`$$($Parameter.Name)
"@
                    }
                    else {
                        $CmdletParameters += @"
        [parameter(Mandatory=`$$($Parameter.required),
                    Position=$Position,
                    HelpMessage="$($Parameter.description)")][$($Parameter.dataType)$(if ($($Parameter.allowMultiple)) { "[]" })]`$$($Parameter.Name)
"@
                    }
               
                    $CmdletParametersDescription += @"
    .PARAMETER $($Parameter.Name)
    $($Parameter.Description)
"@
                    $Position += 1
                }
 
                $properties = ($Section.models.$($Operation.responseClass)).properties.psobject.Properties.value
                if ($properties | ? { $_.description -eq "performance" }) {
                    $properties += New-Object -TypeName PSCustomObject -Property @{type="List";description="Performance History";expands="true";items=@{type="PerformanceHistory"}}
                }
 
                foreach ($model in $properties) {
                    if ($model.expands -eq 'true') {
                        if ($model.type -eq 'List' -and -not $model.items.type -eq "PerformanceHistory") {
                            $Model | Add-Member -MemberType NoteProperty -Name Name -Value (($model.items.type -replace ' ','') + 's') -Force
                        }
                        else {
                            if ($model.description -eq 'host') {
                                $model.description = 'hostswitch'
                            }
                            $Model | Add-Member -MemberType NoteProperty -Name Name -Value ($model.description -replace ' ','') -Force
                        }
                        if ($Position -gt 0) {
                            $CmdletParameters += ",`n"
                            $CmdletParametersDescription += "`n"
                        }
                        $CmdletParameters += @"
        [parameter(Mandatory=`$False,
                    Position=$Position,
                    HelpMessage="$($model.description)")][Switch]`$$($Model.Name)
"@
                    $CmdletParametersDescription += @"
        .PARAMETER $($Model.Name)
        $($model.Description)
"@
               
                        $Position += 1
                    }
                }
 
                $switchparameters=$properties | ? { $_.Name } | % { $_.Name }
                $switchparameters="@(`"" + ($switchparameters -join "`",`"") + "`")"
 
                Write-Verbose "Generating Cmdlet $Name for $($API.Path)"
                $CmdletFunction = @"
<#
    .SYNOPSIS
    $($Operation.Summary)
    .DESCRIPTION
    $($Operation.Notes)
    $($OciExamples[$Name])
$CmdletParametersDescription
#>
function Global:$Name {
    [CmdletBinding()]
 
    PARAM (
$CmdletParameters
    )
 
    Begin {
        `$Result = `$null
    }
   
    Process {
        $`id = @(`$id)
        foreach (`$id in `$id) {
            `$Uri = `$(`$CurrentOciServer.BaseUri) + "$($API.Path)" -replace "{id}","`$id"
 
           
            $`switchparameters=$switchparameters
            foreach (`$parameter in `$switchparameters) {
                if ((Get-Variable `$parameter).Value) {
                    if (`$expand) {
                        `$expand += ",`$(`$parameter.toLower() -replace 'performancehistory','performance.history' -replace 'hostswitch','host')"
                    }
                    else {
                        `$expand = `$(`$parameter.toLower() -replace 'performancehistory','performance.history' -replace 'hostswitch','host')
                    }
                }
            }
 
            if (`$fromTime -or `$toTime -or `$expand) {
                `$Uri += '?'
                `$Separator = ''
                if (`$fromTime) {
                    `$Uri += "fromTime=`$(`$fromTime | ConvertTo-UnixTimestamp)"
                    `$Separator = '&'
                }
                if (`$toTime) {
                    `$Uri += "`$(`$Separator)toTime=`$(`$toTime | ConvertTo-UnixTimestamp)"
                    `$Separator = '&'
                }
                if (`$expand) {
                    `$Uri += "`$(`$Separator)expand=`$expand"
                }
            }
 
            try {
                if ('$($Operation.httpMethod)' -match 'PUT|POST') {
                    `$Result = Invoke-RestMethod -Method $($Operation.httpMethod) -Uri `$Uri -Headers `$CurrentOciServer.Headers -Body "$Body" -ContentType 'application/json'
                }
                else {
                    `$Result = Invoke-RestMethod -Method $($Operation.httpMethod) -Uri `$Uri -Headers `$CurrentOciServer.Headers
                }
            }
            catch {
                `$Response = `$_.Exception.Response
                `$Result = `$Response.GetResponseStream()
                `$Reader = New-Object System.IO.StreamReader(`$Result)
                `$responseBody = `$reader.ReadToEnd()
                Write-Error "$($Operation.httpMethod) to `$Uri failed with response:``n`$responseBody"
            }
 
            if (`$Result.toString().Trim().startsWith('{') -or `$Result.toString().Trim().startsWith('[')) {
                `$Result = ParseJsonString(`$Result.Trim())
            }
           
            if (`$Result.performance) {
                if (`$Result.performance.history) {
                    if (`$Result.performance.history[0].count -eq 2) {
                        foreach (`$entry in `$Result.performance.history) {
                            if ($`entry[1]) {
                                `$entry = New-Object -TypeName PSCustomObject -Property (`$entry[1] | Add-Member -MemberType NoteProperty -Name Timestamp -Value (`$entry[0] | ConvertFrom-UnixDate) )
                            }
                            else {
                                `$entry = `$null
                            }
                        }
                    }
                }
            }
       
            Write-Output `$Result
        }
    }
}

"@
           
                Write-Debug "$CmdletFunction"
                if ($FilePath) {
                    Out-File -Append -FilePath $FilePath -InputObject $CmdletFunction -Encoding utf8
                }
                else {
                    Invoke-Command -ScriptBlock ([ScriptBlock]::Create($CmdletFunction))
                }
            }
        }
    }
 
    # add Search Cmdlet
    $CmdletFunction = @"
<#
    .SYNOPSIS
    Search for OCI Objects
    .DESCRIPTION
    Search for OCI Objects
    .PARAMETER query
    Query parameter
#>
function Global:Search-Oci {
    [CmdletBinding()]
 
    PARAM (
            [parameter(Mandatory=`$true,
                    Position=0,
                    HelpMessage="The search query expression parameter",
                    ValueFromPipeline=`$True,
                    ValueFromPipelineByPropertyName=`$True)][string[]]`$query
    )
 
    Begin {
        `$Result = `$null
    }
   
    
    Process {
        foreach (`$query in `$query) {
            `$Uri = `$(`$CurrentOciServer.BaseUri) + "/rest/v1/search?query=`$query"
 
            try {
                `$Result = Invoke-RestMethod -Method Get -Uri `$Uri -Headers `$CurrentOciServer.Headers
                if (`$Result.toString().startsWith('{')) {
                    `$Result = ParseJsonString(`$Result)
                }
            }
            catch {
                `$Response = `$_.Exception.Response
                `$Result = `$Response.GetResponseStream()
                `$Reader = New-Object System.IO.StreamReader(`$Result)
                `$responseBody = `$reader.ReadToEnd()
                Write-Error "GET to `$Uri failed with response:`n`$responseBody"
            }
       
            Write-Output `$Result.resultsByCategory
        }
    }
}
"@

    Write-Debug "$CmdletFunction"
    if ($FilePath) {
        Out-File -Append -FilePath $FilePath -InputObject $CmdletFunction -Encoding utf8
    }
    else {
        Invoke-Command -ScriptBlock ([ScriptBlock]::Create($CmdletFunction))
    }
}