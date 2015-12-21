Import-Module $PSScriptRoot\epplus
. $PSScriptRoot\CredentialManager.ps1

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

# functions to add and get credentials from the Windows Credential Manager
function Add-OciCredential {
    [CmdletBinding()]
 
    PARAM (
        [parameter(Mandatory=$True,
                   Position=0,
                   HelpMessage="The name of the OCI Server. This value may also be a string representation of an IP address. If not an address, the name must be resolvable to an address.")][String]$Name,
        [parameter(Mandatory=$True,
                   Position=1,
                   HelpMessage="A System.Management.Automation.PSCredential object containing the credentials needed to log into the OCI server.")][System.Management.Automation.PSCredential]$Credential
    )

    $null = Add-WindowsCredential -Target $Name -UserName $Credential.UserName -Password ($Credential.Password | ConvertFrom-SecureString) -Comment 'OnCommand-Insight'
}

function Get-OciCredential {
    [CmdletBinding()]
 
    PARAM (
        [parameter(Mandatory=$True,
                   Position=0,
                   HelpMessage="The name of the OCI Server. This value may also be a string representation of an IP address. If not an address, the name must be resolvable to an address.")][String]$Name
    )

    $WindowsCredential = Get-WindowsCredential -Target $Name
    if ($WindowsCredential) {
        $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList @($WindowsCredential.UserName,($WindowsCredential.CredentialBlob | ConvertTo-SecureString))
        [PSCustomObject]@{Name=($WindowsCredential.TargetName -replace '.*target=','');Credential=$Credential}
    }
}

function Get-OciCredentials {
    [CmdletBinding()]

    PARAM ()
 
    $WindowsCredentials = Get-WindowsCredentials | ? { $_.Comment -eq 'OnCommand-Insight' }

    foreach ($WindowsCredential in $WindowsCredentials) {
        if ($WindowsCredential) {
            $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList @($WindowsCredential.UserName,($WindowsCredential.CredentialBlob | ConvertTo-SecureString))
            [PSCustomObject]@{Name=($WindowsCredential.TargetName -replace '.*target=','');Credential=$Credential}
        }
    }
}

function Remove-OciCredential {
    [CmdletBinding()]
 
    PARAM (
        [parameter(Mandatory=$True,
                   Position=0,
                   HelpMessage="The name of the OCI Server. This value may also be a string representation of an IP address. If not an address, the name must be resolvable to an address.")][String]$Name
    )

    $null = Remove-WindowsCredential -Target $Name
}
 
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
            $parsedItem = ParseItem $item
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

<#
.EXAMPLE
Export-Excel
#>
function global:Export-Excel {
    [CmdletBinding()]
 
    PARAM (
        [parameter(Mandatory=$True,
                   Position=0,
                   HelpMessage="Input Object.",
                   ValueFromPipeline=$True)][PSObject[]]$InputObject,
        [parameter(Mandatory=$True,
                   Position=1,
                   HelpMessage="Filename of the Excel file to be created or updated.")][String]$FileName,
        [parameter(Mandatory=$True,
                   Position=2,
                   HelpMessage="The Worksheet name to be created or replaced")][String]$WorksheetName,
        [parameter(Mandatory=$False,
                   Position=3,
                   HelpMessage="Password to protect file with AES-256 encryption.")][String]$Password
    )

    Begin {
        if ($FileName -notmatch '.xlsx') {
            $FileName += '.xlsx'
        } 

        try {
            if ($Password) {
                $ExcelPackage = New-Object OfficeOpenXml.ExcelPackage -ArgumentList $FileName,$Password
            }
            else {
                $ExcelPackage = New-Object OfficeOpenXml.ExcelPackage -ArgumentList $FileName
            }
        }
        catch {
            throw $_
        }

        # if worksheet already exists, delete it
        if ($ExcelPackage.Workbook.Worksheets[$WorksheetName]) {
            $ExcelPackage.Workbook.Worksheets.Delete($WorksheetName)
        }

        $Worksheet = $ExcelPackage.Workbook.Worksheets.Add($WorksheetName)

        $Format = New-object -TypeName OfficeOpenXml.ExcelTextFormat -Property @{TextQualifier = '"'}
        $Format.Delimiter = ";"
        # use Text Qualifier if your CSV entries are quoted, e.g. "Cell1","Cell2"
        $Format.TextQualifier = '"'
        $Format.Encoding = [System.Text.Encoding]::UTF8
        $Format.SkipLinesEnd = 1

        $TableStyle = [OfficeOpenXml.Table.TableStyles]::Light9

        $SetHeader = $True
    }

    Process {
        if ($InputObject) {
            # only add the header for the first object
            if ($SetHeader) {
                $CsvString += $InputObject | ConvertTo-Csv -Delimiter ';' -NoTypeInformation | Out-String
                $SetHeader = $False
            }
            else {
                $CsvString += $InputObject | ConvertTo-Csv -Delimiter ';' -NoTypeInformation | select -skip 1 | Out-String
            }
        }
    }

    End {
        if ($CsvString) {
            $null=$Worksheet.Cells.LoadFromText($CsvString,$Format,$TableStyle,$true)
            $Worksheet.Cells[$Worksheet.Dimension.Address].AutoFitColumns()
        }

        if ($Password) {
            $ExcelPackage.Encryption.Algorithm = [OfficeOpenXml.EncryptionAlgorithm]::AES256
            $ExcelPackage.Encryption.IsEncrypted = $true
            $ExcelPackage.SaveAs($FileName,$Password)
        } else {
            $ExcelPackage.Encryption.IsEncrypted = $false
            $ExcelPackage.SaveAs($FileName)
        }
        $ExcelPackage.Dispose()
        $ExcelPackage = $null
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
        [parameter(Mandatory=$False,
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

    if (!$Credential) {
        $Credential = Get-OciCredential -Name $Name | select -ExpandProperty Credential
        if (!$Credential) {
            throw "No Credentials supplied and $Name not in list of known OCI Servers"
        }
    }
 
    # Issue with jBoss see http://alihamdar.com/2010/06/19/expect-100-continue/
    [System.Net.ServicePointManager]::Expect100Continue = $false
 
    $EncodedAuthorization = [System.Text.Encoding]::UTF8.GetBytes($Credential.UserName + ':' + $Credential.GetNetworkCredential().Password)
    $EncodedPassword = [System.Convert]::ToBase64String($EncodedAuthorization)
    $Headers = @{"Authorization"="Basic $($EncodedPassword)"}
 
    # check if untrusted SSL certificates should be ignored
    if ($Insecure) {
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    }

    # check if proxy is used
    $ProxyRegistry = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $ProxySettings = Get-ItemProperty -Path $ProxyRegistry
    if ($ProxySettings.ProxyEnable) {
        Write-Warning "Proxy Server $($ProxySettings.ProxyServer) configured in Internet Explorer may be used to connect to the OCI server!"
    }
    if ($ProxySettings.AutoConfigURL) {
        Write-Warning "Proxy Server defined in automatic proxy configuration script $($ProxySettings.AutoConfigURL) configured in Internet Explorer may be used to connect to the OCI server!"
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
        Get-OciCmdlets -Server [PSCustomObject]@{BaseURI=$BaseURI}
    }
 
    return $Server
}
 
function Get-OciCmdlets {
    [CmdletBinding()]
 
    PARAM (
        [parameter(Mandatory=$False,
                   Position=0,
                   HelpMessage="Path for filename to store Cmdlets in.")][String]$FilePath,
        [parameter(Mandatory=$False,
                   Position=1,
                   HelpMessage="OnCommand Insight Server to get cmdlets from.")][PSObject]$Server)

    if (!$Server) {
        $Server = $CurrentOciServer
    }

    $DocumentationURI = $Server.BaseURI + "/rest/v1/documentation/sections"
    Write-Verbose "Retrieving REST API Documentation from $DocumentationURI"
    $Sections = Invoke-RestMethod -Uri $DocumentationURI -Headers $Server.Headers
 
    Write-Verbose "Generating OCI Cmdlets for each section of the API documentation"
    foreach ($Section in $($Sections.APIs  | ? { $_.path -notmatch '/login|/search' })) {
        Write-Verbose "Retrieving details for section $($Section.description)"
        $Section = Invoke-RestMethod -Uri ($($Sections.BasePath) + $Section.path) -Headers $Server.Headers
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
                    'GET /rest/v1/admin/license' {
                        $Name = "Get-OciLicense"
                    }
                    'POST /rest/v1/admin/license' {
                        $Name = "Replace-OciLicense"
                    }
                    'PUT /rest/v1/admin/license' {
                        $Name = "Update-OciLicense"
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
                    'POST /rest/v1/assets/applications' {
                        $Name = "Add-OciApplication"
                    }
                    'GET /rest/v1/assets/applications/{id}' {
                        $Name = "Get-OciApplication"
                    }
                    'GET /rest/v1/assets/businessEntities' {
                        $Name = "Get-OciBusinessEntities"
                    }
                    'GET /rest/v1/assets/businessEntities/{id}' {
                        $Name = "Get-OciBusinessEntity"
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
                    'GET /rest/v1/assets/internalVolumes/{id}/applications' {
                        $Name = "Get-OciApplicationsByInternalVolume"
                    }
                    'POST /rest/v1/assets/internalVolumes/{id}/applications' {
                        $Name = "Update-OciApplicationsByInternalVolume"
                    }
                    'GET /rest/v1/assets/internalVolumes/{id}/performance' {
                        $Name = "Get-OciInternalVolumePerformance"
                    }
                    'GET /rest/v1/assets/ports/{id}' {
                        $Name = "Get-OciPort"
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
                    'POST /rest/v1/assets/volumes/{id}/applications' {
                        $Name = "Update-OciApplicationsByVolume"
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
                    'PUT /rest/v1/assets/annotations/{id}/values' {
                        $operation.parameters += New-Object -TypeName PSCustomObject -Property @{Name="objectType";Required=$True;Description="Object type of objects where annotations should be added (e.g. StoragePool or InternalVolume)";DataType="String";AllowMultiple=$False}
                        $operation.parameters += New-Object -TypeName PSCustomObject -Property @{Name="rawValue";Required=$True;Description="Value of Annotation";DataType="String";AllowMultiple=$False}
                        $operation.parameters += New-Object -TypeName PSCustomObject -Property @{Name="targets";Required=$True;Description="IDs of object where annotation should be added";DataType="String";AllowMultiple=$True}
                        $body = '[ { `"objectType`": `"$objectType`",`"values`": [ { `"rawValue`": `"$rawValue`", `"targets`": [ `"$($targets -join ",")`" ] } ] } ]'
                    }
                    'POST /rest/v1/assets/volumes/{id}/applications' {
                        $operation.parameters += New-Object -TypeName PSCustomObject -Property @{Name="applicationId";Required=$True;Description="Valid application id which should be associated";DataType="String";AllowMultiple=$False}
                        $body = '{ `"id`": `"$applicationId`" }'
                    }
                    'POST /rest/v1/assets/internalVolumes/{id}/applications' {
                        $operation.parameters += New-Object -TypeName PSCustomObject -Property @{Name="applicationId";Required=$True;Description="Valid application id which should be associated";DataType="String";AllowMultiple=$False}
                        $body = '{ `"id`": `"$applicationId`" }'
                    }
                    'POST /rest/v1/assets/applications' {
                        $operation.parameters += New-Object -TypeName PSCustomObject -Property @{Name="name";Required=$True;Description="Name of the application";DataType="String";AllowMultiple=$False}
                        $operation.parameters += New-Object -TypeName PSCustomObject -Property @{Name="priority";Required=$False;Description="Name of the application";DataType="String";AllowMultiple=$False}
                        $operation.parameters += New-Object -TypeName PSCustomObject -Property @{Name="businessEntity";Required=$True;Description="Business entity of the application";DataType="String";AllowMultiple=$False}
                        $body = '{ `"name`": `"$name`", `"priority`": `"$priority`", `"businessEntity`": { `"id`": `"$businessEntity`" } }'
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
 
                $responseClass = $Operation.responseClass -replace 'List\[(.*)\]','$1'
                $properties = ($Section.models.$responseClass).properties.psobject.Properties
 
                # Add expand property for performance history as it is not included in the properties list
                if ($properties.name -match 'performance') {
                    $properties += New-Object -TypeName PSCustomObject -Property @{Name='performancehistory';value=@{description='Performance History';expands='true'}}
                }

                foreach ($model in $properties) {
                    if ($model.value.expands -eq 'true') {
                        if ($Position -gt 0) {
                            $CmdletParameters += ",`n"
                            $CmdletParametersDescription += "`n"
                        }

                        # In PowerShell the host parameter is a reserverd parameter, so we have to replace it with hostswitch
                        if ($mode.name -eq 'host') {
                            $ModelName = 'hostswitch'
                        }
                        else {
                            $ModelName = $model.Name
                        }

                        if ($model.value.type -eq 'List') {
                            $HelpMessage = "Return list of related $($model.value.description)"
                        }
                        else {
                            $HelpMessage = "Return related $($model.value.description)"
                        }

                        $CmdletParameters += @"
        [parameter(Mandatory=`$False,
                    Position=$Position,
                    HelpMessage="$HelpMessage")][Switch]`$$($ModelName)
"@
                    $CmdletParametersDescription += @"
        .PARAMETER $($ModelName)
        $HelpMessage
"@
               
                        $Position += 1
                    }
                }
 
                $switchparameters=$properties | ? { $_.Value.expands -eq 'true' } | % { $_.Name }
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
                        `$expand += ",`$(`$parameter -replace 'performancehistory','performance.history' -replace 'hostswitch','host')"
                    }
                    else {
                        `$expand = `$(`$parameter -replace 'performancehistory','performance.history' -replace 'hostswitch','host')
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
                    Write-Verbose "Body: $Body"
                    `$Result = Invoke-RestMethod -Method $($Operation.httpMethod) -Uri `$Uri -Headers `$CurrentOciServer.Headers -Body "$Body" -ContentType 'application/json'
                }
                else {
                    `$Result = Invoke-RestMethod -Method $($Operation.httpMethod) -Uri `$Uri -Headers `$CurrentOciServer.Headers
                }
            }
            catch {
                `$Response = `$_.Exception.Response
                if (`$Response) {
                    `$Result = `$Response.GetResponseStream()
                    `$Reader = New-Object System.IO.StreamReader(`$Result)
                    `$responseBody = " with response:``n" + `$reader.ReadToEnd()
                } 
                Write-Error "$($Operation.httpMethod) to `$Uri failed`$responseBody"
            }
 
            if (`$Result.toString().Trim().startsWith('{') -or `$Result.toString().Trim().startsWith('[')) {
                `$Result = ParseJsonString(`$Result.Trim())
            }
           
            # check performance data
            foreach (`$Object in `$Result) {
                if (`$Object.performance) {
                    # convert timestamps from unix to data format
                    if (`$Object.performance.accessed) {
                        `$Object.performance.accessed.start = `$Object.performance.accessed.start | ConvertFrom-UnixDate
                        `$Object.performance.accessed.end = `$Object.performance.accessed.end | ConvertFrom-UnixDate
                    }
                    if (`$Object.performance.iops) {
                        `$Object.performance.iops.read.start = `$Object.performance.iops.read.start | ConvertFrom-UnixDate
                        `$Object.performance.iops.read.end = `$Object.performance.iops.read.end | ConvertFrom-UnixDate
                        `$Object.performance.iops.write.start = `$Object.performance.iops.write.start | ConvertFrom-UnixDate
                        `$Object.performance.iops.write.end = `$Object.performance.iops.write.end | ConvertFrom-UnixDate
                        `$Object.performance.iops.totalMax.start = `$Object.performance.iops.totalMax.start | ConvertFrom-UnixDate
                        `$Object.performance.iops.totalMax.end = `$Object.performance.iops.totalMax.end | ConvertFrom-UnixDate
                        `$Object.performance.iops.total.start = `$Object.performance.iops.total.start | ConvertFrom-UnixDate
                        `$Object.performance.iops.total.end = `$Object.performance.iops.total.end | ConvertFrom-UnixDate
                    }
                    if (`$Object.performance.cacheHitRatio) {
                        `$Object.performance.cacheHitRatio.read.start = `$Object.performance.cacheHitRatio.read.start | ConvertFrom-UnixDate
                        `$Object.performance.cacheHitRatio.read.end = `$Object.performance.cacheHitRatio.read.end | ConvertFrom-UnixDate
                        `$Object.performance.cacheHitRatio.write.start = `$Object.performance.cacheHitRatio.write.start | ConvertFrom-UnixDate
                        `$Object.performance.cacheHitRatio.write.end = `$Object.performance.cacheHitRatio.write.end | ConvertFrom-UnixDate
                        `$Object.performance.cacheHitRatio.total.start = `$Object.performance.cacheHitRatio.total.start | ConvertFrom-UnixDate
                        `$Object.performance.cacheHitRatio.total.end = `$Object.performance.cacheHitRatio.total.end | ConvertFrom-UnixDate
                    }
                    if (`$Object.performance.latency) {
                        `$Object.performance.latency.read.start = `$Object.performance.latency.read.start | ConvertFrom-UnixDate
                        `$Object.performance.latency.read.end = `$Object.performance.latency.read.end | ConvertFrom-UnixDate
                        `$Object.performance.latency.write.start = `$Object.performance.latency.write.start | ConvertFrom-UnixDate
                        `$Object.performance.latency.write.end = `$Object.performance.latency.write.end | ConvertFrom-UnixDate
                        `$Object.performance.latency.total.start = `$Object.performance.latency.total.start | ConvertFrom-UnixDate
                        `$Object.performance.latency.total.end = `$Object.performance.latency.total.end | ConvertFrom-UnixDate
                        `$Object.performance.latency.totalMax.start = `$Object.performance.latency.totalMax.start | ConvertFrom-UnixDate
                        `$Object.performance.latency.totalMax.end = `$Object.performance.latency.totalMax.end | ConvertFrom-UnixDate
                    }
                    if (`$Object.performance.partialBlocksRatio.total) {
                        `$Object.performance.partialBlocksRatio.total.start = `$Object.performance.partialBlocksRatio.total.start | ConvertFrom-UnixDate
                        `$Object.performance.partialBlocksRatio.total.end = `$Object.performance.partialBlocksRatio.total.end | ConvertFrom-UnixDate
                    }
                    if (`$Object.performance.writePending.total) {
                        `$Object.performance.writePending.total.start = `$Object.performance.writePending.total.start | ConvertFrom-UnixDate
                        `$Object.performance.writePending.total.end = `$Object.performance.writePending.total.end | ConvertFrom-UnixDate
                    }
                    if (`$Object.performance.throughput) {
                        `$Object.performance.throughput.read.start = `$Object.performance.throughput.read.start | ConvertFrom-UnixDate
                        `$Object.performance.throughput.read.end = `$Object.performance.throughput.read.end | ConvertFrom-UnixDate
                        `$Object.performance.throughput.write.start = `$Object.performance.throughput.write.start | ConvertFrom-UnixDate
                        `$Object.performance.throughput.write.end = `$Object.performance.throughput.write.end | ConvertFrom-UnixDate
                        `$Object.performance.throughput.totalMax.start = `$Object.performance.throughput.totalMax.start | ConvertFrom-UnixDate
                        `$Object.performance.throughput.totalMax.end = `$Object.performance.throughput.totalMax.end | ConvertFrom-UnixDate
                        `$Object.performance.throughput.total.start = `$Object.performance.throughput.total.start | ConvertFrom-UnixDate
                        `$Object.performance.throughput.total.end = `$Object.performance.throughput.total.end | ConvertFrom-UnixDate
                    }

                    # check and convert historical performance data
                    if (`$Object.performance.history) {
                        if (`$Object.performance.history[0].count -eq 2) {
                            `$Object.performance.history = foreach (`$entry in `$Object.performance.history) {
                                if ($`entry[1]) {
                                    `$entry[1] | Add-Member -MemberType NoteProperty -Name timestamp -Value (`$entry[0] | ConvertFrom-UnixDate) -PassThru
                                }
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
                if (`$Response) {
                    `$Result = `$Response.GetResponseStream()
                    `$Reader = New-Object System.IO.StreamReader(`$Result)
                    `$responseBody = " with response:``n" + `$reader.ReadToEnd()
                } 
                Write-Error "$($Operation.httpMethod) to `$Uri failed`$responseBody"
            }
       
            Write-Output `$Result.resultsByCategory
        }
    }
}
"@

    # add Health Cmdlet
    $CmdletFunction = @"
<#
    .SYNOPSIS
    Retrieve OCI Server health status
    .DESCRIPTION
    Retrieve OCI Server health status
#>
function Global:Get-OciHealth {
    [CmdletBinding()]

    PARAM ()
 
    Begin {
        `$Result = `$null
    }
   
    Process {
        `$Uri = `$(`$CurrentOciServer.BaseUri) + "/rest/v1/admin/health"
 
        try {
            `$Result = Invoke-RestMethod -Method Get -Uri `$Uri -Headers `$CurrentOciServer.Headers
            if (`$Result.toString().startsWith('{')) {
                `$Result = ParseJsonString(`$Result)
            }
        }
        catch {
            `$Response = `$_.Exception.Response
            if (`$Response) {
                `$Result = `$Response.GetResponseStream()
                `$Reader = New-Object System.IO.StreamReader(`$Result)
                `$responseBody = " with response:``n" + `$reader.ReadToEnd()
            } 
            Write-Error "$($Operation.httpMethod) to `$Uri failed`$responseBody"
        }

        foreach (`$Item in `$Result) {
            `$Item.time = `$Item.time | ConvertFrom-UnixDate
        }
       
        Write-Output `$Result
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