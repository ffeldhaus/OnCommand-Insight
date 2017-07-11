function New-GithubRelease {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][String]$Version,
        [Parameter(Mandatory = $true)][String]$Name,
        [Parameter(Mandatory = $true)][String]$ReleaseNotes,
        [Parameter(Mandatory = $true)][String]$OutputDirectory,
        [Parameter(Mandatory = $true)][String]$FileName,
        [Parameter(Mandatory = $false)][String]$GitHubUsername="ffeldhaus",
        [Parameter(Mandatory = $false)][String]$GitHubRepository="OnCommand-Insight",
        [Parameter(Mandatory = $false)][switch]$Draft=$false,
        [Parameter(Mandatory = $false)][switch]$PreRelease=$false,
        [Parameter(Mandatory = $false)][switch]$RunTests=$true
    )

    # The github API key must be available in $GitHubApiKey (https://github.com/blog/1509-personal-api-tokens)

    # The Commit SHA for corresponding to this release
    $CommitId = git rev-list -n 1 "refs/tags/$Version"

    $ReleaseData = @{
       tag_name = $Version;
       target_commitish = $CommitId;
       name = $Name;
       body = $ReleaseNotes;
       draft = $Draft.IsPresent;
       prerelease = $PreRelease.IsPresent;
     }

    $ReleaseParams = @{
       Uri = "https://api.github.com/repos/$GitHubUsername/$GitHubRepository/releases";
       Method = 'POST';
       Headers = @{
         Authorization = 'token ' + $GitHubApiKey;
       }
       ContentType = 'application/json';
       Body = (ConvertTo-Json $releaseData -Compress)
     }

     $Result = Invoke-RestMethod @ReleaseParams 
     $UploadUri = $Result | Select -ExpandProperty upload_url
     $UploadUri = $UploadUri -replace '\{\?name,label\}',"?name=$FileName"
     $UploadFile = Join-Path -path $OutputDirectory -childpath $FileName

     $uploadParams = @{
       Uri = $UploadUri;
       Method = 'POST';
       Headers = @{
         Authorization = 'token ' + $GitHubApiKey;
       }
       ContentType = 'application/zip';
       InFile = $UploadFile
     }

    $Result = Invoke-RestMethod @UploadParams
}

<#
.SYNOPSIS
Generates a manifest for the module and bundles all of the module source files and manifest into a distributable ZIP file.
.DESCRIPTION 
Generates a manifest for the module and bundles all of the module source files and manifest into a distributable ZIP file.
.EXAMPLE
New-OciRelease.
#>
function New-OciRelease {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][String]$Author='Florian Feldhaus',
        [Parameter(Mandatory = $false)][String]$Company='NetApp Deutschland GmbH',
        [Parameter(Mandatory = $true)][String]$Name,
        [Parameter(Mandatory = $true)][String]$ReleaseNotes,
        [Parameter(Mandatory = $false)][switch]$Major,
        [Parameter(Mandatory = $false)][switch]$Minor,
        [Parameter(Mandatory = $false)][switch]$Build,
        [Parameter(Mandatory = $false)][switch]$Release,
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate
    )

    $ErrorActionPreference = "Stop"

    $CurrentVersion = git tag | ? { $_ -notmatch "\*" } | Select -last 1

    if (!$CurrentVersion) { $CurrentVersion = "0.1.0" }

    $ModuleVersion = New-Object System.Version($CurrentVersion)
    if ($Major) { $ModuleVersion = New-Object System.Version(($ModuleVersion.Major+1),0,0) }
    if ($Minor) { $ModuleVersion = New-Object System.Version($ModuleVersion.Major,($ModuleVersion.Minor+1),0) }
    if ($Build) { $ModuleVersion = New-Object System.Version($ModuleVersion.Major,$ModuleVersion.Minor,($ModuleVersion.Build+1)) }

    if ($RunTests.IsPresent) {
        Write-Host "Running Pester tests"
        Invoke-OciTests
    }

    Write-Host "Building release for version $ModuleVersion"

    $scriptPath = Split-Path -LiteralPath $(if ($PSVersionTable.PSVersion.Major -ge 3) { $PSCommandPath } else { & { $MyInvocation.ScriptName } })

    $src = (Join-Path (Split-Path $PSScriptRoot) 'src')
    $dst = (Join-Path (Split-Path $PSScriptRoot) 'release')
    $out = (Join-Path (Split-Path $PSScriptRoot) 'out')

    if (Test-Path $dst) {
        Remove-Item $dst -Force -Recurse
    }
    New-Item $dst -ItemType Directory -Force | Out-Null

    Write-Host "Creating module manifest..."

    $manifestFileName = Join-Path $dst 'OnCommand-Insight.psd1'

    $functionsToExport = Get-Command -Module OnCommand-Insight -Name *-Oci* | Select -ExpandProperty Name

    $tags = @("OnCommand-Insight","OCI","NetApp")

    New-ModuleManifest `
        -Path $manifestFileName `
        -ModuleVersion $ModuleVersion `
        -Guid 3f827027-aba0-4ed9-af5d-05c88f0470cd `
        -Author $Author `
        -CompanyName $Company `
        -Copyright "(c) $((Get-Date).Year) NetApp Deutschland GmbH. All rights reserved." `
        -Description 'OnCommand-Insight Powershell Cmdlet.' `
        -PowerShellVersion '3.0' `
        -DotNetFrameworkVersion '4.5' `
        -NestedModules (Get-ChildItem $src\*.psm1,$src\*.dll | % { $_.Name }) `
        -FormatsToProcess (Get-ChildItem $src\*.format.ps1xml | % { $_.Name }) `
        -LicenseUri "https://github.com/ffeldhaus/OnCommand-Insight/blob/master/LICENSE" `
        -ProjectUri "https://github.com/ffeldhaus/OnCommand-Insight" `
        -RootModule "OnCommand-Insight" `
        -FunctionsToExport $functionsToExport `
        -Tags $tags

    Write-Host "Copying file to release folder..."

    # Copy the Module files to the dist folder.
    Copy-Item -Path "$src\*.psm1" `
              -Destination $dst `
              -Recurse

    Copy-Item -Path "$src\*.ps1xml" `
              -Destination $dst `
              -Recurse

#    Write-Host "Running Pester tests"
#
#    $Version = '7.1.1'
#    $Record = $True
#    $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "admin",("admin123" | ConvertTo-SecureString -AsPlainText -Force)
#
#    Invoke-Pester -Script @{Path='./';Parameters=@{Server=$OciServer;Credential=$Credential;Version=$Version;Record=$Record}}

    Write-Host "Copying files to release folder"

    Copy-Item -Path "$scriptPath\..\README.md" `
              -Destination "$dst\README.txt"

    Copy-Item -Path "$scriptPath\..\LICENSE" `
              -Destination "$dst\LICENSE"

    Write-Host "Signing PowerShell files..."

    # Code Signing
    Get-ChildItem $dst\*.ps*  | % { $_.FullName } | Set-AuthenticodeSignature -Certificate $Certificate -TimestampServer "http://timestamp.comodoca.com/authenticode" | Out-Null
    
    Write-Host "Creating the release archive..."

    # Requires .NET 4.5
    [Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null

    $zipFileName = Join-Path $out "OnCommand-Insight.zip"

    # Overwrite the ZIP if it already already exists.
    if (Test-Path $zipFileName) {
        Remove-Item $zipFileName -Force
    }

    $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
    $includeBaseDirectory = $false
    [System.IO.Compression.ZipFile]::CreateFromDirectory($dst, $zipFileName, $compressionLevel, $includeBaseDirectory)

    Write-Host "Release zip file $zipFileName successfully created!" -ForegroundColor Green

    #Write-Host "Creating MSI installers..."
    #Start-WixBuild -Path $dst -OutputFolder $out -ProductShortName "OnCommand-Insight" -ProductName "OnCommand-Insight PowerShell Cmdlets" -ProductVersion $ModuleVersion -Manufacturer $Author -IconFile $PSScriptRoot\icon.ico -BannerFile $PSScriptRoot\banner.bmp -DialogFile $PSScriptRoot\dialog.bmp -UpgradeCodeX86 "8291AEAC-1A4D-CCFD-5870-70741560D087" -UpgradeCodeX64 "DF22600B-7719-B72A-9BA9-5E13FCA37628"

    #Write-Host "Release MSI Installer OnCommand_Insight_$($ModuleVersion)_x64.msi and OnCommand_Insight_$($ModuleVersion)_x86.msi successfully created!" -ForegroundColor Green

    #Remove-Item $dst\.wix.json

    if ($Release) { 
        Write-Host "Publishing Module to PowerShell Gallery"
        Publish-Module -Name "OnCommand-Insight" -NuGetApiKey $NuGetApiKey

        Write-Host "Creating git tag"
        & git pull
        & git tag $ModuleVersion
        if ($Major) { 
            Write-Host "Creating new git branch"
            & git branch $ModuleVersion
            Write-Host "New Git Branch $ModuleVersion created"
        }
        try {
            & git push 2> $null
            & git push --all 2> $null
            & git push --tags 2> $null
        }
        catch {
        }
        
        Write-Host "Creating GitHub release"
        New-GithubRelease -Version $ModuleVersion -Name $Name -ReleaseNotes $ReleaseNotes -FileName "OnCommand-Insight.zip" -OutputDirectory $out
    }
}

function Invoke-OciTests {
    $OciServer = 'localhost'
    $OciCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "admin",("admin123" | ConvertTo-SecureString -AsPlainText -Force)

    $VerbosePreference = "Continue"

    $Result = Invoke-Pester -Script @{Path='./';Parameters=@{Server=$Server;Credential=$Credential;Version=$Version;Record=$Record}} -PassThru

    if ($Result.FailedCount -gt 0) {
        Write-Error "Aborting due to test errors"
    }
}

function Install-OciServer {
    $installerPath = Join-Path $PSScriptRoot 'installer'
    $installerFile = Get-Item "$installerPath/*.msi" | select -first 1
    $DataStamp = get-date -Format yyyyMMddTHHmmss
    $logFile = Join-Path $installerPath ('{0}-{1}.log' -f $installerFile.BaseName,$DataStamp)
    $MSIArguments = @(
        "/i"
        ('"{0}"' -f $installerFile.fullname)
        "/qn"
        "/norestart"
        "/L*v"
        "SKIP_SYSTEM_MEMORY_VALIDATION=1"
        ('"{0}"' -f $logFile)
    )
    Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -verb RunAs
}

function Get-OciCmdlets {
    [CmdletBinding()]
 
    PARAM (
        [parameter(Mandatory=$False,
                   Position=0,
                   HelpMessage="Path for filename to store Cmdlets in.")][String]$FilePath,
        [parameter(Mandatory=$False,
                   Position=1,
                   HelpMessage="OnCommand Insight Server to get cmdlets from.")][PSObject]$Server,
        [parameter(Mandatory=$False,
                   Position=2,
                   HelpMessage="Path to store JSON output from a server in.")][String]$JsonOutFilePath,
        [parameter(Mandatory=$False,
                   Position=3,
                   HelpMessage="Path to get JSON from instead of retrieving it from a server.")][String]$JsonInFilePath
           )

    if (!$Server) {
        $Server = $CurrentOciServer
    }

    if (!$Server) {
        throw "No OCI Server specified and no global OCI Server available. Run Connect-OciServer first."
    }

    $DocumentationURI = $Server.BaseURI + "/rest/v1/documentation/sections"
    Write-Verbose "Retrieving REST API Documentation from $DocumentationURI"
    if ($Server -and $JsonOutFilePath) {
        Invoke-RestMethod -TimeoutSec $Server.Timeout -Uri $DocumentationURI -Headers $Server.Headers -OutFile "$JsonOutFilePath\sections.json"
        $Sections = Get-Content -Raw -Path "$JsonOutFilePath\sections.json" | ConvertFrom-Json
    }
    elseif ($Server) {
        $Sections = Invoke-RestMethod -TimeoutSec $Server.Timeout -Uri $DocumentationURI -Headers $Server.Headers
    }
    elseif ($JsonInFilePath) {
        $Sections = Get-Content -Raw -Path "$JsonInFilePath\sections.json" | ConvertFrom-Json
    }
    else {
        Write-Error "No OCI Server and no JSON file specified"
    }
 
    Write-Verbose "Generating OCI Cmdlets for each section of the API documentation"
    foreach ($Section in $($Sections.APIs  | ? { $_.path -notmatch '/login|/search' })) {
        Write-Verbose "Retrieving details for section $($Section.description)"
        if ($JsonOutFilePath) {
            $SectionName = $Section.description -split '\.' | select -last 1
            Invoke-RestMethod -TimeoutSec $Server.Timeout -Uri ($($Sections.BasePath) + $Section.path) -Headers $Server.Headers -OutFile "$JsonOutFilePath\$SectionName.json"
            $Section = Get-Content -Raw -Path "$JsonOutFilePath\$SectionName.json" | ConvertFrom-Json
        }
        elseif ($JsonInFilePath) {
            $SectionName = $Section.description -split '\.' | select -last 1
            $Section = Get-Content -Raw -Path "$JsonInFilePath\$SectionName.json" | ConvertFrom-Json
        }
        else {
            $Section = Invoke-RestMethod -TimeoutSec $Server.Timeout -Uri ($($Sections.BasePath) + $Section.path) -Headers $Server.Headers
        }
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
                    `$Result = Invoke-RestMethod -TimeoutSec `$CurrentOciServer.Timeout -Method $($Operation.httpMethod) -Uri `$Uri -Headers `$CurrentOciServer.Headers -Body "$Body" -ContentType 'application/json'
                }
                else {
                    `$Result = Invoke-RestMethod -TimeoutSec `$CurrentOciServer.Timeout -Method $($Operation.httpMethod) -Uri `$Uri -Headers `$CurrentOciServer.Headers
                }
            }
            catch {
                `$ResponseBody = ParseExceptionBody `$_.Exception.Response
                Write-Error "$($Operation.httpMethod) to `$Uri failed with Exception `$(`$_Exception.Message) ``n `$responseBody"
            }
 
            if (([String]`$Result).Trim().startsWith('{') -or ([String]`$Result).toString().Trim().startsWith('[')) {
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
                `$Result = Invoke-RestMethod -TimeoutSec `$CurrentOciServer.Timeout -Method Get -Uri `$Uri -Headers `$CurrentOciServer.Headers
                if (`$Result.toString().startsWith('{')) {
                    `$Result = ParseJsonString(`$Result)
                }
            }
            catch {
                `$ResponseBody = ParseExceptionBody `$_.Exception.Response
                Write-Error "$($Operation.httpMethod) to `$Uri failed with Exception `$(`$_Exception.Message) ``n `$responseBody"
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
            `$Result = Invoke-RestMethod -TimeoutSec `$CurrentOciServer.Timeout -Method Get -Uri `$Uri -Headers `$CurrentOciServer.Headers
            if (`$Result.toString().startsWith('{')) {
                `$Result = ParseJsonString(`$Result)
            }
        }
        catch {
            `$ResponseBody = ParseExceptionBody `$_.Exception.Response
            Write-Error "$($Operation.httpMethod) to `$Uri failed with Exception `$(`$_Exception.Message) ``n `$responseBody"
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

    # get DatasourceType Cmdlet
    $CmdletFunction = @"
<#
    .SYNOPSIS
    Retrieve OCI Datasource Types
    .DESCRIPTION
    Retrieve OCI Datasource Types
#>
function Global:Get-OciDatasourceTypes {
    [CmdletBinding()]

    PARAM ()
 
    Begin {
        `$Result = `$null
    }
   
    Process {
        `$Uri = `$(`$CurrentOciServer.BaseUri) + "/rest/v1/admin/datasourceTypes"
 
        try {
            `$Result = Invoke-RestMethod -TimeoutSec `$CurrentOciServer.Timeout -Method Get -Uri `$Uri -Headers `$CurrentOciServer.Headers
            if (`$Result.toString().startsWith('{')) {
                `$Result = ParseJsonString(`$Result)
            }
        }
        catch {
            `$ResponseBody = ParseExceptionBody `$_.Exception.Response
            Write-Error "$($Operation.httpMethod) to `$Uri failed with Exception `$(`$_Exception.Message) ``n `$responseBody"
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


    # update Datasource Cmdlet
    $CmdletFunction = @"
<#
    .SYNOPSIS
    Update OCI Datasource
    .DESCRIPTION
    Update OCI Datasource
#>
function Global:Update-OciDatasource {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory=`$True,
                    Position=0,
                    HelpMessage="Id of the datasource to be updated",
                    ValueFromPipeline=`$True,
                    ValueFromPipelineByPropertyName=`$True)][String[]]`$id,
        [parameter(Mandatory=`$True,
                    Position=1,
                    HelpMessage="Datasource configuration",
                    ValueFromPipeline=`$True,
                    ValueFromPipelineByPropertyName=`$True)][PSObject[]]`$config
        )
 
    Begin {
        `$Result = `$null
    }
   
    Process {
        $`id = @(`$id)
        foreach (`$id in `$id) {
            `$Uri = `$(`$CurrentOciServer.BaseUri) + "/rest/v1/admin/datasources/`$id"
 
            try {
                `$Body = (`$config.config | ConvertTo-Json -Depth 10)
                Write-Verbose "Body: `$Body"
                `$Result = Invoke-RestMethod -TimeoutSec `$CurrentOciServer.Timeout -Method PUT -Uri `$Uri -Headers `$CurrentOciServer.Headers -Body `$Body -ContentType 'application/json'
                if (`$Result.toString().startsWith('{')) {
                    `$Result = ParseJsonString(`$Result)
                }
            }
            catch {
                `$ResponseBody = ParseExceptionBody `$_.Exception.Response
                Write-Error "$($Operation.httpMethod) to `$Uri failed with Exception `$(`$_Exception.Message) ``n `$responseBody"
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

    # get Datasource Cmdlet
    $CmdletFunction = @"
<#
    .SYNOPSIS
    Get OCI Datasource
    .DESCRIPTION
    Get OCI Datasource
#>
function Global:Get-OciDatasource {
    [CmdletBinding()]
 
    PARAM (
        [parameter(Mandatory=`$True,
                    Position=0,
                    HelpMessage="ID of the datasource to retrieve",
                    ValueFromPipeline=`$True,
                    ValueFromPipelineByPropertyName=`$True)][Long[]]`$id,
        [parameter(Mandatory=`$False,
                    Position=1,
                    HelpMessage="Expand parameter for underlying JSON object (e.g. expand=acquisitionUnit)")][String]`$expand,
        [parameter(Mandatory=`$False,
                    Position=2,
                    HelpMessage="Return related Acquisition unit")][Switch]`$acquisitionUnit,
        [parameter(Mandatory=`$False,
                    Position=3,
                    HelpMessage="Return related Note")][Switch]`$note,
        [parameter(Mandatory=`$False,
                    Position=4,
                    HelpMessage="Return list of related Changes")][Switch]`$changes,
        [parameter(Mandatory=`$False,
                    Position=5,
                    HelpMessage="Return list of related Package statuses")][Switch]`$packageStatuses,
        [parameter(Mandatory=`$False,
                    Position=6,
                    HelpMessage="Return related Active patch")][Switch]`$activePatch,
        [parameter(Mandatory=`$False,
                    Position=7,
                    HelpMessage="Return list of related Events")][Switch]`$events,
        [parameter(Mandatory=`$False,
                    Position=8,
                    HelpMessage="Return list of related Devices")][Switch]`$devices,
        [parameter(Mandatory=`$False,
                    Position=9,
                    HelpMessage="Return datasource configuration")][Switch]`$config
    )
 
    Begin {
        `$Result = `$null
    }
   
    Process {
        `$id = @(`$id)
        foreach (`$id in `$id) {
            `$Uri = `$(`$CurrentOciServer.BaseUri) + "/rest/v1/admin/datasources/`$id"
 
           
            `$switchparameters=@("acquisitionUnit","note","changes","packageStatuses","activePatch","events","devices","config")
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
                `$Result = Invoke-RestMethod -TimeoutSec `$CurrentOciServer.Timeout -Method GET -Uri `$Uri -Headers `$CurrentOciServer.Headers
            }
            catch {
                `$ResponseBody = ParseExceptionBody `$_.Exception.Response
                Write-Error "$($Operation.httpMethod) to `$Uri failed with Exception `$(`$_Exception.Message) ``n `$responseBody"
            }
 
            if (([String]`$Result).Trim().startsWith('{') -or ([String]`$Result).toString().Trim().startsWith('[')) {
                `$Result = ParseJsonString(`$Result.Trim())
            }
            
            if (`$Result.config) {
                foreach (`$Package in `$Result.config.packages) {
                    foreach (`$Attribute in `$Package.attributes) {
                        `$PackageIndex = `$Result.config.packages.IndexOf(`$Package)
                        `$AttributeIndex = `$Package.attributes.IndexOf(`$Attribute)
                        Invoke-Command -ScriptBlock ([ScriptBlock]::Create("```$Result.config | Add-Member -MemberType ScriptProperty -Name `$(`$Attribute.name) -Value { ```$this.packages[`$PackageIndex].attributes[`$AttributeIndex].Value } -SecondValue { ```$this.packages[`$PackageIndex].attributes[`$AttributeIndex].Value = ```$args[0] }  -ErrorAction SilentlyContinue"))
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

    # get Datasources Cmdlet
    $CmdletFunction = @"
<#
    .SYNOPSIS
    Get OCI Datasources
    .DESCRIPTION
    Get OCI Datasources
#>
function Global:Get-OciDatasources {
    [CmdletBinding()]
 
    PARAM (
        [parameter(Mandatory=`$False,
                    Position=0,
                    HelpMessage="Expand parameter for underlying JSON object (e.g. expand=acquisitionUnit)")][String]`$expand,
        [parameter(Mandatory=`$False,
                    Position=1,
                    HelpMessage="Return related Acquisition unit")][Switch]`$acquisitionUnit,
        [parameter(Mandatory=`$False,
                    Position=2,
                    HelpMessage="Return related Note")][Switch]`$note,
        [parameter(Mandatory=`$False,
                    Position=3,
                    HelpMessage="Return list of related Changes")][Switch]`$changes,
        [parameter(Mandatory=`$False,
                    Position=4,
                    HelpMessage="Return list of related Package statuses")][Switch]`$packageStatuses,
        [parameter(Mandatory=`$False,
                    Position=5,
                    HelpMessage="Return related Active patch")][Switch]`$activePatch,
        [parameter(Mandatory=`$False,
                    Position=6,
                    HelpMessage="Return list of related Events")][Switch]`$events,
        [parameter(Mandatory=`$False,
                    Position=7,
                    HelpMessage="Return list of related Devices")][Switch]`$devices,
        [parameter(Mandatory=`$False,
                    Position=8,
                    HelpMessage="Return datasource configuration")][Switch]`$config
    )
 
    Begin {
        `$Result = `$null
    }
   
    Process {
        `$id = @(`$id)
        foreach (`$id in `$id) {
            `$Uri = `$(`$CurrentOciServer.BaseUri) + "/rest/v1/admin/datasources"
 
           
            `$switchparameters=@("acquisitionUnit","note","changes","packageStatuses","activePatch","events","devices","config")
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
                `$Result = Invoke-RestMethod -TimeoutSec `$CurrentOciServer.Timeout -Method GET -Uri `$Uri -Headers `$CurrentOciServer.Headers
            }
            catch {
                `$ResponseBody = ParseExceptionBody `$_.Exception.Response
                Write-Error "$($Operation.httpMethod) to `$Uri failed with Exception `$(`$_Exception.Message) ``n `$responseBody"
            }
 
            if (([String]`$Result).Trim().startsWith('{') -or ([String]`$Result).toString().Trim().startsWith('[')) {
                `$Result = ParseJsonString(`$Result.Trim())
            }

            if (`$Result.config) {
                foreach (`$Datasource in `$Result) {
                    foreach (`$Package in `$Datasource.config.packages) {
                        foreach (`$Attribute in `$Package.attributes) {
                            `$PackageIndex = `$Datasource.config.packages.IndexOf(`$Package)
                            `$AttributeIndex = `$Package.attributes.IndexOf(`$Attribute)
                            Invoke-Command -ScriptBlock ([ScriptBlock]::Create("```$Datasource.config | Add-Member -MemberType ScriptProperty -Name `$(`$Attribute.name) -Value { ```$this.packages[`$PackageIndex].attributes[`$AttributeIndex].Value } -SecondValue { ```$this.packages[`$PackageIndex].attributes[`$AttributeIndex].Value = ```$args[0] } -ErrorAction SilentlyContinue"))
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