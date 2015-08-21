<#
.SYNOPSIS
	Generates a manifest for the module
	and bundles all of the module source files
	and manifest into a distributable ZIP file.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)][String]$Author,
    [Parameter(Mandatory = $false)][String]$Company,
    [Parameter(Mandatory = $false)][switch]$Major,
    [Parameter(Mandatory = $false)][switch]$Minor,
    [Parameter(Mandatory = $false)][switch]$Release

)

$ErrorActionPreference = "Stop"

$CurrentVersion = git branch | ? { $_ -notmatch "\*" } | Select -last 1

if (!$CurrentVersion) { $CurrentVersion = "0.1.0" }

$ModuleVersion = New-Object System.Version($CurrentVersion)
if ($Major) { $ModuleVersion = New-Object System.Version(($ModuleVersion.Major+1),0,0) }
if ($Minor) { $ModuleVersion = New-Object System.Version($ModuleVersion.Major,($ModuleVersion.Minor+1),0) }
if ($Build) { $ModuleVersion = New-Object System.Version($ModuleVersion.Major,$ModuleVersion.Minor,($ModuleVersion.Build+1)) }

Write-Host "Building release for version $ModuleVersion"

$scriptPath = Split-Path -LiteralPath $(if ($PSVersionTable.PSVersion.Major -ge 3) { $PSCommandPath } else { & { $MyInvocation.ScriptName } })

$src = (Join-Path (Split-Path $scriptPath) 'src')
$dst = (Join-Path (Split-Path $scriptPath) 'release')
if (Test-Path $dst) {
    Remove-Item $dst -Force -Recurse
}
New-Item $dst -ItemType Directory | Out-Null

Write-Host "Creating module manifest..."

$manifestFileName = Join-Path $dst 'OnCommand-Insight.psd1'

New-ModuleManifest `
    -Path $manifestFileName `
    -ModuleVersion $ModuleVersion `
    -Guid 3f827027-aba0-4ed9-af5d-05c88f0470cd `
    -Author $Author `
    -CompanyName $Company `
    -Copyright '(c) $((Get-Date).Year) Your Company. All rights reserved.' `
    -Description 'OnCommand-Insight Powershell Cmdlet.' `
    -PowerShellVersion '2.0' `
    -DotNetFrameworkVersion '3.5' `
    -NestedModules (Get-ChildItem $src\*.psm1 | % { $_.Name }) `
    -FormatsToProcess (Get-ChildItem $src\*.format.ps1xml | % { $_.Name })

Write-Host "Copying file to release folder..."

# Copy the distributable files to the dist folder.
Copy-Item -Path "$src\*" `
          -Destination $dst `
          -Recurse


# Import new OCI Cmdlets
Import-Module "$src\OnCommand-Insight.psm1"
$Credential = Get-Credential
Connect-OciServer -Name "cbc-oci-01.muccbc.hq.netapp.com" -Credential $Credential -Insecure
Get-OciCmdlets -FilePath "$dst\OnCommand-Insight.psm1"

Copy-Item -Path "$scriptPath\..\README.md" `
          -Destination "$dst\README.txt"

Write-Host "Signing PowerShell files..."

# Code Signing
$cert = Get-ChildItem cert:\CurrentUser\My -CodeSigningCert
Get-ChildItem $dst\*.ps*  | % { $_.FullName } | Set-AuthenticodeSignature -Certificate $cert | Out-Null

Write-Host "Creating the release archive..."

# Requires .NET 4.5
[Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null

$zipFileName = Join-Path ([System.IO.Path]::GetDirectoryName($dst)) "$([System.IO.Path]::GetFileNameWithoutExtension($manifestFileName)).zip"

# Overwrite the ZIP if it already already exists.
if (Test-Path $zipFileName) {
    Remove-Item $zipFileName -Force
}

$compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
$includeBaseDirectory = $false
[System.IO.Compression.ZipFile]::CreateFromDirectory($dst, $zipFileName, $compressionLevel, $includeBaseDirectory)

Move-Item $zipFileName $dst -Force

Write-Host "Release file $zipFileName successfully created!" -ForegroundColor Green

if ($Release) { 
    git tag $ModuleVersion 
    if ($Major -or $Minor) { 
        git branch $ModuleVersion
        Write-Host "New Git Branch $ModuleVersion created"
    }
    try {
        git push 2> $null
        git push --all 2> $null
        git push --tags 2> $null
    }
    catch {
    }
    Write-Host "New Git tag $ModuleVersion created"
}