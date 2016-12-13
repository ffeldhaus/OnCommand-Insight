Import-Module "$PSScriptRoot\OnCommand-Insight"

if (!$OciServerName) {
    $OciServerName = 'localhost'
    $OciCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "admin",("admin123" | ConvertTo-SecureString -AsPlainText -Force)
}

Write-Host "Running tests against OCI Server $OciServerName"

### functions for validating OCI objects
function ValidateAcquisitionUnit {
    [CmdletBinding()]
        
    PARAM (
    [parameter(Mandatory=$True,
                Position=0,
                ValueFromPipeline=$True,
                HelpMessage="Acquisition unit to be verified")][PSObject]$AcquisitionUnit
    )

        Process {
            $AcquisitionUnit.id | Should BeGreaterThan 0
            $AcquisitionUnit.self | Should Be "/rest/v1/admin/acquisitionUnits/$($AcquisitionUnit.id)"
            $AcquisitionUnit.name | Should Be "local"
            $AcquisitionUnit.ip | Should Match "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"
            $AcquisitionUnit.status | Should Match "CONNECTED|CONNECTED_TIMEOUT"
            $AcquisitionUnit.isActive | Should Be "True"
            if ($AcquisitionUnit.leaseContract) {
                $AcquisitionUnit.leaseContract | Should Be 120000
            }
            if ($AcquisitionUnit.nextLeaseRenewal) {
                $AcquisitionUnit.nextLeaseRenewal | Should BeGreaterThan (Get-Date)
            }
            if ($AcquisitionUnit.lastReported) {
                $AcquisitionUnit.lastReported | Should BeLessThan (Get-Date)
            }
    }
}

function ValidateAnnotation {
    [CmdletBinding()]
        
    PARAM (
    [parameter(Mandatory=$True,
                Position=0,
                ValueFromPipeline=$True,
                HelpMessage="Annotation to be verified")][PSObject]$Annotation
    )

        Process {
            $Annotation.id | Should BeGreaterThan 0
            $Annotation.self | Should Be "/rest/v1/assets/annotations/$($Annotation.id)"
            $Annotation.name | Should Match ".+"
            $Annotation.type | Should Match "DATE|TEXT|FIXED_ENUM|FLEXIBLE_ENUM|BOOLEAN|NUMBER"
            $Annotation.label | Should Match ".+"
            if ($Annotation.description) {
               $Annotation.description | Should Match ".+" 
            }
            $Annotation.isUserDefined | Should BeOfType Boolean
            $Annotation.isCostBased | Should BeOfType Boolean
            if ($Annotation.enumValues) {
                $Annotation.enumValues.id | Should BeGreaterThan 0
                $Annotation.enumValues.name | Should Match ".+"
                $Annotation.enumValues.label | Should Match ".+"
                $Annotation.enumValues.description | Should Match ".+"
                $Annotation.enumValues.isUserDefined | Should Match ".+"
            }
            $Annotation.supportedObjectTypes | Should Match "StoragePool|Qtree|Port|Host|StorageNode|Storage|InternalVolume|Switch|Volume|Vmdk|DataStore|Disk|Share|VirtualMachine"
    }
}

function ValidateApplication {
    [CmdletBinding()]
        
    PARAM (
    [parameter(Mandatory=$True,
                Position=0,
                ValueFromPipeline=$True,
                HelpMessage="Application to be verified")][PSObject]$Application
    )

        Process {
            $Application.id | Should BeGreaterThan 0
            $Application.self | Should Be "/rest/v1/assets/applications/$($Application.id)"
            $Application.name | Should Match ".+"
            $Application.simpleName | Should Match ".+"
            $Application.priority | Should Match "Low|Medium|High|Critical" 
            $Application.isBusinessEntityDefault | Should BeOfType Boolean
            $Application.isInherited | Should BeOfType Boolean
            $Application.ignoreShareViolations | Should BeOfType Boolean
    }
}

function ValidatePackage {
    [CmdletBinding()]
        
    PARAM (
    [parameter(Mandatory=$False,
                Position=0,
                ValueFromPipeline=$True,
                HelpMessage="Datasource package to be verified")][PSObject]$Package
    )

        Process {
            $Package.packageName | Should Match 'Inventory|Performance'
            $Package.status | Should Match 'ACQUIRING|STANDBY|ERROR|SUCCESS'
            $Package.statusText | Should Match ".+"
            $Package.releaseStatus | Should Match "BETA|OFFICIAL"
    }
}

function ValidateDatasource {
    [CmdletBinding()]
        
    PARAM (
    [parameter(Mandatory=$False,
                Position=0,
                ValueFromPipeline=$True,
                HelpMessage="Datasource to be verified")][PSObject]$Datasource
    )

        Process {
            $Datasource.id | Should BeGreaterThan 0
            $Datasource.self | Should Be "/rest/v1/admin/datasources/$($Datasource.id)"
            $Datasource.impactIndex | Should Match "-?[0-9]+"
            $Datasource.name | Should Match ".+"
            $Datasource.status | Should Match "[A-Z]+"
            $Datasource.statusText | Should Match ".*"
            $Datasource.pollStatus | Should Match "[A-Z]+"
            $Datasource.vendor | Should Match ".+"
            $Datasource.foundationIp | Should Match "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"
            $Datasource.lastSuccessfullyAccquired | Should BeLessThan (Get-Date)
            if ($Datasource.resumeTime) {
                $Datasource.resumeTime | Should BeGreaterThan (Get-Date)
            }
    }
}

function ValidateDatasourceConfig {
    [CmdletBinding()]
        
    PARAM (
    [parameter(Mandatory=$False,
                Position=0,
                ValueFromPipeline=$True,
                HelpMessage="Datasource configuration to be verified")][PSObject]$DatasourceConfig
    )

        Process {
            $DatasourceConfig.dsTypeId | Should BeGreaterThan 0
            $DatasourceConfig.self | Should Match "/rest/v1/admin/datasources/[0-9]+/config"
            $DatasourceConfig.vendor | Should Match ".+"
            $DatasourceConfig.model | Should Match ".+"
            $DatasourceConfig.packages | ValidateDatasourceConfigPackage
    }
}

function ValidateDatasourceChange {
    [CmdletBinding()]
        
    PARAM (
    [parameter(Mandatory=$False,
                Position=0,
                ValueFromPipeline=$True,
                HelpMessage="Datasource to be verified")][PSObject]$DatasourceChange
    )

        Process {
            $DatasourceChange.time | Should BeOfType DateTime
            $DatasourceChange.time | Should BeLessThan (Get-Date)
            $DatasourceChange.type | Should Match ".+"
            $DatasourceChange.summary | Should Match ".+"
    }
}

function ValidateDatasourceEvent {
    [CmdletBinding()]
        
    PARAM (
    [parameter(Mandatory=$False,
                Position=0,
                ValueFromPipeline=$True,
                HelpMessage="Datasource to be verified")][PSObject]$DatasourceEvent
    )

        Process {
            $DatasourceEvent.id | Should BeGreaterThan 0
            $DatasourceEvent.packageName | Should Match 'Performance|Inventory'
            $DatasourceEvent.status | Should Match 'STANDBY|ERROR|SUCCESS|DISABLED'
            $DatasourceEvent.statusText | Should Match '.+'
            $DatasourceEvent.startTime | Should BeOfType DateTime
            $DatasourceEvent.endTime | Should BeOfType DateTime
            $DatasourceEvent.numberOfTimes | Should BeGreaterThan 0
    }
}

function ValidateDatasourceTypePackage {
    [CmdletBinding()]
        
    PARAM (
    [parameter(Mandatory=$False,
                Position=0,
                ValueFromPipeline=$True,
                HelpMessage="Datasource package to be verified")][PSObject]$DatasourcePackage
    )

        Process {
            $DatasourcePackage.id | Should Match 'cloud|performance|hostvirtualization|storageperformance|foundation'
            $DatasourcePackage.displayName | Should Match '.+'
            $DatasourcePackage.isMandatory | Should BeOfType Boolean
            $DatasourcePackage.attributes | ValidateDatasourceTypePackageAttribute
    }
}

function ValidateDatasourceTypePackageAttribute {
    [CmdletBinding()]
        
    PARAM (
    [parameter(Mandatory=$False,
                Position=0,
                ValueFromPipeline=$True,
                HelpMessage="Datasource package to be verified")][PSObject]$DatasourcePackageAttribute
    )

        Process {
            $DatasourcePackageAttribute.type | Should Match 'list|integer|string|boolean|enum|float'
            $DatasourcePackageAttribute.name | Should Match '.+'
            $DatasourcePackageAttribute.description | Should Match '.*'
            $DatasourcePackageAttribute.label | Should Match '.*'
            $DatasourcePackageAttribute.isEditable | Should BeOfType Boolean
            $DatasourcePackageAttribute.defaultValue | Should Match '.*'
            $DatasourcePackageAttribute.isEncrypted | Should BeOfType Boolean
            $DatasourcePackageAttribute.guiorder | Should BeOfType int
            $DatasourcePackageAttribute.isMandatory | Should BeOfType Boolean
            $DatasourcePackageAttribute.isHidden | Should BeOfType Boolean
            $DatasourcePackageAttribute.isCloneable | Should BeOfType Boolean
            $DatasourcePackageAttribute.isAdvanced | Should BeOfType Boolean
    }
}

function ValidateDatasourceConfigPackage {
    [CmdletBinding()]
        
    PARAM (
    [parameter(Mandatory=$False,
                Position=0,
                ValueFromPipeline=$True,
                HelpMessage="Datasource package to be verified")][PSObject]$DatasourcePackage
    )

        Process {
            $DatasourcePackage.id | Should Match 'cloud|performance|storageperformance|hostvirtualization|foundation'
            $DatasourcePackage.displayName | Should Match '.+'
            $DatasourcePackage.isMandatory | Should BeOfType Boolean
            $DatasourcePackage.attributes | ValidateDatasourceConfigPackageAttribute
    }
}

function ValidateDatasourceConfigPackageAttribute {
    [CmdletBinding()]
        
    PARAM (
    [parameter(Mandatory=$False,
                Position=0,
                ValueFromPipeline=$True,
                HelpMessage="Datasource package to be verified")][PSObject]$DatasourceConfigPackageAttribute
    )

        Process {
            $DatasourceConfigPackageAttribute.RELEASESTATUS | Should Match 'BETA|OFFICIAL'
            # TODO: add parameters
    }
}

function ValidateDatasourcePatch {
    [CmdletBinding()]
        
    PARAM (
    [parameter(Mandatory=$False,
                Position=0,
                ValueFromPipeline=$True,
                HelpMessage="Datasource package to be verified")][PSObject]$DatasourcePatch
    )

        Process {
            $DatasourcePatch.id | Should BeGreaterThan 0
            $DatasourcePatch.self | Should Be "/rest/v1/admin/patches/$($DatasourcePatch.id)"
            $DatasourcePatch.name | Should Match ".+"
            $DatasourcePatch.description | Should Match ".+"
            $DatasourcePatch.createTime | Should BeOfType DateTime
            $DatasourcePatch.createTime | Should BeLessThan (Get-Date)
            $DatasourcePatch.lastUpdateTime | Should BeOfType DateTime
            $DatasourcePatch.lastUpdateTime | Should BeLessThan (Get-Date)
            $DatasourcePatch.state | Should Match "ACTIVE"
            $DatasourcePatch.recommendation | Should Match "VERIFYING"
            $DatasourcePatch.recommendationText | Should Match ".+"
            $DatasourcePatch.datasourceTypes | ValidateDatasourceType
            $DatasourcePatch.numberOfAffectedDatasources | Should BeGreaterThan 0
            $DatasourcePatch.type | Should Match 'PATCH'
            if ($DatasourcePatch.note) {
                $DatasourcePatch.note | Should Match '.+'
            }
    }
}

function ValidateDatasourceType {
    [CmdletBinding()]
        
    PARAM (
    [parameter(Mandatory=$False,
                Position=0,
                ValueFromPipeline=$True,
                HelpMessage="Datasource package to be verified")][PSObject]$DatasourceType
    )

        Process {
            $DatasourceType.id | Should BeGreaterThan 0
            $DatasourceType.name | Should Match '.+'
            $DatasourceType.description | Should Match '.+'
            $DatasourceType.self | Should Be "/rest/v1/admin/datasourceTypes/$($DatasourceType.id)"
            $DatasourceType.vendorModels | ValidateVendorModel
            $DatasourceType.packages | ValidateDatasourceTypePackage
    }
}

function ValidateVendorModel {
    [CmdletBinding()]
        
    PARAM (
    [parameter(Mandatory=$False,
                Position=0,
                ValueFromPipeline=$True,
                HelpMessage="Datasource package to be verified")][PSObject]$VendorModel
    )

        Process {
            $VendorModel.modelName | Should Match '.+'
            $VendorModel.modelDescription | Should Match '.+'
            $VendorModel.vendorName | Should Match '.+'
            $VendorModel.vendorDescription | Should Match '.+'
    }
}

function ValidateDevice {
    [CmdletBinding()]
        
    PARAM (
    [parameter(Mandatory=$False,
                Position=0,
                ValueFromPipeline=$True,
                HelpMessage="Device to be verified")][PSObject]$Device
    )

        Process {
            $Device.id | Should BeGreaterThan 0
            $Device.name | Should Match '.+'
            $Device.simpleName | Should Match '.+'
            $Device.ip | Should Match '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+,?)+'
            $Device.type | Should Match 'SWITCH|STORAGE|HOST'
            $Device.wwn | Should Match '.*'
            $Device.description | Should Match '.+'
            $Device.self | Should Match "/rest/v1/assets/$($Device.type.toLower())[es]*/$($Device.id)"
    }
}

### Begin of tests ###

Describe "Acquisition unit management" {

    BeforeEach {
        $OciServer = $null
        $Global:CurrentOciServer = $null
        $AcquisitionUnits = $null
    }

    Context "retrieving acquisition units" {
        it "succeeds with no parameters" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $AcquisitionUnits = Get-OciAcquisitionUnits
            $AcquisitionUnits | Should Not BeNullOrEmpty
            $AcquisitionUnits | ValidateAcquisitionUnit
        }

        it "succeeds with getting datasources" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $AcquisitionUnits = Get-OciAcquisitionUnits -datasources
            $AcquisitionUnits | Should Not BeNullOrEmpty
            $AcquisitionUnits | ValidateAcquisitionUnit
            $AcquisitionUnits.datasources | ValidateDatasource
        }

        it "succeeds with transient OCI Server" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure -Transient
            $Global:CurrentOciServer | Should BeNullOrEmpty

            $AcquisitionUnits = Get-OciAcquisitionUnits -Server $OciServer
            $AcquisitionUnits | Should Not BeNullOrEmpty
            $AcquisitionUnits | ValidateAcquisitionUnit
        }
    }

    Context "retrieving single acquisition unit" {
        it "succeeds with no parameters" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $AcquisitionUnits = Get-OciAcquisitionUnits
            $AcquisitionUnits | Should Not BeNullOrEmpty
            $AcquisitionUnit = $AcquisitionUnits | Get-OciAcquisitionUnit
            $AcquisitionUnit | ValidateAcquisitionUnit
        }

        it "succeeds with getting datasources" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $AcquisitionUnits = Get-OciAcquisitionUnits -datasources
            $AcquisitionUnits | Should Not BeNullOrEmpty
            $AcquisitionUnit = $AcquisitionUnits | Get-OciAcquisitionUnit -datasources
            $AcquisitionUnit | ValidateAcquisitionUnit
            $AcquisitionUnit.datasources | ValidateDatasource
        }

        it "succeeds with transient OCI Server" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure -Transient
            $Global:CurrentOciServer | Should BeNullOrEmpty

            $AcquisitionUnits = Get-OciAcquisitionUnits -Server $OciServer
            $AcquisitionUnits | Should Not BeNullOrEmpty
            $AcquisitionUnit = $AcquisitionUnits | Get-OciAcquisitionUnit -Server $OciServer
            $AcquisitionUnit | ValidateAcquisitionUnit
        }
    }

    Context "retrieving datasources of single acquisition unit" {
        it "succeeds with no parameters" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $AcquisitionUnits = Get-OciAcquisitionUnits
            $AcquisitionUnits | Should Not BeNullOrEmpty
            $Datasources = $AcquisitionUnits | Get-OciDatasourcesByAcquisitionUnit
            $Datasources | ValidateDatasource
        }

        it "succeeds when requesting related acquisition units" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $AcquisitionUnits = Get-OciAcquisitionUnits
            $AcquisitionUnits | Should Not BeNullOrEmpty
            $Datasources = $AcquisitionUnits | Get-OciDatasourcesByAcquisitionUnit -acquisitionUnit
            $Datasources | ValidateDatasource
            $Datasources.acquisitionUnit | ValidateAcquisitionUnit
        }
        
        it "succeeds when requesting related notes" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $AcquisitionUnits = Get-OciAcquisitionUnits
            $AcquisitionUnits | Should Not BeNullOrEmpty
            $Datasources = $AcquisitionUnits | Get-OciDatasourcesByAcquisitionUnit -note
            $Datasources | ValidateDatasource
            $Datasources | % { [bool]($_.PSobject.Properties.name -match "note") | Should Be $true }
        }

        it "succeeds when requesting related changes" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $AcquisitionUnits = Get-OciAcquisitionUnits
            $AcquisitionUnits | Should Not BeNullOrEmpty
            $Datasources = $AcquisitionUnits | Get-OciDatasourcesByAcquisitionUnit -changes
            $Datasources | ValidateDatasource
            $Datasources.changes | ValidateDatasourceChange
        }

        it "succeeds when requesting related packages" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $AcquisitionUnits = Get-OciAcquisitionUnits
            $AcquisitionUnits | Should Not BeNullOrEmpty
            $Datasources = $AcquisitionUnits | Get-OciDatasourcesByAcquisitionUnit -packages
            $Datasources | ValidateDatasource
            $Datasources.packages | ValidatePackage
        }

        it "succeeds when requesting related events" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $AcquisitionUnits = Get-OciAcquisitionUnits
            $AcquisitionUnits | Should Not BeNullOrEmpty
            $Datasources = $AcquisitionUnits | Get-OciDatasourcesByAcquisitionUnit -events
            $Datasources | ValidateDatasource
            $Datasources.events | ? { $_ } | ValidateDatasourceEvent
        }

        it "succeeds when requesting related devices" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $AcquisitionUnits = Get-OciAcquisitionUnits
            $AcquisitionUnits | Should Not BeNullOrEmpty
            $Datasources = $AcquisitionUnits | Get-OciDatasourcesByAcquisitionUnit -devices
            $Datasources | ValidateDatasource
            $Datasources.devices | ? { $_ } | ValidateDevice
        }

        it "succeeds when requesting related devices" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $AcquisitionUnits = Get-OciAcquisitionUnits
            $AcquisitionUnits | Should Not BeNullOrEmpty
            $Datasources = $AcquisitionUnits | Get-OciDatasourcesByAcquisitionUnit -config
            $Datasources | ValidateDatasource
            $Datasources.config | ? { $_ } | ValidateDatasourceConfig
        }

        it "succeeds with transient OCI Server" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure -Transient
            $Global:CurrentOciServer | Should BeNullOrEmpty

            $AcquisitionUnits = Get-OciAcquisitionUnits -Server $OciServer
            $AcquisitionUnits | Should Not BeNullOrEmpty
            $Datasources = $AcquisitionUnits | Get-OciDatasourcesByAcquisitionUnit -Server $OciServer
            $Datasources | ValidateDatasource
        }     
    }
}

Describe "Datasource management" {

    BeforeEach {
        $OciServer = $null
        $Global:CurrentOciServer = $null
        $Datasources = $null
    }

    Context "retrieving datasource types" {
        it "succeeds with no parameters" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $DatasourceTypes = Get-OciDatasourceTypes
            $DatasourceTypes | Should Not BeNullOrEmpty
            $DatasourceTypes | ValidateDatasourceType
        }

        it "succeeds when retrieving one by one" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            Get-OciDatasourceTypes | Get-OciDatasourceType | ValidateDatasourceType
        }

        it "succeeds with transient OCI Server" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure -Transient
            $Global:CurrentOciServer | Should BeNullOrEmpty

            $DatasourceTypes = Get-OciDatasourceTypes -Server $OciServer
            $DatasourceTypes | Should Not BeNullOrEmpty
            $DatasourceTypes = $DatasourceTypes | Get-OciDatasourceType -Server $OciServer
            $DatasourceTypes | Should Not BeNullOrEmpty
            $DatasourceTypes | ValidateDatasourceType
        }
    }

    Context "retrieving datasources" {
        it "succeeds with no parameters" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $Datasources = Get-OciDatasources
            $Datasources | Should Not BeNullOrEmpty
            $Datasources | ValidateDatasource
        }

        it "succeeds when retrieving one by one" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            Get-OciDatasources | Get-OciDatasource | ValidateDatasource
        }

        it "succeeds with transient OCI Server" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure -Transient
            $Global:CurrentOciServer | Should BeNullOrEmpty

            $Datasources = Get-OciDatasources -Server $OciServer
            $Datasources | Should Not BeNullOrEmpty
            $Datasources = $Datasources | Get-OciDatasource -Server $OciServer
            $Datasources | Should Not BeNullOrEmpty
            $Datasources | ValidateDatasource
        }
    }

    Context "modifying datasources" {
        it "succeeds when modifying name" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $Datasources = Get-OciDatasources
            $Datasources | Should Not BeNullOrEmpty
            
            foreach ($Datasource in $Datasources) {
                $CurrentName = $Datasource.name
                $NewName = $Datasource.name + "test"
                $Datasource = $Datasource | Update-OciDataSource -name $NewName

                $Datasource | ValidateDatasource
                $Datasource.Name | Should Be $NewName

                sleep 1

                $Datasource = $Datasource | Update-OciDataSource -name $CurrentName

                $Datasource | ValidateDatasource
                $Datasource.Name | Should Be $CurrentName
            }
        }

        it "succeeds when modifying acquisition unit" {
            Write-Warning "Checking modification of acquisition unit not implemented"
        }

        it "succeeds when modifying poll interval in configuration" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $Datasources = Get-OciDatasources -config
            $Datasources | Should Not BeNullOrEmpty

            foreach ($Datasource in $Datasources) {
                $CurrentPollInterval = $Datasource.config.foundation.attributes.poll
                $NewPollInterval = $CurrentPollInterval + 120

                $Datasource.config.foundation.attributes.poll = $NewPollInterval
                $Datasource = $Datasource | Update-OciDataSource -config $Datasource.config
                $Datasource | ValidateDatasource
                $Datasource.config.foundation.attributes.poll | Should Be $NewPollInterval

                $Datasource.config.foundation.attributes.poll = $CurrentPollInterval
                $Datasource = $Datasource | Update-OciDataSource -config $Datasource.config
                $Datasource | ValidateDatasource
                $Datasource.config.foundation.attributes.poll | Should Be $CurrentPollInterval
            }
        }

        it "succeeds when modifying name using transient OCI Server" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure -Transient
            $Global:CurrentOciServer | Should BeNullOrEmpty

            $Datasources = Get-OciDatasources -Server $OciServer
            $Datasources | Should Not BeNullOrEmpty
            
            foreach ($Datasource in $Datasources) {
                $CurrentName = $Datasource.name
                $NewName = $Datasource.name + "test"
                $Datasource = $Datasource | Update-OciDataSource -name $NewName -Server $OciServer

                $Datasource | ValidateDatasource
                $Datasource.Name | Should Be $NewName

                sleep 1

                $Datasource = $Datasource | Update-OciDataSource -name $CurrentName -Server $OciServer

                $Datasource | ValidateDatasource
                $Datasource.Name | Should Be $CurrentName
            }
        }
    }

    Context "creating datasources" {
        it "succeeds for all datasource types" {
             $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

             $User = "test"
             $IP = "127.0.0.1"
             $Password = "test"

             $DatasourceTypes = Get-OciDatasourceTypes

             $AcquisitionUnit = Get-OciAcquisitionUnits | select -first 1

             foreach ($DatasourceType in $DatasourceTypes) {
                if ($DatasourceType.vendorModels.count -gt 1) {
                    $DatasourceType.vendorModels = $DatasourceType.vendorModels | select -Last 1
                }
                $Datasource = New-OciDatasource -type $DatasourceType -name "test" -acquisitionUnit $AcquisitionUnit
                if ($Datasource.config.foundation) {
                    if ($Datasource.config.foundation.attributes.PSobject.Properties.name -match "ip") {
                        $Datasource.config.foundation.attributes.ip = $IP
                    }
                    if ($Datasource.config.foundation.attributes.PSobject.Properties.name -match "user") {
                        $Datasource.config.foundation.attributes.user = $User
                    }
                    if ($Datasource.config.foundation.attributes.PSobject.Properties.name -match "password") {
                        $Datasource.config.foundation.attributes.password = $Password
                    }
                }
                if ($Datasource.config.performance) {
                    $Datasource.config.performance.attributes.enabled = $true
                }
                if ($Datasource.config.storageperformance) {
                    $Datasource.config.storageperformance.attributes.enabled = $true
                }
                if ($Datasource.config.hostvirtualization) {
                    $Datasource.config.hostvirtualization.attributes.enabled = $true
                }
                if ($Datasource.config.cloud) {
                    if ($Datasource.config.cloud.attributes.PSobject.Properties.name -match "ip") {
                        $Datasource.config.cloud.attributes.ip = $IP
                    }
                    if ($Datasource.config.cloud.attributes.PSobject.Properties.name -match "user") {
                        $Datasource.config.cloud.attributes.user = $User
                    }
                    if ($Datasource.config.cloud.attributes.PSobject.Properties.name -match "password") {
                        $Datasource.config.cloud.attributes.password = $Password
                    }
                }
                $Datasource = Add-OciDatasource -name $Datasource.name -acquisitionUnit $AcquisitionUnit -config $Datasource.config
                sleep 2
                $null = $Datasource | Remove-OciDatasource
                sleep 3
             }
        }
    }
}

Describe "Application management" {

    BeforeEach {
        $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure
        $null = Get-OciApplications | ? { $_.Name -eq "OciCmdletTest" } | Remove-OciApplication
        $null = Get-OciBusinessEntities | ? { $_.Tenant -eq "OciCmdletTest" } | Remove-OciBusinessEntity
        $OciServer = $null
        $Global:CurrentOciServer = $null
        $Application = $null
    }

    Context "Add and remove application" {
        it "succeeds using only name parameter" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $Application = Add-OciApplication -Name "OciCmdletTest"
            $Application | ValidateApplication
            $Application | Remove-OciApplication
        }

        it "succeeds with priority" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $Application = Add-OciApplication -Name "OciCmdletTest" -priority Critical
            $Application | ValidateApplication
            $Application.priority | Should Be "Critical"
            $Application | Remove-OciApplication
        }

        it "succeeds when associating business entity" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $BusinessEntity = Add-OciBusinessEntity -Tenant "OciCmdletTest"

            $Application = Add-OciApplication -Name "OciCmdletTest" -businessEntity $BusinessEntity.id
            $Application | ValidateApplication
            $Application.businessEntity.id | Should Be $BusinessEntity.id
            $Application | Remove-OciApplication

            $BusinessEntity | Remove-OciBusinessEntity
        }

        it "succeeds with ignoreShareViolations switch" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $Application = Add-OciApplication -Name "OciCmdletTest" -ignoreShareViolations
            $Application | ValidateApplication
            $Application.ignoreShareViolations | Should Be $true
            $Application | Remove-OciApplication
        }

        it "succeeds when list of compute resources is requested" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $Application = Add-OciApplication -Name "OciCmdletTest" -ComputeResources
            $Application | ValidateApplication
            $Application.computeResources | Should BeNullOrEmpty
            $Application | Remove-OciApplication
        }

        it "succeeds when list of storage resources is requested" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $Application = Add-OciApplication -Name "OciCmdletTest" -StorageResources
            $Application | ValidateApplication
            $Application.computeResources | Should BeNullOrEmpty
            $Application | Remove-OciApplication
        }

        it "succeeds with transient OCI Server" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure -Transient
            $Global:CurrentOciServer | Should BeNullOrEmpty

            $Application = Add-OciApplication -Name "OciCmdletTest" -Server $OciServer
            $Application | ValidateApplication
            $Application.computeResources | Should BeNullOrEmpty
            $Application | Remove-OciApplication -Server $OciServer
        }
    }

    Context "Adding, updating and deleting application" {
        it "succeeds when updating priority" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $Application = Add-OciApplication -Name "OciCmdletTest"
            $Application = $Application | Update-OciApplication -priority Critical
            $Application | ValidateApplication
            $Application.priority | Should Be "Critical"
            $Application | Remove-OciApplication
        }

        it "succeeds when associating business entity" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $BusinessEntity = Add-OciBusinessEntity -Tenant "OciCmdletTest"

            $Application = Add-OciApplication -Name "OciCmdletTest"
            $Application = $Application | Update-OciApplication -businessEntity $BusinessEntity.id
            $Application | ValidateApplication
            $Application.businessEntity.id | Should Be $BusinessEntity.id
            $Application | Remove-OciApplication

            $BusinessEntity | Remove-OciBusinessEntity
        }

        it "succeeds with ignoreShareViolations switch" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $Application = Add-OciApplication -Name "OciCmdletTest"
            $Application = $Application | Update-OciApplication -ignoreShareViolations
            $Application | ValidateApplication
            $Application.ignoreShareViolations | Should Be $true
            $Application | Remove-OciApplication
        }

        it "succeeds when list of compute resources is requested" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $Application = Add-OciApplication -Name "OciCmdletTest"
            $Application = $Application | Update-OciApplication -ComputeResources
            $Application | ValidateApplication
            $Application.computeResources | Should BeNullOrEmpty
            $Application | Remove-OciApplication
        }

        it "succeeds when list of storage resources is requested" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $Application = Add-OciApplication -Name "OciCmdletTest" -StorageResources
            $Application = $Application | Update-OciApplication -StorageResources
            $Application | ValidateApplication
            $Application.computeResources | Should BeNullOrEmpty
            $Application | Remove-OciApplication
        }

        it "succeeds with transient OCI Server" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure -Transient
            $Global:CurrentOciServer | Should BeNullOrEmpty

            $Application = Add-OciApplication -Name "OciCmdletTest" -Server $OciServer
            $Application = $Application | Update-OciApplication -Server $OciServer
            $Application | ValidateApplication
            $Application.computeResources | Should BeNullOrEmpty
            $Application | Remove-OciApplication -Server $OciServer
        }
    }
}

Describe "Annotation management" {

    BeforeEach {
        $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure
        $null = Get-OciAnnotations | ? { $_.Name -eq "OciCmdletTest" } | Remove-OciAnnotation
        $OciServer = $null
        $Global:CurrentOciServer = $null
        $Annotation = $null
    }

    Context "adding and removing annotations" {
        it "succeeds for type BOOLEAN" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $Annotation = Add-OciAnnotation -Name "OciCmdletTest" -Type BOOLEAN
            $Annotation | ValidateAnnotation
            $Annotation | Remove-OciAnnotation
        }

        it "succeeds for type DATE" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $Annotation = Add-OciAnnotation -Name "OciCmdletTest" -Type DATE
            $Annotation | ValidateAnnotation
            $Annotation | Remove-OciAnnotation
        }

        it "succeeds for type FIXED_ENUM" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $Annotation = Add-OciAnnotation -Name "OciCmdletTest" -Type FIXED_ENUM -enumValues @(@{name="key1";label="label of key 1"},@{name="key2";label="label of key 2"})
            $Annotation | ValidateAnnotation
            $Annotation | Remove-OciAnnotation
        }

        it "succeeds for type FLEXIBLE_ENUM" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $Annotation = Add-OciAnnotation -Name "OciCmdletTest" -Type FLEXIBLE_ENUM -enumValues @(@{name="key1";label="label of key 1"},@{name="key2";label="label of key 2"})
            $Annotation | ValidateAnnotation
            $Annotation | Remove-OciAnnotation
        }

        it "succeeds for type NUMBER" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $Annotation = Add-OciAnnotation -Name "OciCmdletTest" -Type NUMBER
            $Annotation | ValidateAnnotation
            $Annotation | Remove-OciAnnotation
        }

        it "succeeds with description" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $Annotation = Add-OciAnnotation -Name "OciCmdletTest" -Type BOOLEAN -Description "description"
            $Annotation.description | Should Be "description"
            $Annotation | ValidateAnnotation
            $Annotation | Remove-OciAnnotation
        }

        it "succeeds with transient OCI Server" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure -Transient
            $CurrentOciServer | Should BeNullOrEmpty

            $Annotation = Add-OciAnnotation -Name "OciCmdletTest" -Type BOOLEAN -Server $OciServer
            $Annotation | ValidateAnnotation
            $Annotation | Remove-OciAnnotation -Server $OciServer
        }
    }
}

Describe "OCI server connection management" {
    BeforeEach {
        $OciServer = $null
        $Global:CurrentOciServer = $null
    }

    Context "initiating a connection to an OnCommand Insight Server" {
        it "succeeds with parameters Name, Credential, Insecure" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure
            $OciServer.Name | Should Be $OciServerName
            $Global:CurrentOciServer | Should Be $OciServer
        }

        it "succeeds when forcing HTTPS" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure -HTTPS
            $OciServer.Name | Should Be $OciServerName
            $Global:CurrentOciServer | Should Be $OciServer
        }

        it "succeeds when timezone is set to UTC" {
            $Timezone = [TimeZoneInfo]::UTC
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure -Timezone $Timezone
            $OciServer.Name | Should Be $OciServerName
            $OciServer.Timezone | Should Be $Timezone
            $Global:CurrentOciServer | Should Be $OciServer
        }

        it "succeeds when transient OCI Server object is requested" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Transient -Insecure
            $OciServer.Name | Should Be $OciServerName
            $Global:CurrentOciServer | Should BeNullOrEmpty
        }
    }
}