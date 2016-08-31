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
            $AcquisitionUnit.status | Should Be "CONNECTED"
            $AcquisitionUnit.isActive | Should Be "True"
            $AcquisitionUnit.leaseContract | Should Be 120000
            $AcquisitionUnit.nextLeaseRenewal | Should BeGreaterThan (Get-Date)
            $AcquisitionUnit.lastReported | Should BeLessThan (Get-Date)
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

function ValidateDatasources {
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
            $Datasource.statusText | Should Match ".+"
            $Datasource.pollStatus | Should Match "[A-Z]+"
            $Datasource.vendor | Should Match ".+"
            $Datasource.foundationIp | Should Match "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"
            $Datasource.lastSuccessfullyAccquired | Should BeLessThan (Get-Date)
            if ($Datasource.resumeTime) {
                $Datasource.resumeTime | Should BeGreaterThan (Get-Date)
            }
    }
}

Describe "Connecting to OCI server" {
    BeforeEach {
        $OciServer = $null
        $Global:CurrentOciServer = $null
    }

    Context "initiates a connection to an OnCommand Insight Server" {
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

Describe "Add-OciAnnotation" {

    BeforeEach {
        $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure
        $null = Get-OciAnnotations | ? { $_.Name -eq "OciCmdletTest" } | Remove-OciAnnotation
        $OciServer = $null
        $Global:CurrentOciServer = $null
        $Annotation = $null
    }

    Context "adds annotation" {
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

        it "succeeds for type FIXED_ENUM" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $Annotation = Add-OciAnnotation -Name "OciCmdletTest" -Type FLEXIBLE_ENUM -enumValues @(@{name="key1";label="label of key 1"},@{name="key2";label="label of key 2"})
            $Annotation | ValidateAnnotation
            $Annotation | Remove-OciAnnotation
        }

        it "succeeds for type FIXED_ENUM" {
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

Describe "Get-OciAcquisitionUnits" {

    BeforeEach {
        $OciServer = $null
        $Global:CurrentOciServer = $null
        $AcquisitionUnits = $null
    }

    Context "retrieves acquisition units" {
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
            $AcquisitionUnits.datasources | ValidateDatasources
        }

        it "succeeds with transient OCI Server" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure -Transient
            $Global:CurrentOciServer | Should BeNullOrEmpty

            $AcquisitionUnits = Get-OciAcquisitionUnits -Server $OciServer
            $AcquisitionUnits | Should Not BeNullOrEmpty
            $AcquisitionUnits | ValidateAcquisitionUnit
        }
    }
}