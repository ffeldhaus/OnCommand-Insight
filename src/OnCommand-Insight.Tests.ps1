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
    [parameter(Mandatory=$False,
                Position=0,
                ValueFromPipeline=$True,
                HelpMessage="Expand parameter for underlying JSON object (e.g. expand=datasources)")][PSObject]$AcquisitionUnit
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

function ValidateDatasources {
    [CmdletBinding()]
        
    PARAM (
    [parameter(Mandatory=$False,
                Position=0,
                ValueFromPipeline=$True,
                HelpMessage="Expand parameter for underlying JSON object (e.g. expand=datasources)")][PSObject]$Datasource
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

Describe "Connect-OciServer" {
    BeforeEach {
        $OciServer = $null
        $Global:CurrentOciServer = $null
    }

    AfterEach {
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

        it "succeeds and successfully sets timezone to UTC" {
            $Timezone = [TimeZoneInfo]::UTC
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure -Timezone $Timezone
            $OciServer.Name | Should Be $OciServerName
            $OciServer.Timezone | Should Be $Timezone
            $Global:CurrentOciServer | Should Be $OciServer
        }

        it "succeeds and returns a transient OCI Server object" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Transient -Insecure
            $OciServer.Name | Should Be $OciServerName
            $Global:CurrentOciServer | Should BeNullOrEmpty
        }
    }
}

Describe "Get-OciAcquisitionUnits" {

    BeforeEach {
        $Global:CurrentOciServer = $null
        $AcquisitionUnits = $null
    }

    AfterEach {
        $OciServer = $null
        $Global:CurrentOciServer = $null
    }

    Context "retrieves acquisition units" {
        it "succeeds with no parameters" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure

            $AcquisitionUnits = Get-OciAcquisitionUnits
            $AcquisitionUnits | Should Not BeNullOrEmpty
            $AcquisitionUnits | ValidateAcquisitionUnit
        }

        it "succeeds with transient OCI Server" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure -Transient

            $AcquisitionUnits = Get-OciAcquisitionUnits -Server $OciServer
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
    }
}