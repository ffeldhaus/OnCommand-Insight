Import-Module "$PSScriptRoot\OnCommand-Insight"

$Globa:OciServerName = 'ff-oc1.muccbc.hq.netapp.com'
$Global:OciCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "admin",("admin123" | ConvertTo-SecureString -AsPlainText -Force)

$global:OciTestServer = Connect-OciServer -Name $Name -Credential $Credential -Insecure

Describe "Credential Management" {
    BeforeEach {
        $Credential = $null
        $OciCredential = $null
        $HostName = $null
        $Password = $null

        Remove-OciCredential -Name example.com
    }
    
    AfterEach {
        $Credential = $null
        $OciCredential = $null
        $HostName = $null
        $Password = $null

        Remove-OciCredential -Name example.com
    }

    Context "adding, retrieving and removing of Credentials" {
        it "successfully adds, retrieves and removes a credential with hostname example.com and valid credential" {
            $HostName = "example.com"
            $UserName = "user"
            $Password = "password"
            $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserName,($Password  | ConvertTo-SecureString -AsPlainText -Force)

            Add-OciCredential -Name $HostName -Credential $Credential

            $OciCredential = Get-OciCredential -Name $HostName

            $OciCredential.Credential.UserName | Should Be $UserName
            $OciCredential.Credential.GetNetworkCredential().Password | Should Be $Password

            Remove-OciCredential -Name $HostName

            $OciCredential = Get-OciCredential -Name $HostName

            $OciCredential | Should Be $null
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

        it "succeeds with parameters Name, Credential and Insecure" {
            $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure
            $OciServer.Name | Should Be $OciServerName
            $Global:CurrentOciServer | Should Be $OciServer
        }
    }
    
    Context "initiates a connection to an OnCommand Insight Server without setting the global variable `$Global:CurrentOciServer" {
        it "succeeds with parameters Name, Credential and Transient" {
            $Server = Connect-OciServer -Name example.com -Credential $Credential -Transient
            $Server.Name | Should Be $ServerName
            $Global:CurrentOciServer | Should BeNullOrEmpty
        }
    }
}

Describe "Get-OciAcquisitionUnits" {
    BeforeEach {
        $OciServer = Connect-OciServer -Name $OciServerName -Credential $OciCredential -Insecure
        $Global:CurrentOciServer = $null
        $AcquisitionUnits = $null
    }

    AfterEach {
        $OciServer = $null
        $Global:CurrentOciServer = $null
    }

    Context "gets Acquisition Units" {
        $AcquisitionUnits = Get-OciAcquisitionUnits
        $AcquisitionUnits | Should Not BeNullOrEmpty
    }

    Context "gets Acquisition Units with datasources" {
        $AcquisitionUnits = Get-OciAcquisitionUnits -datasources
        $AcquisitionUnits | Should Not BeNullOrEmpty
        $AcquisitionUnits.datasources | Should Not BeNullOrEmpty
    }
}