$ScriptPath = Split-Path -Parent $PSCommandPath

Import-Module $ScriptPath\OnCommand-Insight.psm1

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
        Mock -ModuleName OnCommand-Insight Invoke-RestMethod { 
            if ($Record) {
                Write-Host $Uri
                Write-Host $Headers
                $Result = Microsoft.PowerShell.Utility\Invoke-RestMethod -Body $Body `
                                            -Headers $Headers `
                                            -Method $Method `
                                            -OutFile $ScriptPath\$Version-recording.json `
                                            -Uri $Uri
            }
            else {
                $FileName = "$ScriptPath\$Version-recording.json"
                if (Test-Path -Path $FileName) {
                    $Result = Get-Content $FileName
                }
                else {
                    throw "Recording $FileName does not exist, run first with -Recording, -Server and -Version parameters"
                }
            }

            $Result
        }

        it "succeeds with parameters Name, Credential and Insecure" {
            $OciServer = Connect-OciServer -Name $Server -Credential $Credential -Insecure
            $OciServer.Name | Should Be $Server
            #$Server.APIVersion | Should Be $MockProxyAPIVersion
            $Global:CurrentOciServer | Should Be $OciServer
        }
    }
    #Context "initiates a connection to an OnCommand Insight Server without setting the global variable `$Global:CurrentOciServer" {
    #    Mock -ModuleName OnCommand-Insight Get-OciProxy { return $MockProxy }
    #    Mock -ModuleName OnCommand-Insight New-WebServiceProxy { return $MockProxy }
    #    it "succeeds with parameters Name, Credential and Transient" {
    #        $Global:CurrentOciServer = $null
    #        $Server = Connect-OciServer -Name example.com -Credential $Credential -Transient
    #        $Server.Name | Should Be "example.com"
    #        $Server.SANScreenVersion | Should Be $MockProxySANScreenVersion
    #        $Server.Limit | Should Be 1000
    #        $Server.APIVersion | Should Be $MockProxyAPIVersion
    #        $Global:CurrentOciServer | Should BeNullOrEmpty
    #        Assert-MockCalled New-WebServiceProxy -ModuleName OnCommand-Insight -Times 1
    #    }
    #}
}
