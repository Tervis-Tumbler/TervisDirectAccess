function Invoke-DirectAccessProvision {
    param (
        $EnvironmentName
    )
    Invoke-ClusterApplicationProvision -ClusterApplicationName DirectAccess -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisClusterApplicationNode -ClusterApplicationName DirectAccess -EnvironmentName $EnvironmentName
}

function Set-DirectAccessConfiguration {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    Begin {
        $DirectAccessServerGpoName = $env:USERDNSDOMAIN + '\DirectAccess Server Settings'
        $DirectAccessClientGpoName = $env:USERDNSDOMAIN + '\DirectAccess Client Settings'
        $DirectAccessConnectToDomain = 'DirectAccess.' + $env:USERDOMAIN + '.com'
        $DirectAccessNlsUrl = 'https://nls.' + $env:USERDOMAIN + '.com/'
        $DirectAccessCorporateResources = 'HTTP:http://directaccess-WebProbeHost.' + $env:USERDOMAIN + '.com'
    }
    Process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Install-RemoteAccess -Force -PassThru -ServerGpoName $Using:DirectAccessServerGpoName -ClientGpoName $Using:DirectAccessClientGpoName -DAInstallType 'FullInstall' -InternetInterface 'Internet' -InternalInterface 'Internal' -ConnectToAddress $Using:DirectAccessConnectToDomain -NlsUrl $Using:DirectAccessNlsUrl

            $certs = Get-ChildItem Cert:\LocalMachine\Root  
            $IPsecRootCert = $certs | Where-Object {$_.Subject -Match "INF-DirectAcc"}  
            Set-DAServer -IPsecRootCertificate $IPsecRootCert 

            Set-DAClient -OnlyRemoteComputers 'Enabled' -Downlevel 'Enabled'

            Set-DAClientExperienceConfiguration -FriendlyName 'Tervis DirectAccess Connection' -PreferLocalNamesAllowed $False -PolicyStore $Using:DirectAccessClientGpoName -CorporateResources @($Using:DirectAccessCorporateResources)
        }
    }
}