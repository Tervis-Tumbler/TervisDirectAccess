function Invoke-DirectAccessProvision {
    param (
        $EnvironmentName
    )
    Invoke-ClusterApplicationProvision -ClusterApplicationName DirectAccess -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisClusterApplicationNode -ClusterApplicationName DirectAccess -EnvironmentName $EnvironmentName
    # $Nodes | Add-ExternalFacingNIC
    $Nodes | Set-DirectAccessConfiguration
    $Nodes | Install-DirectAccessCertificates
    $Nodes | Enable-DirectAccessCoexistenceWithThirdPartyClients
    $Nodes | Add-DirectAccessDnsRecords
}

function Add-ExternalFacingNIC {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    Begin {
        $ADDomain = Get-ADDomain
        $PDCEmulator = $ADDomain | Select -ExpandProperty PDCEmulator
        $DHCPScope = get-dhcpserverv4scope -ComputerName $(Get-DhcpServerInDC | select -First 1 -ExpandProperty DNSName) | 
            where name -match ^management | Select -ExpandProperty ScopeId
    }
    Process {
        $NetworkAdapters = Invoke-Command -ComputerName $ComputerName -ScriptBlock {Get-NetAdapter}
        if (-NOT ($NetworkAdapters.count -ge 2)) {
            $HyperVHosts = Get-HyperVHosts
            $VMNetworkAdapter = Start-ParallelWork -Parameters $HyperVHosts -OptionalParameters $ComputerName -ScriptBlock {
                param($HyperVHost, [String[]]$ComputerName)
                Invoke-Command -ComputerName $HyperVHost -ErrorAction SilentlyContinue -ArgumentList (,$ComputerName) -ScriptBlock { 
                    param ([String[]]$ComputerName)
                    Get-VMNetworkAdapter -VMName $ComputerName
                }
            }
            Add-VMNetworkAdapter -ComputerName ($VMNetworkAdapter).ComputerName -VMName $ComputerName -SwitchName ($VMNetworkAdapter).SwitchName
            Get-TervisVM -Name $ComputerName -ComputerName ($VMNetworkAdapter).ComputerName |
            Set-TervisVMNetworkAdapter -DHCPScope $DHCPScope -UseVlanTagging -PassThru |
            Set-TervisDHCPForVM -DHCPScope $DHCPScope
        }
    }
}

function Set-DirectAccessConfiguration {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    Begin {
        $ADDomain = Get-ADDomain
        $ADDNSRoot = $ADDomain | Select -ExpandProperty DNSRoot
        $ADNetBIOSName = $ADDomain | Select -ExpandProperty NetBIOSName
        $DirectAccessServerGpoName = $ADDNSRoot + '\DirectAccess Server Settings'
        $DirectAccessClientGpoName = $ADDNSRoot + '\DirectAccess Client Settings'
        $DirectAccessConnectToDomain = 'DirectAccess.' + $ADNetBIOSName + '.com'
        $DirectAccessNlsUrl = 'https://nls.' + $ADNetBIOSName + '.com/'
        $DirectAccessCorporateResources = 'HTTP:http://directaccess-WebProbeHost.' + $ADNetBIOSName + '.com'
    }
    Process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            if ((Get-RemoteAccess).DAStatus -eq 'Uninstalled') {
                Install-RemoteAccess -Force -PassThru -ServerGpoName $Using:DirectAccessServerGpoName -ClientGpoName $Using:DirectAccessClientGpoName -DAInstallType 'FullInstall' -InternetInterface 'Internet' -InternalInterface 'Internal' -ConnectToAddress $Using:DirectAccessConnectToDomain -NlsUrl $Using:DirectAccessNlsUrl
            }
            $certs = Get-ChildItem Cert:\LocalMachine\Root  
            $IPsecRootCert = $certs | Where-Object {$_.Subject -Match "INF-DirectAcc"}  
            Set-DAServer -IPsecRootCertificate $IPsecRootCert 

            Set-DAClient -OnlyRemoteComputers 'Disabled' -Downlevel 'Enabled'

            Set-DAClientExperienceConfiguration -FriendlyName 'Tervis DirectAccess Connection' -PreferLocalNamesAllowed $False -PolicyStore $Using:DirectAccessClientGpoName -CorporateResources @($Using:DirectAccessCorporateResources)
        }
    }
}

function Add-DirectAccessDnsRecords {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    Begin {
        $ADDomain = Get-ADDomain
        $ADNetBIOSName = $ADDomain | Select -ExpandProperty NetBIOSName
        $PDCEmulator = $ADDomain | Select -ExpandProperty PDCEmulator
        $DirectAccessNetWorkLocationServerDnsHostName = 'nls.' + $ADNetBIOSName + '.com'
        $DirectAccessWebProbeDnsHostName = 'directaccess-WebProbeHost.' + $ADNetBIOSName + '.com'
        $DNSZone = Get-DnsServerZone -ComputerName $PDCEmulator | where {$_.IsReverseLookupZone -eq $false -and $_.DynamicUpdate -eq "None"} | Select -ExpandProperty ZoneName
    }
    Process {
        $InternalIPAddress = Invoke-Command -ComputerName $ComputerName -ScriptBlock {Get-NetAdapter | Get-NetIPAddress | Where AddressFamily -eq IPv4 | Select -ExpandProperty IPAddress}
        if (-NOT (Resolve-DnsName $DirectAccessNetWorkLocationServerDnsHostName)) {
            Add-DnsServerResourceRecordA -ComputerName $PDCEmulator -Name $DirectAccessNetWorkLocationServerDnsHostName -ZoneName $DNSZone -IPv4Address $InternalIPAddress
        }
        if (-NOT (Resolve-DnsName $DirectAccessWebProbeDnsHostName)) {
            Add-DnsServerResourceRecordA -ComputerName $PDCEmulator -Name $DirectAccessWebProbeDnsHostName -ZoneName $DNSZone -IPv4Address $InternalIPAddress
        }
    }
}

function Install-DirectAccessCertificates {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    Begin {

    }
    Process {
        # certificates for IP-HTTPS
        # netsh http add ssl ipport=0.0.0.0:443 certhash=<use the thumbprint from wildcard cert> appid=<use the appid from the binding>
    }
}

function Enable-DirectAccessCoexistenceWithThirdPartyClients {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    Begin {
        [string]$ThirdPartyVpnClientCoexistenceRegistryPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\ShowDomainEndpointInterfaces"
        [string]$ThirdPartySplitTunnelRegistryPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet"
    }
    Process {
        if (-NOT (Invoke-Command -ComputerName $computername -ScriptBlock {Get-ItemProperty -Path $Using:ThirdPartyVpnClientCoexistenceRegistryPath -Name "ShowDomainEndpointInterfaces" -ErrorAction SilentlyContinue})) {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                New-Item -Path $Using:ThirdPartyVpnClientCoexistenceRegistryPath
                New-ItemProperty -Path $Using:ThirdPartyVpnClientCoexistenceRegistryPath -Name "ShowDomainEndpointInterfaces" -Value 1 -PropertyType DWORD -Force
            }
        }

        if (-NOT (Invoke-Command -ComputerName $computername -ScriptBlock {Get-ItemProperty -Path $Using:ThirdPartySplitTunnelRegistryPath -Name "EnableNoGatewayLocationDetection" -ErrorAction SilentlyContinue})) {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                New-Item -Path $Using:ThirdPartySplitTunnelRegistryPath
                New-ItemProperty -Path $Using:ThirdPartySplitTunnelRegistryPath -Name "EnableNoGatewayLocationDetection" -Value 1 -PropertyType DWORD -Force
            }
        }
    }
}
