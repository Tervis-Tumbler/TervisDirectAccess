function Invoke-DirectAccessProvision {
    param (
        $EnvironmentName
    )
    Invoke-ClusterApplicationProvision -ClusterApplicationName DirectAccess -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisClusterApplicationNode -ClusterApplicationName DirectAccess -EnvironmentName $EnvironmentName
    $Nodes | Enable-CredSSPDoubleHop
    # $Nodes | Add-ExternalFacingNIC
    $Nodes | Add-DirectAccessDnsRecords
    $Nodes | Set-DirectAccessConfiguration
    $Nodes | Install-DirectAccessCertificates
    $Nodes | Enable-DirectAccessCoexistenceWithThirdPartyClients
}

function Enable-CredSSPDoubleHop {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    Process{
        Enable-WSManCredSSP –Role Client –DelegateComputer $ComputerName -Force
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Enable-WSManCredSSP –Role Server -Force
        }
    }
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
    #Requires -Module RemoteAccess
    [cmdletbinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName,
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )
    Begin {
        $ADDomain = Get-ADDomain
        $ADDNSRoot = $ADDomain | Select -ExpandProperty DNSRoot
        $ADNetBIOSName = ($ADDomain | Select -ExpandProperty NetBIOSName).ToLower()
        $DirectAccessServerGpoName = $ADDNSRoot + '\DirectAccess Server Settings'
        $DirectAccessClientGpoName = $ADDNSRoot + '\DirectAccess Client Settings'
        $DirectAccessClientGroupName = $ADDNSRoot + '\Direct Access Client Computers'
        $DomainComputersGroup = $ADDNSRoot + '\Domain Computers'
        $DirectAccessConnectToDomain = 'DirectAccess.' + $ADNetBIOSName + '.com'
        $DirectAccessNlsDomain = 'nls.' + $ADNetBIOSName + '.com'
        $DirectAccessNlsUrl = 'https://' + $DirectAccessNlsDomain + '/'
        $DirectAccessCorporateResources = 'HTTP:http://directaccess-WebProbeHost.' + $ADNetBIOSName + '.com'
    }
    Process {
        $RemoteAccessConfiguration = Get-RemoteAccess -ComputerName $ComputerName
        If (($RemoteAccessConfiguration).DAStatus -eq 'Uninstalled') {
            $NIC = Invoke-Command -ComputerName $ComputerName -ScriptBlock {(Get-NetAdapter).Name}
            Install-RemoteAccess -Force -PassThru -ServerGpoName $DirectAccessServerGpoName -ClientGpoName $DirectAccessClientGpoName -DAInstallType 'FullInstall' -InternetInterface $NIC -InternalInterface $NIC -ConnectToAddress $DirectAccessConnectToDomain -NlsUrl $DirectAccessNlsUrl -ComputerName $ComputerName
            Add-DAClient -SecurityGroupNameList @($DirectAccessClientGroupName) -ComputerName $ComputerName
            Remove-DAClient -SecurityGroupNameList @($DomainComputersGroup) -ComputerName $ComputerName
        }

        $IPsecRootCert = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Get-ChildItem Cert:\LocalMachine\Root | Where-Object {$_.Subject -Match "CN=tervis"} 
        }
        Set-DAServer -IPsecRootCertificate $IPsecRootCert -ComputerName $ComputerName

        if (-NOT (($RemoteAccessConfiguration).ClientSecurityGroupNameList -eq $DirectAccessClientGroupName)) {
            Add-DAClient -SecurityGroupNameList @($DirectAccessClientGroupName) -ComputerName $ComputerName
            Remove-DAClient -SecurityGroupNameList @($DomainComputersGroup) -ComputerName $ComputerName
        }

        if (($RemoteAccessConfiguration).Downlevel -eq 'Disabled') {
            Set-DAClient -Downlevel Enabled -ComputerName $ComputerName
        }

        if (($RemoteAccessConfiguration).OnlyRemoteComputers -eq 'Enabled') {
            Set-DAClient -OnlyRemoteComputers Disabled -ComputerName $ComputerName
        }

        $DAClientExperienceConfiguration = Get-DAClientExperienceConfiguration -PolicyStore $DirectAccessClientGpoName
        if (-NOT (($DAClientExperienceConfiguration).FriendlyName -eq 'Tervis DirectAccess Connection')) {
            Set-DAClientExperienceConfiguration -FriendlyName 'Tervis DirectAccess Connection' -PreferLocalNamesAllowed $False -PolicyStore $Using:DirectAccessClientGpoName -CorporateResources @("$Using:DirectAccessCorporateResources")
        }
    }
}

function Add-DirectAccessDnsRecords {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    Begin {
        $ADDomain = Get-ADDomain
        $ADNetBIOSName = ($ADDomain | Select -ExpandProperty NetBIOSName).ToLower()
        $PDCEmulator = $ADDomain | Select -ExpandProperty PDCEmulator
        $DirectAccessNetWorkLocationServerDnsHostName = 'nls'
        $DirectAccessNetWorkLocationServerDnsAddress = 'nls.' + $ADNetBIOSName + '.com'
        $DirectAccessConnectToHostName = 'directaccess'
        $DirectAccessConnectToAddress = 'DirectAccess.' + $ADNetBIOSName + '.com'
        $DirectAccessWebProbeDnsHostName = 'directaccess-WebProbeHost'
        $DirectAccessWebProbeDnsAddress = 'directaccess-WebProbeHost.' + $ADNetBIOSName + '.com'
        $DNSZone = Get-DnsServerZone -ComputerName $PDCEmulator | where {$_.IsReverseLookupZone -eq $false -and $_.DynamicUpdate -eq "None"} | Select -ExpandProperty ZoneName
    }
    Process {
        $InternalIPAddress = Invoke-Command -ComputerName $ComputerName -ScriptBlock {Get-NetAdapter | Get-NetIPAddress | Where AddressFamily -eq IPv4 | Select -ExpandProperty IPAddress}
        <#
        if (-NOT (Resolve-DnsName $DirectAccessNetWorkLocationServerDnsAddress -Server $PDCEmulator -ErrorAction SilentlyContinue)) {
            Add-DnsServerResourceRecordA -ComputerName $PDCEmulator -Name $DirectAccessNetWorkLocationServerDnsHostName -ZoneName $DNSZone -IPv4Address $InternalIPAddress
        }
        #>
        if (-NOT (Resolve-DnsName $DirectAccessWebProbeDnsAddress -Server $PDCEmulator -ErrorAction SilentlyContinue)) {
            Add-DnsServerResourceRecordA -ComputerName $PDCEmulator -Name $DirectAccessWebProbeDnsHostName -ZoneName $DNSZone -IPv4Address $InternalIPAddress
        }
        if (-NOT (Resolve-DnsName $DirectAccessConnectToAddress -Server $PDCEmulator -ErrorAction SilentlyContinue)) {
            Add-DnsServerResourceRecordA -ComputerName $PDCEmulator -Name $DirectAccessConnectToHostName -ZoneName $DNSZone -IPv4Address $InternalIPAddress
        }
    }
}

function Install-DirectAccessCertificates {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    Begin {
        $WildcardCredential = ConvertTo-SecureString (Get-PasswordstateCredential -PasswordID '2570' -AsPlainText).Password -AsPlainText -Force
        if (-NOT (Test-Path "C:\Temp")) {
            New-Item "C:\Temp" -ItemType Directory
        }
        Get-PasswordstateDocument -DocumentID '3' -FilePath "C:\Temp\Wildcard.pfx"
    }
    Process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            if (-NOT (Test-Path "C:\Temp")) {
                New-Item "C:\Temp" -ItemType Directory
            }
        }
        if (-NOT (Invoke-Command -ComputerName $ComputerName -ScriptBlock {Get-ChildItem -Path cert:\localmachine\my | Where-Object {$_.FriendlyName -eq '*.tervis.com' -and $_.Issuer -match 'CN=Go Daddy'}})) {
            Copy-Item "C:\Temp\Wildcard.pfx" -Destination "\\$ComputerName\C$\Temp\Wildcard.pfx"
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                Import-PfxCertificate -FilePath "C:\Temp\Wildcard.pfx" -Password $Using:WildcardCredential -CertStoreLocation "cert:\localMachine\my"
                $cert = Get-ChildItem -Path cert:\localmachine\my | Where-Object {$_.FriendlyName -eq '*.tervis.com' -and $_.Issuer -match 'CN=Go Daddy'}
                Set-RemoteAccess -SslCertificate $cert
                Remove-Item "C:\Temp\Wildcard.pfx" -Confirm:$false
                Restart-Service -Name iphlpsvc -Force
            }
        }
    }
    End {
        Remove-Item "C:\Temp\Wildcard.pfx" -Confirm:$false
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
