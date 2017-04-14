function Invoke-DirectAccessProvision {
    param (
        $EnvironmentName
    )
    Invoke-ClusterApplicationProvision -ClusterApplicationName DirectAccess -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisClusterApplicationNode -ClusterApplicationName DirectAccess -EnvironmentName $EnvironmentName
}