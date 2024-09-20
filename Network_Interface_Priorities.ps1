<#
.SYNOPSIS
Gets network interface information and sorts by priority.

.DESCRIPTION
This script gathers details on network interfaces, including their DNS settings, connection state, interface metrics, MAC address, IP addresses, and more. Results are written to a CSV.

.NOTES
Requires PowerShell v5+ and appropriate permissions to access network interface configurations.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Network_Interface_Priorities.ps1

.EXAMPLE
PS> .\Network_Interface_Priorities.ps1
#>

# Output path
$outputFolder = 'C:\BlueTeam'
$outputFile = Join-Path $outputFolder 'Network_Interface_Priorities.csv'

if (-not (Test-Path -Path $outputFolder)) {
    New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null
}

# Track InterfaceIndex
$processedInterfaces = @{}

# Collect interface details
$interfaces = Get-NetIPInterface | ForEach-Object {
    if (-not $processedInterfaces.ContainsKey($_.InterfaceIndex)) {
        $dnsIPv4 = (Get-DnsClientServerAddress | Where-Object InterfaceIndex -EQ $_.InterfaceIndex | Where-Object AddressFamily -EQ 2).ServerAddresses -join ', '
        $dnsIPv6 = (Get-DnsClientServerAddress | Where-Object InterfaceIndex -EQ $_.InterfaceIndex | Where-Object AddressFamily -EQ 23).ServerAddresses -join ', '
        $adapter = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue

        $processedInterfaces[$_.InterfaceIndex] = [PSCustomObject]@{
            InterfaceAlias       = if ($_.InterfaceAlias) { $_.InterfaceAlias } else { '-' }
            InterfaceIndex       = $_.InterfaceIndex
            InterfaceMetric      = $_.InterfaceMetric
            IPv4DNS              = if ($dnsIPv4) { $dnsIPv4 } else { '-' }
            IPv6DNS              = if ($dnsIPv6) { $dnsIPv6 } else { '-' }
            ConnectionState      = if ($_.ConnectionState) { $_.ConnectionState } else { '-' }
            InterfaceDescription = if ($adapter) { $adapter.InterfaceDescription } else { '-' }
            MacAddress           = if ($adapter) { $adapter.MacAddress } else { '-' }
            LinkSpeed            = if ($adapter) { $adapter.LinkSpeed } else { '-' }
            DhcpEnabled          = if ($adapter -and $adapter.DhcpEnabled -ne $null) { $adapter.DhcpEnabled } else { '-' }
            IP4Address           = (Get-NetIPAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress -join ', ' -replace '(^$|-)', '-'
            IP6Address           = (Get-NetIPAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue).IPAddress -join ', ' -replace '(^$|-)', '-'
        }
    }
}

# Convert hash table to array
$interfacesArray = $processedInterfaces.Values

# Order by InterfaceMetric
$orderedInterfaces = $interfacesArray | Sort-Object InterfaceMetric

# Export to CSV
$orderedInterfaces | Export-Csv -Path $outputFile -NoTypeInformation -Force | Out-Null

Write-Progress -Id 1 -Activity "Processing Complete" -Completed
