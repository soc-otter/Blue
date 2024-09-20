<#
.SYNOPSIS
Gets DNS settings for connected network interfaces and sorts by priority.

.DESCRIPTION
This script gathers DNS-related details on connected network interfaces, including their DNS server addresses for both IPv4 and IPv6, and sorts them by interface metrics. Results are written to a CSV.

.NOTES
Requires PowerShell v5+ and appropriate permissions to access network interface configurations.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Interface_DNS_Priorities.ps1

.EXAMPLE
PS> .\Interface_DNS_Priorities.ps1
#>

# Output path
$outputFolder = 'C:\BlueTeam'
$outputFile = Join-Path $outputFolder 'Interface_DNS_Priorities.csv'

if (-not (Test-Path -Path $outputFolder)) {
    New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null
}

# Get details for each connected interface
$Combined = Get-NetIPInterface | Where-Object ConnectionState -EQ 'Connected' | ForEach-Object {
    [PSCustomObject]@{
        InterfaceAlias  = if ($_.InterfaceAlias) { $_.InterfaceAlias } else { '-' }
        InterfaceIndex  = $_.InterfaceIndex
        InterfaceMetric = $_.InterfaceMetric
        DNSIPv4         = (Get-DnsClientServerAddress | Where-Object InterfaceIndex -EQ $_.InterfaceIndex | Where-Object AddressFamily -EQ 2).ServerAddresses -join ', '
        DNSIPv6         = (Get-DnsClientServerAddress | Where-Object InterfaceIndex -EQ $_.InterfaceIndex | Where-Object AddressFamily -EQ 23).ServerAddresses -join ', '
    }
} | Sort-Object InterfaceMetric -Unique

# Export to CSV
$Combined | Export-Csv -Path $outputFile -NoTypeInformation -Force | Out-Null

Write-Progress -Id 1 -Activity "Processing Complete" -Completed
