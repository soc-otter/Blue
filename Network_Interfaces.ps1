<#
.SYNOPSIS
Gathers network interface details.

.DESCRIPTION
This script gets information about the host network interfaces. Results are written to a CSV.

.NOTES
Requires PowerShell v5+ and appropriate permissions.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Network_Interfaces.ps1

.EXAMPLE
PS> .\Network_Interfaces.ps1
#>

# Output directory
$outputDirectory = 'C:\BlueTeam'

Write-Progress -Activity "Network Interface Details" -Status "Setting up directory..." -PercentComplete 10

# Create the output directory if it doesn't exist
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Retrieve network adapter details
Write-Progress -Activity "Network Interface Details" -Status "Retrieving network adapter details..." -PercentComplete 20
$networkAdapters = Get-NetAdapter | Select-Object InterfaceIndex, Name, MacAddress

# Retrieve IP address details
Write-Progress -Activity "Network Interface Details" -Status "Retrieving IP address details..." -PercentComplete 30
$ipAddressDetails = Get-NetIPAddress | Select-Object InterfaceIndex, InterfaceAlias, IPAddress, AddressFamily, Type, PrefixOrigin, SuffixOrigin, AddressState, ValidLifetime, PreferredLifetime, SkipAsSource, PolicyStore

# Function to convert TimeSpan to a readable format
function ConvertTo-ReadableTimeSpan {
    param (
        [TimeSpan]$timespan
    )

    if ($timespan.Ticks -eq [TimeSpan]::MaxValue.Ticks) {
        return "Infinite"
    } elseif ($timespan.Ticks -eq [TimeSpan]::MinValue.Ticks) {
        return "Invalid/Uninitialized"
    } else {
        return ("{0} days, {1} hours, {2} minutes, {3} seconds" -f 
            $timespan.Days, $timespan.Hours, $timespan.Minutes, $timespan.Seconds)
    }
}

# Function to replace empty values with a hyphen
function Replace-EmptyWithHyphen {
    param (
        $value
    )
    
    if ([string]::IsNullOrWhiteSpace($value)) {
        return "-"
    } else {
        return $value
    }
}

# Create a lookup table for network adapters by InterfaceIndex
$adapterLookup = @{}
foreach ($adapter in $networkAdapters) {
    $adapterLookup[$adapter.InterfaceIndex] = $adapter
}

# Process interface
$detailCount = $ipAddressDetails.Count
$processedCount = 0
$progressPerDetail = if ($detailCount -gt 0) { 50 / $detailCount } else { 0 }

# Hold network details
$networkDetails = New-Object System.Collections.Generic.List[PSObject]

# Merge
foreach ($currentIP in $ipAddressDetails) {
    $processedCount++
    $currentProgress = 30 + ($processedCount * $progressPerDetail)
    Write-Progress -Activity "Network Interface Details" -Status "Processing interface $processedCount of $detailCount..." -PercentComplete $currentProgress

    # Get the adapter
    $currentAdapter = $adapterLookup[$currentIP.InterfaceIndex]
    
    # Convert lifetimes to readable
    $validLifetimeReadable = ConvertTo-ReadableTimeSpan -timespan $currentIP.ValidLifetime
    $preferredLifetimeReadable = ConvertTo-ReadableTimeSpan -timespan $currentIP.PreferredLifetime
    $macAddress = Replace-EmptyWithHyphen $currentAdapter.MacAddress

    $networkDetail = [PSCustomObject]@{
        'Interface Name'                = Replace-EmptyWithHyphen $currentIP.InterfaceAlias
        'IP Address'                    = Replace-EmptyWithHyphen $currentIP.IPAddress
        'MAC Address'                   = $macAddress
        'Protocol'                      = Replace-EmptyWithHyphen $currentIP.AddressFamily
        'Interface ID'                  = Replace-EmptyWithHyphen $currentIP.InterfaceIndex
        'Address Type'                  = Replace-EmptyWithHyphen $currentIP.Type
        'IP Acquisition Method'         = Replace-EmptyWithHyphen $currentIP.PrefixOrigin
        'Suffix Acquisition Method'     = Replace-EmptyWithHyphen $currentIP.SuffixOrigin
        'Address State'                 = Replace-EmptyWithHyphen $currentIP.AddressState
        'Lifetime (Valid)'              = Replace-EmptyWithHyphen $currentIP.ValidLifetime.ToString()
        'Lifetime (Valid) Readable'     = $validLifetimeReadable
        'Lifetime (Preferred)'          = Replace-EmptyWithHyphen $currentIP.PreferredLifetime.ToString()
        'Lifetime (Preferred) Readable' = $preferredLifetimeReadable
        'Skip as Source'                = Replace-EmptyWithHyphen $currentIP.SkipAsSource
        'Policy Storage'                = Replace-EmptyWithHyphen $currentIP.PolicyStore
    }

    # Add to the list
    $networkDetails.Add($networkDetail)
}

Write-Progress -Activity "Network Interface Details" -Status "Preparing for export..." -PercentComplete 80
$outputFilePath = Join-Path -Path $outputDirectory -ChildPath "Network_Interfaces.csv"

# Export to CSV
Write-Progress -Activity "Network Interface Details" -Status "Exporting to CSV..." -PercentComplete 90
$networkDetails | Export-Csv -Path $outputFilePath -NoTypeInformation

Write-Progress -Activity "Network Interface Details" -Status "Completed" -PercentComplete 100
