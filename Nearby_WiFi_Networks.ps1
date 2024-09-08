<#
.SYNOPSIS
Gathers metadata about nearby Wi-Fi networks.

.DESCRIPTION
This script retrieves information about visible Wi-Fi networks using the `netsh wlan show network mode=bssid` command. The metadata for each network, such as SSID, BSSID, signal strength, radio type, channel, and rates, is parsed and exported to a CSV file. Additionally, the script identifies whether the network is actively connected by checking both the SSID and BSSID. This is useful for identifying potential security risks or unauthorized networks within range of the host.

.NOTES
Requires PowerShell v5+.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Nearby_Wifi_Networks.ps1

.EXAMPLE
PS> .\Nearby_Wifi_Networks.ps1
#>

# Define the output directory and file path
$outputDirectory = "C:\BlueTeam"
$outputFile = "Nearby_Wifi_Networks.csv"
$outputPath = Join-Path -Path $outputDirectory -ChildPath $outputFile

# Create the output directory if it doesn't exist
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Capture the output of the netsh commands
$netshOutput = netsh wlan show network mode=bssid

# Retrieve the currently connected SSID and BSSID
$interfaceInfo = netsh wlan show interfaces
$connectedSSID = $null
$connectedBSSID = $null

foreach ($line in $interfaceInfo) {
    if ($line -match "^\s*SSID\s+:\s+(.+)$") {
        $connectedSSID = $matches[1].Trim()
    }
    if ($line -match "^\s*BSSID\s+:\s+(.+)$") {
        $connectedBSSID = $matches[1].Trim()
    }
}

# Initialize an array to hold Wi-Fi network information
$wifiNetworks = @()
$currentSSID = $null
$bssidInfo = $null

# Function to add BSSID information to the array
function Add-BssidInfo {
    param (
        [ref]$bssidInfo,
        [ref]$wifiNetworks
    )
    if ($bssidInfo.Value) {

        # Determine if the current SSID and BSSID are the ones currently connected
        $bssidInfo.Value.IsConnected = ($bssidInfo.Value.SSID -eq $connectedSSID) -and ($bssidInfo.Value.BSSID -eq $connectedBSSID)
        $wifiNetworks.Value += $bssidInfo.Value
        $bssidInfo.Value = $null
    }
}

# Parse the netsh output
foreach ($line in $netshOutput) {
    $trimmedLine = $line.Trim()

    if ($line -match "^SSID\s+\d+\s+:\s+(.+)$") {

        # Add previous BSSID info before processing the new SSID
        Add-BssidInfo -bssidInfo ([ref]$bssidInfo) -wifiNetworks ([ref]$wifiNetworks)

        $currentSSID = $matches[1].Trim()
    } elseif ($line -match "^\s{4}BSSID\s+\d+\s+:\s+(.+)$" -and $currentSSID) {

        # Add previous BSSID info before processing the new BSSID
        Add-BssidInfo -bssidInfo ([ref]$bssidInfo) -wifiNetworks ([ref]$wifiNetworks)

        $bssid = $matches[1].Trim()
        $bssidInfo = [PSCustomObject]@{
            SSID        = $currentSSID
            IsConnected = $false  # Initialize with false, will be updated in Add-BssidInfo
            BSSID       = $bssid
            Signal      = ""
            RadioType   = ""
            Channel     = ""
            BasicRates  = ""
            OtherRates  = ""
        }
    } elseif ($bssidInfo) {
        if ($line -match "^\s{9}Signal\s*:\s*(.+)$") {
            $bssidInfo.Signal = $matches[1].Trim()
        } elseif ($line -match "^\s{9}Radio type\s*:\s*(.+)$") {
            $bssidInfo.RadioType = $matches[1].Trim()
        } elseif ($line -match "^\s{9}Channel\s*:\s*(.+)$") {
            $bssidInfo.Channel = $matches[1].Trim()
        } elseif ($line -match "^\s{9}Basic rates \(Mbps\)\s*:\s*(.+)$") {
            $bssidInfo.BasicRates = $matches[1].Trim()
        } elseif ($line -match "^\s{9}Other rates \(Mbps\)\s*:\s*(.+)$") {
            $bssidInfo.OtherRates = $matches[1].Trim()
        }
    }
}

# Add the last BSSID info object to the array if it exists
Add-BssidInfo -bssidInfo ([ref]$bssidInfo) -wifiNetworks ([ref]$wifiNetworks)

# Ensure the IsConnected column appears after SSID
$orderedColumns = @('SSID', 'IsConnected') + ($wifiNetworks[0].PSObject.Properties.Name | Where-Object { $_ -notin @('SSID', 'IsConnected') })

# Export the Wi-Fi network information to a CSV file with explicitly ordered columns
$wifiNetworks | Select-Object -Property $orderedColumns | Export-Csv -Path $outputPath -NoTypeInformation -Force
