<#
.SYNOPSIS
Gathers details of previously connected Wi-Fi networks.

.DESCRIPTION
This script retrieves the names and security keys of Wi-Fi networks previously connected to on the system. This is useful for cyber investigations to review past Wi-Fi connections, source of infection networks, user locations, and helping to identify potential adversarial activities or unauthorized access points.

.NOTES
Requires PowerShell v5+ and administrative privileges

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Historical_WiFi_Connections.ps1

.EXAMPLE
PS> .\Historical_WiFi_Connections.ps1
#>

# This 1-liner is great for shells that cannot accept multi-line input and writes to the terminal
#(netsh wlan show profiles) -match "All User Profile" -replace "^\s+All User Profile\s+:\s+" | ForEach-Object { $ssid = $_; $pwd = ((netsh wlan show profile name="$ssid" key=clear) -match "Key Content\s+:\s+(.*)" | Out-String).Trim() -replace "Key Content\s+:\s+" -replace "^{|}$", ""; [PSCustomObject]@{Name=$ssid; Password=$pwd} } | Format-Table -AutoSize

# Define the output directory
$outputDirectory = 'C:\BlueTeam'

# Create the output directory if it doesn't exist
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Define the output file
$outputFilePath = "$outputDirectory\Historical_WiFi_Connections.csv"

# Retrieve the currently connected SSID
$connectedSSID = netsh wlan show interfaces | ForEach-Object {
    if ($_ -match "^\s*SSID\s+:\s+(.+)$") {
        return $matches[1].Trim()
    }
}

# Initialize a list to hold Wi-Fi profile objects
$wifiProfileObjects = @()

# Retrieve the list of Wi-Fi profiles
$ssidList = ((netsh.exe wlan show profile) -split "`n" | Where-Object {$_ -match 'Profile\s+:'} | ForEach-Object {($_ -split ':')[-1]}).Trim()

# Process each Wi-Fi profile
for ($i = 0; $i -lt $ssidList.Count; $i++) {
    $ssid = $ssidList[$i]
    Write-Progress -Activity "Collecting Wi-Fi Profiles" -Status "Processing SSID $i of $($ssidList.Count)" -PercentComplete (($i / $ssidList.Count) * 100)
    
    # Retrieve detailed information for each Wi-Fi profile
    $profileDetails = (netsh wlan show profile name="$ssid" key=clear) -split "`n" | Where-Object {$_ -match '^\s.+:'}
    $profileObject = New-Object PSObject

    foreach ($detail in $profileDetails) {
        $keyValuePair = $detail.Trim() -split ':', 2
        $key = ($keyValuePair[0].Replace(' ', '_').Replace('Key_Content', 'Password') -replace "_+$", '') # Removes trailing underscores
        $value = $keyValuePair[1].Trim()

        # Add or update the property in the profile object
        $profileObject | Add-Member -MemberType NoteProperty -Name $key -Value $value -Force
    }

    # Add the IsConnected property to the profile object
    $profileObject | Add-Member -MemberType NoteProperty -Name 'IsConnected' -Value ($ssid -eq $connectedSSID)

    $wifiProfileObjects += $profileObject
}

Write-Progress -Activity "Collecting Wi-Fi Profiles" -Status "Processing Complete" -Completed

# Define the primary headers to be ordered first in the CSV
$primaryHeaders = @(
    'SSID_name',
    'IsConnected',  # Add IsConnected as a primary header
    'Name',
    'Authentication',
    'Cipher',
    'Security_key',
    'Connection_mode',
    'AutoSwitch',
    'MAC_Randomization',
    'Type',
    'Network_broadcast',
    'Radio_type',
    'Network_type',
    'Password'
)

# Detect additional headers dynamically from the first profile object if available
$additionalHeaders = @()
if ($wifiProfileObjects.Count -gt 0) {
    $additionalHeaders = $wifiProfileObjects[0].psobject.Properties.Name | Where-Object { $_ -notin $primaryHeaders }
}

# Define the complete order of columns for the CSV export
$orderedColumns = $primaryHeaders + $additionalHeaders

# Export the list of profile objects to CSV format
$wifiProfileObjects | Select-Object -Property $orderedColumns | Export-Csv -Path $outputFilePath -NoTypeInformation
