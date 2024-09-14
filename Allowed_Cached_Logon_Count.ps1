<#
.SYNOPSIS
Queries the registry for the allowed cached user logon count.

.DESCRIPTION
Fetches the "CachedLogonsCount" value from the registry key `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, which specifies how many user credentials are stored locally on a machine when a domain controller isn’t available. This setting is used to allow users to log in even if the network connection to the domain is down. Setting it too low might lock out legitimate users who need to access their accounts offline (default is 10). Results are written to a CSV.

.NOTES
Requires PowerShell v5+ and administrative privileges to access the registry.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Allowed_Cached_Logon_Count.ps1

.EXAMPLE
PS> .\Allowed_Cached_Logon_Count.ps1
#>

# Registry path and property name
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$propertyName = "CachedLogonsCount"

# Output directory and file
$outputDirectory = "C:\BlueTeam"
$outputFileName = "Allowed_Cached_Logon_Count.csv"
$outputPath = Join-Path $outputDirectory $outputFileName

# Create output directory if it doesn't exist
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Initialize variables
$valueType = "-"
$valueData = "-"
$valueExists = $false  # Flag to check if the value exists

# Query the registry
Write-Progress -Activity "Querying Registry" -Status "Fetching $propertyName from $registryPath"
try {
    $regItem = Get-ItemProperty -Path $registryPath -Name $propertyName -ErrorAction Stop
    $valueData = $regItem.$propertyName

    $regKey = Get-Item -Path $registryPath -ErrorAction Stop
    $valueType = $regKey.GetValueKind($propertyName).ToString()

    # Set flag to true if value is retrieved
    if ($valueData -ne $null -and $valueData -ne "") {
        $valueExists = $true
    }
} catch {
    Write-Warning "Failed to retrieve $propertyName from ${registryPath}: $_"
}

Write-Progress -Activity "Querying Registry" -Completed

# Proceed only if the value exists
if ($valueExists) {
    # Replace null or empty values with "-"
    if ([string]::IsNullOrEmpty($valueType)) { $valueType = "-" }
    if ([string]::IsNullOrEmpty($valueData)) { $valueData = "-" }

    # Hold the data
    $dataObject = [PSCustomObject]@{
        RegistryPath = $registryPath
        PropertyName = $propertyName
        ValueType    = $valueType
        Value        = $valueData
    }

    # Export the object to a CSV file
    $dataObject | Export-Csv -Path $outputPath -NoTypeInformation
}
