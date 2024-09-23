<#
.SYNOPSIS
Retrieves the mapping between drive letters and their respective device paths.

.DESCRIPTION
This script queries the system for volume mappings, associating drive letters with their corresponding device paths. It also enriches the data with additional drive information like size and free space. Results are exported to a CSV.

.NOTES
Requires PowerShell v5+.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Volume_Path_Mappings.ps1

.EXAMPLE
PS> .\Volume_Path_Mappings.ps1
#>

# Define the output directory and file for the CSV
$outputDirectory = "C:\BlueTeam"
$outputFile = Join-Path -Path $outputDirectory -ChildPath "Volume_Path_Mappings.csv"

# Ensure the output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Function to format byte size to the closest metric
function Get-FormattedByteSize {
    param ([double]$ByteSize)
    $SizeUnits = @("bytes", "KB", "MB", "GB", "TB", "PB")
    $UnitIndex = 0
    $Size = [math]::Round($ByteSize, 2)
    while ($Size -ge 1KB -and $UnitIndex -lt $SizeUnits.Count - 1) {
        $Size /= 1KB
        $UnitIndex++
    }
    return "{0:N2} {1}" -f $Size, $SizeUnits[$UnitIndex]
}

# Define the P/Invoke method for QueryDosDevice
$kernel32 = Add-Type -MemberDefinition @"
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern uint QueryDosDevice(string lpDeviceName, System.Text.StringBuilder lpTargetPath, uint ucchMax);
"@ -Name "Kernel32" -Namespace "Win32" -PassThru

# Function to get the device path
function Get-DevicePath {
    param ([string]$DriveLetter)
    $sb = New-Object System.Text.StringBuilder(260)
    $null = $kernel32::QueryDosDevice($DriveLetter, $sb, 260)
    return $sb.ToString()
}

# Query volume information and device paths
$volumeMappings = Get-WmiObject -Query "SELECT DriveLetter, Capacity, FreeSpace, Label, FileSystem FROM Win32_Volume WHERE DriveLetter IS NOT NULL" | 
    ForEach-Object {
        [PSCustomObject]@{
            DriveLetter = $_.DriveLetter
            DevicePath  = Get-DevicePath $_.DriveLetter
            Size        = Get-FormattedByteSize $_.Capacity
            FreeSpace   = Get-FormattedByteSize $_.FreeSpace
            UsedSpace   = Get-FormattedByteSize ($_.Capacity - $_.FreeSpace)
            VolumeLabel = if ($_.Label) { $_.Label } else { '-' }
            FileSystem  = if ($_.FileSystem) { $_.FileSystem } else { '-' }
        }
    }

# Export the results to a CSV file
if ($volumeMappings) {
    $volumeMappings | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
} else {
    Write-Host "No volume path mappings found."
}
