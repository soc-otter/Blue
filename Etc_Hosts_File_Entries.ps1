<#
.SYNOPSIS
Extracts and exports the contents of the system's hosts file to a CSV.

.DESCRIPTION
This script reads and exports the entries from the system's hosts file. The hosts file can be modified by malware or used for unauthorized network redirection. The script filters out comments and blank lines to focus soley on only active entries.

.NOTES
Requires PowerShell v5+ and appropriate read permissions for the hosts file.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Etc_Hosts_File_Entries.ps1

.EXAMPLE
PS> .\Etc_Hosts_File_Entries.ps1
#>

# Define the path to the hosts file
$hostsFilePath = 'C:\Windows\System32\drivers\etc\hosts'

# Define the output directory
$outputDirectory = 'C:\BlueTeam'

# Ensure the output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Define the output CSV file path
$outputCsvFilePath = Join-Path $outputDirectory "Etc_Hosts_File_Entries.csv"

# Initialize an array to hold the hosts file entries
$hostsFileEntries = @()

# Update progress
Write-Progress -Activity "Processing Hosts File" -Status "Reading hosts file..." -PercentComplete 30

# Read the contents of the hosts file, ignoring comments and empty lines
Get-Content -Path $hostsFilePath | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() -ne '' } | ForEach-Object {

    # Split each line by whitespace and create an object with IP and Hostname
    $parts = $_ -split '\s+'
    $ip = $parts[0]
    $hostname = $parts[1]

    $hostsFileEntries += [PSCustomObject]@{
        IPAddress = $ip
        Hostname  = $hostname
    }
}

# Update progress
Write-Progress -Activity "Processing Hosts File" -Status "Analyzing entries..." -PercentComplete 60

# Export the hosts file entries to a CSV only if there are results
if ($hostsFileEntries.Count -gt 0) {
    $hostsFileEntries | Export-Csv -Path $outputCsvFilePath -NoTypeInformation
    Write-Progress -Activity "Processing Hosts File" -Status "Hosts file entries exported to $outputCsvFilePath" -PercentComplete 100 -Completed
} else {
    Write-Progress -Activity "Processing Hosts File" -Status "No hosts file entries found." -PercentComplete 100 -Completed
}
