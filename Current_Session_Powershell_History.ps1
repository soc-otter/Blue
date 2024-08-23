<#
.SYNOPSIS
Exports the command history from the current PowerShell session to a CSV.

.DESCRIPTION
This script captures the command history from the active PowerShell session, including command IDs and command lines executed by the current user. By capturing the command history, security analysts can review user activities in PowerShell to detect anomalies or unauthorized actions.

.NOTES
Requires PowerShell v5+ and administrative privileges.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Current_Session_Powershell_History.ps1

.EXAMPLE
PS> .\Current_Session_Powershell_History.ps1
#>

# Set the output directory
$outputDirectory = 'C:\BlueTeam'

# Get the current user's username
$username = [Environment]::UserName

# Get the current process ID and process name
$processId = $PID
$processName = (Get-Process -Id $processId).ProcessName

# Define the output file path with process ID and name
$outputFile = Join-Path $outputDirectory "${username}_${processName}_${processId}_PowerShell_Session_History.csv"

# Ensure the output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Retrieve the current PowerShell session history
$psHistory = Get-History | Select-Object -Property Id, CommandLine

# Update progress to indicate export is starting
Write-Progress -Activity "Exporting PowerShell History" -Status "Starting export..." -PercentComplete 0

# Export the PowerShell history to a CSV
$psHistory | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8

# Update progress to indicate export is complete
Write-Progress -Activity "Exporting PowerShell History" -Status "Export complete" -PercentComplete 100 -Completed
