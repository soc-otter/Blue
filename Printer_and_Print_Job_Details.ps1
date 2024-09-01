<#
.SYNOPSIS
Retrieves and exports information about printers and active print jobs on Windows systems.

.DESCRIPTION
This script collects details of all printers and active print jobs on a Windows system using Windows Management Instrumentation (WMI). It exports the data to CSV files, one for print jobs data and another for active printer data. This method can be used by an active attacker to enumerate domain usernames and servers subtly.

.NOTES
Requires PowerShell v5+ and administrative privileges.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Printer_and_Print_Job_Details.ps1

.EXAMPLE
PS> .\Printer_and_Print_Job_Details.ps1
#>

# Define the output directory
$outputDirectory = 'C:\BlueTeam'

# Ensure output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Function to convert array properties to strings
function Convert-ArrayPropertyToString {
    param ([Object]$Property)
    if ($null -ne $Property -and $Property -is [Array]) {
        return ($Property -join ',')
    }
    return $Property
}

# Function to replace blank, empty, or null values with a hyphen (-)
function Replace-NullOrEmpty {
    param ([Object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace($Value)) {
        return '-'
    }
    return $Value
}

# Function to format byte size into a human-readable format
function Get-FormattedByteSize {
    param ([int64]$ByteSize)
    $SizeUnits = @("Bytes", "KB", "MB", "GB", "TB", "PB")
    $UnitIndex = 0
    while ($ByteSize -ge 1KB -and $UnitIndex -lt $SizeUnits.Length - 1) {
        $ByteSize = [math]::Round($ByteSize / 1KB, 2)
        $UnitIndex++
    }
    return "{0} {1}" -f $ByteSize, $SizeUnits[$UnitIndex]
}

# Initialize the progress
Write-Progress -Activity "Retrieving Printer Information" -Status "Starting..." -PercentComplete 0

# Retrieve and process printer information
$printers = Get-WmiObject -Class Win32_Printer | ForEach-Object {
    $printer = $_ | Select-Object Name, DeviceID, Default, Priority, Direct, Location, Local, Network, PortName, ServerName, DriverName, PrinterState, DetectedErrorState, ErrorInformation, Published, Queued, Shared, ShareName, SpoolEnabled, WorkOffline
    $printer.PSObject.Properties | ForEach-Object {
        $printer.$($_.Name) = Replace-NullOrEmpty (Convert-ArrayPropertyToString $printer.$($_.Name))
    }
    return $printer
}

# Export printer information to CSV if there are any results
if ($printers.Count -gt 0) {
    $printerCsvPath = Join-Path -Path $outputDirectory -ChildPath "Printer_Details.csv"
    $printers | Export-Csv -Path $printerCsvPath -NoTypeInformation
    Write-Progress -Activity "Retrieving Printer Information" -Status "Completed" -PercentComplete 50
} else {
    Write-Progress -Activity "Retrieving Printer Information" -Status "No printers found" -PercentComplete 50 -Completed
}

# Initialize the progress for print job information
Write-Progress -Activity "Retrieving Print Job Information" -Status "Starting..." -PercentComplete 50

# Retrieve and process print job information
$printJobs = Get-WmiObject -Class Win32_PrintJob | ForEach-Object {
    $printJob = $_ | Select-Object Name, Document, Size, @{Name='SizeReadable';Expression={Get-FormattedByteSize $_.Size}}, TotalPages, JobStatus, Owner, Priority, TimeSubmitted, StartTime, ElapsedTime, UntilTime, HostPrintQueue
    $printJob.PSObject.Properties | ForEach-Object {
        $printJob.$($_.Name) = Replace-NullOrEmpty (Convert-ArrayPropertyToString $printJob.$($_.Name))
    }
    return $printJob
}

# Export print job information to CSV if there are any results
if ($printJobs.Count -gt 0) {
    $printJobCsvPath = Join-Path -Path $outputDirectory -ChildPath "Printer_Job_Details.csv"
    $printJobs | Export-Csv -Path $printJobCsvPath -NoTypeInformation
    Write-Progress -Activity "Retrieving Print Job Information" -Status "Completed" -PercentComplete 100 -Completed
} else {
    Write-Progress -Activity "Retrieving Print Job Information" -Status "No active print jobs found" -PercentComplete 100 -Completed
}
