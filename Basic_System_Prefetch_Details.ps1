<#

.SYNOPSIS
Extracts and organizes basic Windows Prefetch file details into a CSV.

.DESCRIPTION
This script retrieves Prefetch files from the Windows Prefetch directory, which are used to optimize application launch times and contain valuable forensic information. It ensures the specified output directory exists, collects and sorts the Prefetch files by last write time, and extracts key properties such as the stripped name, file size, and timestamps. These details are compiled into a CSV. The CSV includes the stripped name, original file name, Prefetch file size, file mode, last access time, last write time, and creation time.

.NOTES
File Version: 1.2
Requires PowerShell v5+ and administrative privileges to access the Prefetch directory.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Basic_System_Prefetch_Details.ps1

.EXAMPLE
PS> .\Basic_System_Prefetch_Details.ps1

#>

# Set the output directory
$outputDirectory = 'C:\BlueTeam'

# Ensure the output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

Write-Progress -Activity "Processing Prefetch files" -Status "Initializing" -PercentComplete 10

# Get Prefetch files and sort by last write time
$prefetchFiles = Get-ChildItem -Path C:\Windows\Prefetch -Filter *.pf | Sort-Object -Property LastWriteTime -Descending

# Exit if no Prefetch files are found
if ($prefetchFiles.Count -eq 0) {
    Write-Host "No Prefetch files found. Exiting."
    return
}

$progressPerFile = 80 / $prefetchFiles.Count

# Process each Prefetch file
$results = foreach ($file in $prefetchFiles) {
    $fileIndex++
    $currentProgress = [math]::Min(10 + ($fileIndex * $progressPerFile), 100)
    $strippedName = ([regex]::Match($file.Name, '^(.+?)-[A-Za-z0-9]{8}\.pf$')).Groups[1].Value
    Write-Progress -Activity "Processing Prefetch files" -Status "Processing $($file.Name)" -PercentComplete $currentProgress

    # Add properties to file object
    $file | Add-Member -MemberType NoteProperty -Name 'Stripped' -Value $strippedName -Force
    $file | Add-Member -MemberType NoteProperty -Name 'PrefetchFileSizeMB' -Value ("{0:N2} MB" -f ($file.Length / 1MB)) -Force

    $file
}

Write-Progress -Activity "Processing Prefetch files" -Status "Finalizing and exporting data" -PercentComplete 90

# Export results to CSV
$results | Select-Object Stripped, Name, PrefetchFileSizeMB, LastAccessTime, LastWriteTime, CreationTime, Mode | Export-Csv -Path "$outputDirectory\System_Prefetch_Details.csv" -NoTypeInformation

Write-Progress -Activity "Processing Prefetch files" -Status "Completed" -PercentComplete 100
