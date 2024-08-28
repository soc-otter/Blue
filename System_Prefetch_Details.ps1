<#
.SYNOPSIS
Extracts Windows Prefetch file details into a CSV.

.DESCRIPTION
This script retrieves Prefetch files from the Windows Prefetch directory by attempting to use Eric Zimmerman's PECmd tool for detailed analysis. If the tool is not available on the system, it will try to download it. If it fails to download, it falls back to a basic method of extracting key properties from the Prefetch files.

.NOTES
Requires PowerShell v5+ and administrative privileges to access the Prefetch directory.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/System_Prefetch_Details.ps1

.EXAMPLE
PS> .\System_Prefetch_Details.ps1
#>

# Set the output directory
$outputDirectory = 'C:\BlueTeam'
$outputCsv = Join-Path -Path $outputDirectory -ChildPath "System_Prefetch_Details.csv"

# PECmd download details
$PECmdUrl = 'https://download.mikestammer.com/PECmd.zip'
$PECmdDestination = Join-Path -Path $outputDirectory -ChildPath 'PECmd'
$PECmdExePath = Join-Path -Path $PECmdDestination -ChildPath 'PECmd.exe'

# Ensure the output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Ensure the PECmd directory exists
if (-not (Test-Path -Path $PECmdDestination)) {
    New-Item -ItemType Directory -Path $PECmdDestination -Force | Out-Null
}

# Function to download and extract PECmd
function Download-PECmd {
    param (
        [string]$downloadUrl,
        [string]$destination
    )
    try {
        # Download PECmd zip
        $zipFilePath = Join-Path -Path $destination -ChildPath 'PECmd.zip'
        Invoke-WebRequest -Uri $downloadUrl -OutFile $zipFilePath -ErrorAction Stop

        # Extract PECmd zip
        Add-Type -AssemblyName 'System.IO.Compression.FileSystem'
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipFilePath, $destination)

        # Remove the zip file
        Remove-Item -Path $zipFilePath -Force

        return $true
    } catch {
        Write-Error "Failed to download or extract PECmd. Error details: $_" -ErrorAction Stop
        return $false
    }
}

# Check if PECmd exists, if not, download it
$useFallback = $false
try {
    if (-not (Test-Path -Path $PECmdExePath)) {
        Write-Progress -Activity "PECmd Download" -Status "PECmd tool not found. Attempting to download..." -PercentComplete 10
        if (-not (Download-PECmd -downloadUrl $PECmdUrl -destination $PECmdDestination)) {
            throw "Failed to download PECmd. Reverting to basic method."
        }
    }
} catch {
    Write-Progress -Activity "PECmd Download" -Status "$_ Reverting to basic method." -PercentComplete 20
    $useFallback = $true
}

# If PECmd exists, use it to process the Prefetch files
if (-not $useFallback -and (Test-Path -Path $PECmdExePath)) {
    Write-Progress -Activity "PECmd Processing" -Status "Using PECmd tool to process Prefetch files..." -PercentComplete 30
    
    # Suppress PECmd output by redirecting stdout and stderr to $null
    $cmdArgs = @("-d", "C:\Windows\Prefetch", "--csv", $outputDirectory, "--csvf", "System_Prefetch_Details.csv")
    $null = & $PECmdExePath @cmdArgs
    
    if ($LASTEXITCODE -ne 0) {
        Write-Progress -Activity "PECmd Processing" -Status "PECmd encountered an error. Reverting to basic method." -PercentComplete 40
        $useFallback = $true

        # Delete any incomplete output file from PECmd
        Remove-Item -Path $outputCsv -Force -ErrorAction SilentlyContinue
    } else {
        Write-Progress -Activity "PECmd Processing" -Status "Prefetch files processed successfully using PECmd." -PercentComplete 100
    }
}

# Fallback to the basic method if PECmd fails or is not available
if ($useFallback) {
    Write-Progress -Activity "Basic Method Processing" -Status "PECmd failed or was unavailable. Using basic method to process Prefetch files..." -PercentComplete 50

    # Get Prefetch files and sort by last write time
    $prefetchFiles = Get-ChildItem -Path C:\Windows\Prefetch -Filter *.pf | Sort-Object -Property LastWriteTime -Descending

    # Exit if no Prefetch files are found
    if ($prefetchFiles.Count -eq 0) {
        Write-Progress -Activity "Basic Method Processing" -Status "No Prefetch files found. Exiting." -PercentComplete 100
        return
    }

    $progressPerFile = 50 / $prefetchFiles.Count
    $fileIndex = 0

    # Process each Prefetch file
    $results = foreach ($file in $prefetchFiles) {
        $fileIndex++
        $currentProgress = [math]::Min(60 + ($fileIndex * $progressPerFile), 100)
        Write-Progress -Activity "Processing Prefetch Files" -Status "Processing $($file.Name)" -PercentComplete $currentProgress

        # Add properties to file object
        $file | Add-Member -MemberType NoteProperty -Name 'Stripped' -Value ($file.Name -replace '-[A-Za-z0-9]{8}\.pf$', '') -Force
        $file | Add-Member -MemberType NoteProperty -Name 'PrefetchFileSizeMB' -Value ("{0:N2} MB" -f ($file.Length / 1MB)) -Force

        $file
    }

    Write-Progress -Activity "Processing Prefetch Files" -Status "Finalizing and exporting data" -PercentComplete 90

    # Export results to CSV (without the empty columns)
    $results | Select-Object Stripped, Name, PrefetchFileSizeMB, LastAccessTime, LastWriteTime, CreationTime, Mode |
        Export-Csv -Path $outputCsv -NoTypeInformation -Force

    Write-Progress -Activity "Processing Prefetch Files" -Status "Basic method completed. CSV file saved." -PercentComplete 100
}

# Clean up the PECmd download if it was used
if (Test-Path -Path $PECmdDestination) {
    Remove-Item -Path $PECmdDestination -Recurse -Force
    Write-Progress -Activity "Cleanup" -Status "Cleaned up PECmd tool files." -PercentComplete 100
}
