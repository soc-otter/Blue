<#
.SYNOPSIS
Finds and collects PowerShell ISE auto-save files.

.DESCRIPTION
This searches for PowerShell ISE auto-save files created during idle periods or after crashes. It collects metadata and file contents, including the size of the file, the number of lines, and the number of characters in the file content. The results are exported to a single CSV file with a column indicating the user that owns each file and are sorted by newest files first.

.NOTES
Requires PowerShell v5+ and admin permissions to access user directories.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/PowerShell_ISE_AutoSaved_Files.ps1

.EXAMPLE
PS> .\PowerShell_ISE_AutoSaved_Files.ps1
#>

# Define output folder and file
$OutputFolder = "C:\BlueTeam"
$OutputFile = Join-Path $OutputFolder "PowerShell_ISE_AutoSaved_Files.csv"

# Ensure output folder exists
if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory | Out-Null
}

# Function to format byte size
function Get-FormattedFileSize {
    param ([double]$ByteSize)
    $SizeUnits = @("bytes", "KB", "MB", "GB", "TB", "PB")
    $UnitIndex = 0
    $Size = [math]::Round($ByteSize, 2)
    while ($Size -ge 1KB -and $UnitIndex -lt $SizeUnits.Count - 1) {
        $Size /= 1KB
        $UnitIndex++
    }
    "{0:N2} {1}" -f $Size, $SizeUnits[$UnitIndex]
}

# Function to get file owner
function Get-FileOwner {
    param ([string]$FilePath)
    try {
        (Get-Acl $FilePath).Owner
    } catch {
        "-"
    }
}

# Function to get file hash
function Get-FileHashSHA256 {
    param ([string]$FilePath)
    try {
        (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    } catch {
        "-"
    }
}

# Function to get file content
function Get-FileContent {
    param ([string]$FilePath)
    try {
        Get-Content -Path $FilePath -ErrorAction SilentlyContinue -Raw
    } catch {
        "-"
    }
}

# Function to count the number of lines and characters in the file content
function Get-FileContentStats {
    param ([string]$FileContent)
    if ($FileContent -ne "-") {
        $LineCount = ($FileContent -split "`n").Count
        $CharacterCount = $FileContent.Length
    } else {
        $LineCount = 0
        $CharacterCount = 0
    }
    [PSCustomObject]@{
        LineCount       = $LineCount
        CharacterCount  = $CharacterCount
    }
}

# Function to get timestamp fields
function Get-FileTimestamps {
    param ([string]$FilePath)
    try {
        $file = Get-Item -Path $FilePath -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            CreationTime       = $file.CreationTime
            LastWriteTime      = $file.LastWriteTime
            LastAccessTime     = $file.LastAccessTime
        }
    } catch {
        [PSCustomObject]@{
            CreationTime       = "-"
            LastWriteTime      = "-"
            LastAccessTime     = "-"
        }
    }
}

# Gather AutoSave files by user
$AutoSaveFiles = Get-ChildItem -Path "C:\Users\*\AppData\Local\Microsoft_Corporation\powershell_ise.exe*\*\AutoSaveFiles" -Recurse -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer }

# Initialize array to store all results
$Results = @()

# Process files by user
$AutoSaveFiles | Group-Object { ($_.FullName -split '\\')[2] } | ForEach-Object {
    $UserName = $_.Name
    $UserFiles = $_.Group | ForEach-Object {
        $timestamps = Get-FileTimestamps -FilePath $_.FullName
        $FileContent = Get-FileContent -FilePath $_.FullName
        $ContentStats = Get-FileContentStats -FileContent $FileContent
        $Results += [PSCustomObject]@{
            User              = $UserName
            FullName          = $_.FullName
            FileSize          = Get-FormattedFileSize -ByteSize $_.Length
            FileHashSHA256    = Get-FileHashSHA256 -FilePath $_.FullName
            FileOwner         = Get-FileOwner -FilePath $_.FullName
            CreationTime      = $timestamps.CreationTime
            LastWriteTime     = $timestamps.LastWriteTime
            LastAccessTime    = $timestamps.LastAccessTime
            LineCount         = $ContentStats.LineCount
            CharacterCount    = $ContentStats.CharacterCount
            FileContent       = $FileContent
        }
    }
}

# Sort results by CreationTime (newest first)
$SortedResults = $Results | Sort-Object -Property CreationTime -Descending

# Export results, if any
if ($SortedResults.Count -gt 0) {
    $SortedResults | Export-Csv -Path $OutputFile -NoTypeInformation
    Write-Progress -Activity "Auto-save file collection" -Status "Complete" -PercentComplete 100
} else {
    Write-Progress -Activity "Auto-save file collection" -Status "No files found" -PercentComplete 100
}
