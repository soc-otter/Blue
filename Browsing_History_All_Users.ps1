<#

.SYNOPSIS
Pulls browsing history from Chrome, Edge, and Firefox for all Windows users.

.DESCRIPTION
This script extracts browsing history from Chrome, Edge, and Firefox for all users on a Windows system, sorting raw timestamps and then converting to the local machine's time zone, accounting for daylight savings time. If SQLite3.exe doesn't exist in `$ToolsDir`, this script will attempt to download it and remove when complete.

.NOTES
Requires PowerShell v5+ and admin rights.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Browsing_History_All_Users.ps1

.EXAMPLE
PS> .\Browsing_History_All_Users.ps1

#>

$OutputDir = 'C:\BlueTeam'
$ToolsDir = 'C:\BlueTeamTools'
$SQLitePath = "$ToolsDir\sqlite3.exe"
$SQLiteUri = "https://www.sqlite.org/2022/sqlite-tools-win32-x86-3380500.zip"
$HistoryCSV = "$OutputDir\Browsing_History_Details.csv"

# Create directories
New-Item -ItemType Directory -Force -Path $OutputDir, $ToolsDir | Out-Null

# Check and download SQLite if needed
$SQLiteAvailable = $false
$SQLiteDownloaded = $false
if (-not (Test-Path -Path $SQLitePath)) {
    try {
        $TempZip = "$ToolsDir\sqlite.zip"
        Invoke-WebRequest -Uri $SQLiteUri -OutFile $TempZip
        Expand-Archive $TempZip -DestinationPath "$ToolsDir\SQLite3" -Force
        Move-Item "$ToolsDir\SQLite3\sqlite-tools-win32-x86-3380500\sqlite3.exe" $SQLitePath -Force
        Remove-Item $TempZip, "$ToolsDir\SQLite3" -Recurse -Force
        $SQLiteAvailable = $true
        $SQLiteDownloaded = $true
    } catch {
        Write-Host "SQLite download failed. Quitting."
        exit 1
    }
} else {
    $SQLiteAvailable = $true
}

function Copy-SQLiteDB($Path, $User, $Browser) {
    $CopyPath = "$Env:TEMP\${User}_${Browser}_History.sqlite"
    if (Test-Path -Path $Path) {
        Copy-Item -Path $Path -Destination $CopyPath -Force
        return $CopyPath
    }
    return $null
}

function Get-BrowserHistory($User, $Browser, $DBPath) {
    $Data = @()
    $CopyPath = Copy-SQLiteDB -Path $DBPath -User $User -Browser $Browser
    if ($CopyPath) {
        try {
            $Query = "SELECT url, last_visit_time FROM urls"
            $Items = & $SQLitePath $CopyPath $Query
            $Data = $Items | Where-Object { $_ -match '\S' } | ForEach-Object {
                $Url, $Time = $_ -split '\|'
                [PSCustomObject]@{
                    User = $User
                    Browser = $Browser
                    URL = $Url
                    LastAccessed = $Time
                }
            }
        } catch {
            Write-Host "Error accessing $Browser history for $User`: $($_.Exception.Message)"
        }
        Remove-Item -Path $CopyPath -ErrorAction SilentlyContinue
    }
    return $Data
}

function Get-FirefoxHistory($User) {
    $ProfilePath = "C:\Users\$User\AppData\Roaming\Mozilla\Firefox\Profiles"
    $Data = @()
    Get-ChildItem -Path $ProfilePath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $DBPath = Join-Path $_.FullName "places.sqlite"
        if (Test-Path $DBPath) {
            $Query = "SELECT url, last_visit_date FROM moz_places WHERE last_visit_date IS NOT NULL"
            $Items = & $SQLitePath $DBPath $Query
            $Data += $Items | Where-Object { $_ -match '\S' } | ForEach-Object {
                $Url, $Time = $_ -split '\|'
                [PSCustomObject]@{
                    User = $User
                    Browser = 'Firefox'
                    URL = $Url
                    LastAccessed = $Time
                }
            }
        }
    }
    return $Data
}

# Main execution
$AllHistory = @()
$Users = Get-ChildItem "$Env:systemdrive\Users" -Directory | Select-Object -ExpandProperty Name
$UserCount = $Users.Count
$ProgressPerUser = 90 / $UserCount

foreach ($User in $Users) {
    $UserIndex = $Users.IndexOf($User) + 1
    $ProgressBase = 5 + (($UserIndex - 1) * $ProgressPerUser)

    if ($SQLiteAvailable) {
        Write-Progress -Activity "Extracting browsing histories" -Status "Processing Chrome (User: $User)" -PercentComplete $ProgressBase
        $AllHistory += Get-BrowserHistory -User $User -Browser 'Chrome' -DBPath "$Env:systemdrive\Users\$User\AppData\Local\Google\Chrome\User Data\Default\History"

        Write-Progress -Activity "Extracting browsing histories" -Status "Processing Edge (User: $User)" -PercentComplete ($ProgressBase + ($ProgressPerUser / 2))
        $AllHistory += Get-BrowserHistory -User $User -Browser 'Edge' -DBPath "$Env:systemdrive\Users\$User\AppData\Local\Microsoft\Edge\User Data\Default\History"

        Write-Progress -Activity "Extracting browsing histories" -Status "Processing Firefox (User: $User)" -PercentComplete ($ProgressBase + $ProgressPerUser)
        $AllHistory += Get-FirefoxHistory -User $User
    }
}

Write-Progress -Activity "Extracting browsing histories" -Status "Sorting and Converting Timestamps" -PercentComplete 95

$LocalTimeZone = [System.TimeZoneInfo]::Local

$SortedHistory = $AllHistory | Sort-Object {
    if ($_.Browser -eq 'Firefox') {
        # Firefox timestamps are in microseconds since Unix epoch (1970-01-01)
        [Int64]::Parse($_.LastAccessed) / 1000  # Convert to milliseconds
    } elseif ($_.Browser -in 'Chrome','Edge') {
        # Chrome/Edge timestamps are in microseconds since 1601-01-01
        # Convert to milliseconds since Unix epoch for consistent sorting
        ([Int64]::Parse($_.LastAccessed) / 1000) - 11644473600000
    }
} -Descending

$ConvertedHistory = $SortedHistory | ForEach-Object {
    $ConvertedTime = if ($_.LastAccessed) {
        if ($_.Browser -eq 'Firefox') {
            # Convert Firefox timestamp (microseconds since Unix epoch) to DateTime
            $utcTime = [DateTimeOffset]::FromUnixTimeMilliseconds([Int64]::Parse($_.LastAccessed) / 1000)
            $localTime = [TimeZoneInfo]::ConvertTimeFromUtc($utcTime.UtcDateTime, $LocalTimeZone)
            if ($LocalTimeZone.IsDaylightSavingTime($localTime)) {
                $localTime.AddHours(-1)  # Adjust for DST
            } else {
                $localTime
            }
        } elseif ($_.Browser -in 'Chrome','Edge') {
            # Convert Chrome/Edge timestamp (microseconds since 1601-01-01) to DateTime
            $unixEpochStart = [DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
            $microsecondsSinceUnixEpoch = ([Int64]::Parse($_.LastAccessed) / 1000) - 11644473600000
            $utcTime = $unixEpochStart.AddMilliseconds($microsecondsSinceUnixEpoch)
            $localTime = [TimeZoneInfo]::ConvertTimeFromUtc($utcTime, $LocalTimeZone)
            if ($LocalTimeZone.IsDaylightSavingTime($localTime)) {
                $localTime.AddHours(-1)  # Adjust for DST
            } else {
                $localTime
            }
        }
    } else {
        $null
    }

    [PSCustomObject]@{
        User = $_.User
        Browser = $_.Browser
        URL = $_.URL
        LocalTime = if ($ConvertedTime) { $ConvertedTime.ToString('g') } else { '-' }
        RawTimestamp = $_.LastAccessed
    }
}

$ConvertedHistory | Export-Csv -Path $HistoryCSV -NoTypeInformation -Encoding UTF8

$CurrentTime = Get-Date
$CurrentTimeUTC = $CurrentTime.ToUniversalTime()
$TimeZoneId = $LocalTimeZone.Id

# Cleanup
if ($SQLiteDownloaded) {
    Remove-Item -Path $SQLitePath -ErrorAction SilentlyContinue
}

Write-Progress -Activity "Extracting browsing histories" -Completed
