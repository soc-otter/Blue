<#
.SYNOPSIS
Pulls browsing history from Chrome, Edge, and Firefox for all Windows users from the local machine.

.DESCRIPTION
This script extracts browsing history from Chrome, Edge, and Firefox for all users on a Windows system, sorting raw timestamps and then converting to the local machine's time zone, accounting for daylight savings time. If SQLite3.exe doesn't exist in `$toolsDirectory`, this script will attempt to download it and remove, if downloaded,  when complete.

.NOTES
Requires PowerShell v5+ and admin rights.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Browsing_History_All_Users.ps1

.EXAMPLE
PS> .\Browsing_History_All_Users.ps1

#>

$outputDirectory = 'C:\BlueTeam'
$toolsDirectory = 'C:\BlueTeamTools'
$sqliteExecutablePath = "$toolsDirectory\sqlite3.exe"
$sqliteDownloadUrl = "https://www.sqlite.org/2022/sqlite-tools-win32-x86-3380500.zip"
$historyOutputCsvPath = "$outputDirectory\Browsing_History_Details.csv"

# Create directories
New-Item -ItemType Directory -Force -Path $outputDirectory, $toolsDirectory | Out-Null

# Check and download SQLite if needed
$isSqliteAvailable = $false
$wasSqliteDownloaded = $false
if (-not (Test-Path -Path $sqliteExecutablePath)) {
    try {
        $tempZipFile = "$toolsDirectory\sqlite.zip"
        Invoke-WebRequest -Uri $sqliteDownloadUrl -OutFile $tempZipFile
        Expand-Archive $tempZipFile -DestinationPath "$toolsDirectory\SQLite3" -Force
        Move-Item "$toolsDirectory\SQLite3\sqlite-tools-win32-x86-3380500\sqlite3.exe" $sqliteExecutablePath -Force
        Remove-Item $tempZipFile, "$toolsDirectory\SQLite3" -Recurse -Force
        $isSqliteAvailable = $true
        $wasSqliteDownloaded = $true
    } catch {
        Write-Host "SQLite download failed. Quitting."
        exit 1
    }
} else {
    $isSqliteAvailable = $true
}

function Copy-BrowserDatabase($originalDbPath, $userName, $browserName) {
    $tempDbPath = "$Env:TEMP\${userName}_${browserName}_History.sqlite"
    if (Test-Path -Path $originalDbPath) {
        Copy-Item -Path $originalDbPath -Destination $tempDbPath -Force
        return $tempDbPath
    }
    return $null
}

function Get-BrowserHistory($userName, $browserName, $browserDbPath) {
    $browserData = @()
    $tempDbPath = Copy-BrowserDatabase -originalDbPath $browserDbPath -userName $userName -browserName $browserName
    if ($tempDbPath) {
        try {
            $sqlQuery = "SELECT url, last_visit_time FROM urls"
            $queryResults = & $sqliteExecutablePath $tempDbPath $sqlQuery
            $browserData = $queryResults | Where-Object { $_ -match '\S' } | ForEach-Object {
                $url, $timestamp = $_ -split '\|'
                [PSCustomObject]@{
                    User = $userName
                    Browser = $browserName
                    URL = $url
                    LastAccessed = $timestamp
                }
            }
        } catch {
            Write-Host "Error accessing $browserName history for $userName`: $($_.Exception.Message)"
        }
        Remove-Item -Path $tempDbPath -ErrorAction SilentlyContinue
    }
    return $browserData
}

function Get-FirefoxHistory($userName) {
    $firefoxProfilePath = "C:\Users\$userName\AppData\Roaming\Mozilla\Firefox\Profiles"
    $firefoxData = @()
    Get-ChildItem -Path $firefoxProfilePath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $firefoxDbPath = Join-Path $_.FullName "places.sqlite"
        if (Test-Path $firefoxDbPath) {
            $sqlQuery = "SELECT url, last_visit_date FROM moz_places WHERE last_visit_date IS NOT NULL"
            $queryResults = & $sqliteExecutablePath $firefoxDbPath $sqlQuery
            $firefoxData += $queryResults | Where-Object { $_ -match '\S' } | ForEach-Object {
                $url, $timestamp = $_ -split '\|'
                [PSCustomObject]@{
                    User = $userName
                    Browser = 'Firefox'
                    URL = $url
                    LastAccessed = $timestamp
                }
            }
        }
    }
    return $firefoxData
}

# Main execution
$allBrowserHistory = @()
$userProfiles = Get-ChildItem "$Env:systemdrive\Users" -Directory | Select-Object -ExpandProperty Name
$totalUserCount = $userProfiles.Count
$progressIncrement = 90 / $totalUserCount

foreach ($currentUser in $userProfiles) {
    $userIndex = $userProfiles.IndexOf($currentUser) + 1
    $progressBaseValue = 5 + (($userIndex - 1) * $progressIncrement)

    if ($isSqliteAvailable) {
        Write-Progress -Activity "Extracting browsing histories" -Status "Processing Chrome (User: $currentUser)" -PercentComplete $progressBaseValue
        $allBrowserHistory += Get-BrowserHistory -userName $currentUser -browserName 'Chrome' -browserDbPath "$Env:systemdrive\Users\$currentUser\AppData\Local\Google\Chrome\User Data\Default\History"

        Write-Progress -Activity "Extracting browsing histories" -Status "Processing Edge (User: $currentUser)" -PercentComplete ($progressBaseValue + ($progressIncrement / 2))
        $allBrowserHistory += Get-BrowserHistory -userName $currentUser -browserName 'Edge' -browserDbPath "$Env:systemdrive\Users\$currentUser\AppData\Local\Microsoft\Edge\User Data\Default\History"

        Write-Progress -Activity "Extracting browsing histories" -Status "Processing Firefox (User: $currentUser)" -PercentComplete ($progressBaseValue + $progressIncrement)
        $allBrowserHistory += Get-FirefoxHistory -userName $currentUser
    }
}

Write-Progress -Activity "Extracting browsing histories" -Status "Sorting and Converting Timestamps" -PercentComplete 95

$localTimeZone = [System.TimeZoneInfo]::Local

$sortedBrowserHistory = $allBrowserHistory | Sort-Object {
    if ($_.Browser -eq 'Firefox') {
        # Firefox timestamps are in microseconds since Unix epoch (1970-01-01)
        [Int64]::Parse($_.LastAccessed) / 1000  # Convert to milliseconds
    } elseif ($_.Browser -in 'Chrome','Edge') {
        # Chrome/Edge timestamps are in microseconds since 1601-01-01
        # Convert to milliseconds since Unix epoch for consistent sorting
        ([Int64]::Parse($_.LastAccessed) / 1000) - 11644473600000
    }
} -Descending

$convertedBrowserHistory = $sortedBrowserHistory | ForEach-Object {
    $convertedTimestamp = if ($_.LastAccessed) {
        if ($_.Browser -eq 'Firefox') {
            # Convert Firefox timestamp (microseconds since Unix epoch) to DateTime
            $utcTimestamp = [DateTimeOffset]::FromUnixTimeMilliseconds([Int64]::Parse($_.LastAccessed) / 1000)
            $localTimestamp = [TimeZoneInfo]::ConvertTimeFromUtc($utcTimestamp.UtcDateTime, $localTimeZone)
            if ($localTimeZone.IsDaylightSavingTime($localTimestamp)) {
                $localTimestamp.AddHours(-1)  # Adjust for DST
            } else {
                $localTimestamp
            }
        } elseif ($_.Browser -in 'Chrome','Edge') {
            # Convert Chrome/Edge timestamp (microseconds since 1601-01-01) to DateTime
            $unixEpochStart = [DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
            $microsecondsSinceUnixEpoch = ([Int64]::Parse($_.LastAccessed) / 1000) - 11644473600000
            $utcTimestamp = $unixEpochStart.AddMilliseconds($microsecondsSinceUnixEpoch)
            $localTimestamp = [TimeZoneInfo]::ConvertTimeFromUtc($utcTimestamp, $localTimeZone)
            if ($localTimeZone.IsDaylightSavingTime($localTimestamp)) {
                $localTimestamp.AddHours(-1)  # Adjust for DST
            } else {
                $localTimestamp
            }
        }
    } else {
        $null
    }

    [PSCustomObject]@{
        User = $_.User
        Browser = $_.Browser
        URL = $_.URL
        LocalTime = if ($convertedTimestamp) { $convertedTimestamp.ToString('g') } else { '-' }
        RawTimestamp = $_.LastAccessed
    }
}

$convertedBrowserHistory | Export-Csv -Path $historyOutputCsvPath -NoTypeInformation -Encoding UTF8

$currentSystemTime = Get-Date
$currentUtcTime = $currentSystemTime.ToUniversalTime()
$systemTimeZoneId = $localTimeZone.Id

# Cleanup
if ($wasSqliteDownloaded) {
    Remove-Item -Path $sqliteExecutablePath -ErrorAction SilentlyContinue
}

Write-Progress -Activity "Extracting browsing histories" -Completed
