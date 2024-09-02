<#

.SYNOPSIS
Extracts cookie data from Chrome, Edge, and Firefox for all Windows users.

[!] THIS SCRIPT CLOSES ANY OPEN BROWSERS [!]

.DESCRIPTION
This script retrieves cookie information such as name, value, domain, path, expiration date, and metadata from Chrome, Edge, and Firefox browsers for all users on a Windows system. It checks if SQLite3.exe is available in the specified tools directory and downloads it if necessary.

.NOTES
Requires PowerShell v5+ and admin rights.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Browsing_Cookies_All_Users.ps1

.EXAMPLE
PS> .\Browsing_Cookies_All_Users.ps1

#>

$outputDirectory = 'C:\BlueTeam'
$toolsDirectory = 'C:\BlueTeamTools'
$sqliteExecutablePath = "$toolsDirectory\sqlite3.exe"
$sqliteDownloadUrl = "https://www.sqlite.org/2022/sqlite-tools-win32-x86-3380500.zip"
$cookiesOutputCsvPath = "$outputDirectory\Browsing_Cookies_All_Users.csv"

# Create directories
Write-Progress -Activity "Setup" -Status "Creating necessary directories..." -PercentComplete 0
New-Item -ItemType Directory -Force -Path $outputDirectory, $toolsDirectory | Out-Null

# Check and download SQLite if needed
$isSqliteAvailable = Test-Path -Path $sqliteExecutablePath
$wasSqliteDownloaded = $false
if (-not $isSqliteAvailable) {
    Write-Progress -Activity "Setup" -Status "Downloading SQLite..." -PercentComplete 5
    try {
        $tempZipFile = "$toolsDirectory\sqlite.zip"
        Invoke-WebRequest -Uri $sqliteDownloadUrl -OutFile $tempZipFile

        # Extract the ZIP and search for sqlite3.exe
        Expand-Archive -Path $tempZipFile -DestinationPath "$toolsDirectory\SQLite3" -Force
        $extractedExecutable = Get-ChildItem -Path "$toolsDirectory\SQLite3" -Recurse -Filter "sqlite3.exe" | Select-Object -First 1

        if ($extractedExecutable) {
            Move-Item -Path $extractedExecutable.FullName -Destination $sqliteExecutablePath -Force
            Write-Progress -Activity "Setup" -Status "SQLite downloaded and moved successfully." -PercentComplete 10
            Remove-Item $tempZipFile, "$toolsDirectory\SQLite3" -Recurse -Force
            $isSqliteAvailable = $true
            $wasSqliteDownloaded = $true
        } else {
            Write-Host "Failed to find sqlite3.exe after extraction. Exiting." -ForegroundColor Red
            exit 1
        }
    } catch {
        Write-Host "Failed to download SQLite. Exiting." -ForegroundColor Red
        exit 1
    }
}

function Close-All-Browser-Processes {
    param ($browserName, [ref]$runningBrowsers)
    Write-Progress -Activity "Closing Browsers" -Status "Closing $browserName processes..." -PercentComplete 10
    $browserProcesses = Get-Process -Name $browserName -ErrorAction SilentlyContinue
    if ($browserProcesses) {
        $runningBrowsers.Value[$browserName] = $true  # Mark this browser as running
        foreach ($process in $browserProcesses) {
            try {
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Host "Failed to close $browserName (PID: $($process.Id))." -ForegroundColor Red
            }
        }
        Start-Sleep -Seconds 2
    } else {
        $runningBrowsers.Value[$browserName] = $false
    }
}

function Ensure-Browser-Closed {
    param ($browserName)
    $maxRetries = 5
    for ($i = 0; $i -lt $maxRetries; $i++) {
        Write-Progress -Activity "Closing Browsers" -Status "Ensuring $browserName is closed (Attempt $($i+1))..." -PercentComplete 15
        $browserProcesses = Get-Process -Name $browserName -ErrorAction SilentlyContinue
        if (-not $browserProcesses) {
            return $true
        } else {
            Start-Sleep -Seconds 2
        }
    }
    Write-Host "$browserName could not be closed completely." -ForegroundColor Red
    return $false
}

function Reopen-Browsers {
    param ($runningBrowsers)
    Write-Progress -Activity "Reopening Browsers" -Status "Reopening browsers..." -PercentComplete 90
    foreach ($browser in $runningBrowsers.Keys) {
        if ($runningBrowsers[$browser]) {  # Only reopen if it was closed
            try {
                if ($browser -eq 'msedge') {
                    Start-Process "msedge.exe" -ErrorAction SilentlyContinue
                } elseif ($browser -eq 'chrome') {
                    Start-Process "chrome.exe" -ErrorAction SilentlyContinue
                } elseif ($browser -eq 'firefox') {
                    Start-Process "firefox.exe" -ErrorAction SilentlyContinue
                }
                Write-Progress -Activity "Reopening Browsers" -Status "$browser reopened successfully." -PercentComplete 95
            } catch {
                Write-Host "Failed to reopen $browser`: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
}

function Copy-Database {
    param ($dbPath, $userName, $browserName)
    $tempDbPath = "$Env:TEMP\${userName}_${browserName}_Cookies.sqlite"
    $maxRetries = 3
    $retryDelay = 2

    for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
        try {
            if (Test-Path -Path $dbPath) {
                Write-Progress -Activity "Copying Database" -Status "Copying $browserName database for $userName (Attempt $attempt)..." -PercentComplete 20
                Copy-Item -Path $dbPath -Destination $tempDbPath -Force
                return $tempDbPath
            } else {
                return $null
            }
        } catch {
            Start-Sleep -Seconds $retryDelay
        }
    }
    Write-Host "Failed to copy database for $userName ($browserName) after $maxRetries attempts." -ForegroundColor Red
    return $null
}

function Convert-Timestamp {
    param (
        [Parameter(Mandatory=$true)]
        [string]$timestamp,
        
        [Parameter(Mandatory=$true)]
        [string]$browser
    )

    if ([string]::IsNullOrEmpty($timestamp) -or $timestamp -eq "0") {
        return '-'
    }

    try {
        $longTimestamp = [Int64]::Parse($timestamp)

        switch ($browser) {
            'Firefox' {

                # Firefox can use seconds or microseconds since Unix epoch
                if ($longTimestamp -lt 30000000000) {  # Likely in seconds
                    return [DateTimeOffset]::FromUnixTimeSeconds($longTimestamp).UtcDateTime
                } else {  # Likely in microseconds
                    return [DateTimeOffset]::FromUnixTimeMilliseconds($longTimestamp / 1000).UtcDateTime
                }
            }
            { $_ -in 'Chrome', 'Edge' } {

                # Chrome and Edge use microseconds since Windows epoch (1601-01-01)
                $windowsEpoch = [DateTime]::new(1601, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
                return $windowsEpoch.AddTicks($longTimestamp * 10)  # Convert microseconds to ticks
            }
            default {
                throw "Unsupported browser: $browser"
            }
        }
    }
    catch {
        Write-Host "Error converting timestamp '$timestamp' for $browser browser: $($_.Exception.Message)" -ForegroundColor Red
        return '-'
    }
}

function Get-Cookies {
    param ($userName, $browserName, $dbPath)
    $cookieData = @()
    $tempDbPath = Copy-Database -dbPath $dbPath -userName $userName -browserName $browserName
    if ($tempDbPath) {
        try {
            $sqlQuery = "SELECT name, value, host_key, path, expires_utc, is_secure, is_httponly, creation_utc, last_access_utc FROM cookies"
            $queryResults = & $sqliteExecutablePath $tempDbPath $sqlQuery 2>$null
            if ($queryResults) {
                $cookieData = $queryResults | Where-Object { $_ -match '\S' } | ForEach-Object {
                    $name, $value, $domain, $path, $expiresUtc, $isSecure, $isHttpOnly, $creationUtc, $lastAccessUtc = $_ -split '\|'
                    
                    # Ensure timestamps are valid before conversion
                    $expiresUtcConverted = if ([Int64]::TryParse($expiresUtc, [ref]$null)) { Convert-Timestamp -timestamp $expiresUtc -browser $browserName } else { '-' }
                    $creationUtcConverted = if ([Int64]::TryParse($creationUtc, [ref]$null)) { Convert-Timestamp -timestamp $creationUtc -browser $browserName } else { '-' }
                    $lastAccessUtcConverted = if ([Int64]::TryParse($lastAccessUtc, [ref]$null)) { Convert-Timestamp -timestamp $lastAccessUtc -browser $browserName } else { '-' }

                    [PSCustomObject]@{
                        User = $userName
                        Browser = $browserName
                        Name = if ($name) { $name } else { '-' }
                        Value = if ($value) { $value } else { '-' }
                        Domain = if ($domain) { $domain } else { '-' }
                        Path = if ($path) { $path } else { '-' }
                        ExpiresUTC = $expiresUtcConverted
                        IsSecure = $isSecure -eq '1'
                        IsHttpOnly = $isHttpOnly -eq '1'
                        CreationUTC = $creationUtcConverted
                        LastAccessUTC = $lastAccessUtcConverted
                    }
                }
            }
        } catch {
            Write-Host "Error accessing $browserName cookies for $userName`: $($_.Exception.Message)" -ForegroundColor Red
        }
        Remove-Item -Path $tempDbPath -ErrorAction SilentlyContinue
    }
    return $cookieData
}

function Get-FirefoxCookies {
    param ($userName)
    $firefoxProfilePath = "C:\Users\$userName\AppData\Roaming\Mozilla\Firefox\Profiles"
    $cookieData = @()
    Get-ChildItem -Path $firefoxProfilePath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $dbPath = Join-Path $_.FullName "cookies.sqlite"
        $tempDbPath = Copy-Database -dbPath $dbPath -userName $userName -browserName 'Firefox'
        if ($tempDbPath) {
            try {
                $sqlQuery = "SELECT name, value, host, path, expiry, isSecure, isHttpOnly, creationTime, lastAccessed FROM moz_cookies"
                $queryResults = & $sqliteExecutablePath $tempDbPath $sqlQuery 2>$null
                if ($queryResults) {
                    $cookieData += $queryResults | Where-Object { $_ -match '\S' } | ForEach-Object {
                        $name, $value, $domain, $path, $expiry, $isSecure, $isHttpOnly, $creationTime, $lastAccessed = $_ -split '\|'
                        [PSCustomObject]@{
                            User = $userName
                            Browser = 'Firefox'
                            Name = if ($name) { $name } else { '-' }
                            Value = if ($value) { $value } else { '-' }
                            Domain = if ($domain) { $domain } else { '-' }
                            Path = if ($path) { $path } else { '-' }
                            ExpiresUTC = Convert-Timestamp -timestamp $expiry -browser 'Firefox'
                            IsSecure = $isSecure -eq '1'
                            IsHttpOnly = $isHttpOnly -eq '1'
                            CreationUTC = Convert-Timestamp -timestamp $creationTime -browser 'Firefox'
                            LastAccessUTC = Convert-Timestamp -timestamp $lastAccessed -browser 'Firefox'
                        }
                    }
                }
            } catch {
                Write-Host "Error accessing Firefox cookies for $userName`: $($_.Exception.Message)" -ForegroundColor Red
            }
            Remove-Item -Path $tempDbPath -ErrorAction SilentlyContinue
        }
    }
    return $cookieData
}

# Main execution
$runningBrowsers = @{}
$allBrowserCookies = @()
$userProfiles = Get-ChildItem "$Env:systemdrive\Users" -Directory | Select-Object -ExpandProperty Name
$totalUserCount = $userProfiles.Count
$progressIncrement = 60 / $totalUserCount

# Close all browser processes before processing (most browsers lock cookie files when open)
Close-All-Browser-Processes -browserName 'msedge' -runningBrowsers ([ref]$runningBrowsers)
Close-All-Browser-Processes -browserName 'chrome' -runningBrowsers ([ref]$runningBrowsers)
Close-All-Browser-Processes -browserName 'firefox' -runningBrowsers ([ref]$runningBrowsers)
Ensure-Browser-Closed -browserName 'msedge' | Out-Null
Ensure-Browser-Closed -browserName 'chrome' | Out-Null
Ensure-Browser-Closed -browserName 'firefox' | Out-Null

foreach ($currentUser in $userProfiles) {
    $userIndex = $userProfiles.IndexOf($currentUser) + 1
    $progressBaseValue = 35 + (($userIndex - 1) * $progressIncrement)

    if ($isSqliteAvailable) {
        Write-Progress -Activity "Extracting cookies" -Status "Processing Chrome (User: $currentUser)" -PercentComplete $progressBaseValue
        $allBrowserCookies += Get-Cookies -userName $currentUser -browserName 'Chrome' -dbPath "$Env:systemdrive\Users\$currentUser\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies"

        Write-Progress -Activity "Extracting cookies" -Status "Processing Edge (User: $currentUser)" -PercentComplete ($progressBaseValue + ($progressIncrement / 3))
        $allBrowserCookies += Get-Cookies -userName $currentUser -browserName 'Edge' -dbPath "$Env:systemdrive\Users\$currentUser\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies"

        Write-Progress -Activity "Extracting cookies" -Status "Processing Firefox (User: $currentUser)" -PercentComplete ($progressBaseValue + (2 * $progressIncrement / 3))
        $allBrowserCookies += Get-FirefoxCookies -userName $currentUser
    }
}

# Sort by CreationUTC in descending order
$sortedBrowserCookies = $allBrowserCookies | Sort-Object { $_.CreationUTC } -Descending

Write-Progress -Activity "Finalizing" -Status "Exporting data to CSV..." -PercentComplete 95
$sortedBrowserCookies | Export-Csv -Path $cookiesOutputCsvPath -NoTypeInformation -Encoding UTF8

# Reopen browsers if they were closed
Reopen-Browsers -runningBrowsers $runningBrowsers

if ($wasSqliteDownloaded) {
    Remove-Item -Path $sqliteExecutablePath -ErrorAction SilentlyContinue
}

Write-Progress -Activity "Complete" -Status "Cookie extraction completed." -Completed
