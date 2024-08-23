<#
.SYNOPSIS
Follows URL redirection chains and displays each URL with corresponding status codes, descriptions, and timestamps.

.DESCRIPTION
This script follows URL redirection chains to display each URL in order along with corresponding HTTP status codes, descriptions, timestamps, and the time difference between redirects. It processes only HTTP headers to avoid any interaction with webpage content to reduce the risk of encountering malicious content. The script also defangs URLs to prevent accidental navigation to potentially harmful sites.

This tool is useful for investigating redirection paths.

.NOTES
Requires PowerShell v5+ and internet access.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Follow_URL_Redirections.ps1

.EXAMPLE
PS> .\Follow_URL_Redirections.ps1 -url 'https://www.example.com'
#>

param (
    [string]$url = 'https://httpbin.org/redirect/40' # Default value in case the parameter is not provided
)

$originalUrl = $url
$urlHistory = @()
$lastRedirectUrl = $url
$retryLimit = 3 # Number of retries
$retryDelay = 2 # Initial delay in seconds between retries
$previousTimestamp = Get-Date

# Function to defang URLs
Function Defang-Url {
    param ([string]$url)
    return $url -replace '\.', '[.]'
}

# Function to ensure URL has a scheme (http/https) and handle relative URLs
Function Ensure-UrlScheme {
    param (
        [string]$url,
        [string]$previousUrl
    )
    if (-not($url.StartsWith("https://")) -and -not($url.StartsWith("http://"))) {
        # Handle relative URLs using the hostname from the previous URL
        if ($url.StartsWith("/")) {
            $previousUri = New-Object System.Uri $previousUrl
            return $previousUri.Scheme + "://" + $previousUri.Host + $url
        } else {
            # Assume https if no scheme is present
            return "https://" + $url
        }
    }
    return $url
}

# Function to translate HTTP status codes to a brief description
Function Get-HttpStatusDescription {
    param ([int]$statusCode)
    switch ($statusCode) {
        200 { return "OK" }
        301 { return "Moved Permanently" }
        302 { return "Found" }
        400 { return "Bad Request" }
        401 { return "Unauthorized" }
        403 { return "Forbidden" }
        404 { return "Not Found" }
        500 { return "Server Error" }
        502 { return "Bad Gateway" }
        503 { return "Service Unavailable" }
        default { return "Unknown" }
    }
}

# Function to format time differences
Function Format-TimeDifference {
    param ([TimeSpan]$timeSpan)
    if ($timeSpan.TotalMilliseconds -lt 1000) {
        return "{0} ms" -f [math]::Round($timeSpan.TotalMilliseconds, 2)
    } elseif ($timeSpan.TotalSeconds -lt 60) {
        return "{0} sec" -f [math]::Round($timeSpan.TotalSeconds, 2)
    } elseif ($timeSpan.TotalMinutes -lt 60) {
        return "{0} min" -f [math]::Round($timeSpan.TotalMinutes, 2)
    } else {
        return "{0} hr" -f [math]::Round($timeSpan.TotalHours, 2)
    }
}

# Print headers before the loop
# The format string defines the structure for the output, determining the width and alignment of each column. The widths are based on the maximum possible values expected for each column to ensure that the content fits neatly.
# For example, the timestamp format "yyyy-MM-ddTHH:mm:ss.fffZ" is 24 characters long so the width for the Timestamp column is set to 24.
$formatString = "{0,-7} {1,-24} {2,-15} {3,-7} {4,-17} {5}"
Write-Host ($formatString -f "`nIndex", " Timestamp", " Duration", " Code", " Status", " URL") -ForegroundColor Green
Write-Host ($formatString -f "-----", "---------", "--------", "----", "------", "---") -ForegroundColor Green

try {
    $redirectCounter = 0
    $url = Ensure-UrlScheme -url $url -previousUrl $lastRedirectUrl

    do {
        if ($redirectCounter -ge 30) {
            Write-Host "`n[!] Warning: More than 30 redirects. Possible infinite loop." -ForegroundColor Yellow
            break
        }

        $currentTimestamp = Get-Date
        $timeDifference = $currentTimestamp - $previousTimestamp

        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue

        # Retry logic for 502 Bad Gateway or similar transient errors
        $attempts = 0
        while ($response.StatusCode -eq 502 -and $attempts -lt $retryLimit) {
            Write-Host "`n[!] Received 502 Bad Gateway. Retrying in $retryDelay seconds..." -ForegroundColor Yellow
            Start-Sleep -Seconds $retryDelay
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue
            $attempts++
            $retryDelay *= 2 # Exponential backoff
        }

        if ($response.StatusCode -eq 301 -or $response.StatusCode -eq 302) {
            if ($urlHistory -contains $url) {
                Write-Host "`n[!] Warning: Repeating URL pattern detected. Possible infinite loop." -ForegroundColor Yellow
                break
            }

            Write-Host ($formatString -f "$redirectCounter", "$($currentTimestamp.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ"))", "$(Format-TimeDifference -timeSpan $timeDifference)", "$($response.StatusCode)", "$(Get-HttpStatusDescription -statusCode $response.StatusCode)", "$(Defang-Url -url $url)") -ForegroundColor Green
            
            $urlHistory += $url

            $url = Ensure-UrlScheme -url $response.Headers.Location -previousUrl $lastRedirectUrl
            $lastRedirectUrl = $url
            $redirectCounter++
        }
        elseif ($response) {
            Write-Host ($formatString -f "$redirectCounter", "$($currentTimestamp.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ"))", "$(Format-TimeDifference -timeSpan $timeDifference)", "$($response.StatusCode)", "$(Get-HttpStatusDescription -statusCode $response.StatusCode)", "$(Defang-Url -url $url)") -ForegroundColor Green
            break
        }
        else {
            Write-Host "`n[!] No response received or invalid URL." -ForegroundColor Red
            break
        }

        $previousTimestamp = $currentTimestamp
    } while ($true)
}
catch {
    Write-Host "`n[!] $($_.Exception.Message)`n" -ForegroundColor Red
}

$redirectCount = $redirectCounter
Write-Host "`nTotal redirects: $redirectCount`n" -ForegroundColor Green
