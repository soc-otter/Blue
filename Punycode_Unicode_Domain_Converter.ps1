<#
.SYNOPSIS
Converts and defangs domain names between Punycode and Unicode formats. Tries to show conversion in notepad by opening file due to formatting reasons but, if that fails, it will attempt to write to console.

.DESCRIPTION
This script handles domain names in both Punycode and Unicode formats including optionally defanged domains. It refangs domains if necessary, converts between Punycode and Unicode, and defangs the output for security purposes. The conversion results, including both original and converted domains in defanged format, are saved to a text file. This is useful for analyzing potentially malicious domains that may use obfuscation techniques. If file writing fails, results are output to the console but the output isn't formatted as nicely due to constraints.

.NOTES
Requires PowerShell v5+.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Punycode_Unicode_Domain_Converter.ps1

.EXAMPLE
PS> .\Punycode_Unicode_Domain_Converter.ps1
#>

$domains = @("xn--s7y[.]co", "短[.]co", "example[.]com", "xn--starucks-hpd[.]com")

function Convert-Domains {
    param (
        [string[]]$domains
    )

    # Define the output path
    $outputDir = "C:\BlueTeam"
    $outputFileName = "punycode_and_unicode_domain_conversion_results.txt"
    $outputPath = Join-Path -Path $outputDir -ChildPath $outputFileName

    # Create the directory if it doesn't exist
    if (-not (Test-Path -Path $outputDir)) {
        try {
            New-Item -ItemType Directory -Path $outputDir -ErrorAction Stop | Out-Null
        } catch {
            # Fallback to current directory if creation fails
            $outputPath = Join-Path -Path (Get-Location) -ChildPath $outputFileName
        }
    }

    $idn = New-Object System.Globalization.IdnMapping
    $results = @()

    foreach ($domain in $domains) {
        # Refang domain
        $refangedDomain = $domain -replace '\[\.\]', '.'

        try {
            if ($refangedDomain -match '^xn--') {
                # Punycode to Unicode
                $converted = $idn.GetUnicode($refangedDomain)
                $conversionType = 'Punycode to Unicode'
            } elseif (-not $refangedDomain.Contains("xn--") -and $refangedDomain -match '[^\u0000-\u007F]') {
                # Unicode to Punycode
                $converted = $idn.GetAscii($refangedDomain)
                $conversionType = 'Unicode to Punycode'
            } else {
                # No conversion needed
                $converted = $refangedDomain
                $conversionType = 'None'
            }
        } catch {
            $converted = 'Error in conversion'
            $conversionType = 'Error'
        }

        # Defang domains for output
        $defangedOriginal = ($domain -replace '\.', '[.]') -replace '\[\[\.\]\]', '[.]'
        $defangedConverted = ($converted -replace '\.', '[.]') -replace '\[\[\.\]\]', '[.]'

        $results += [PSCustomObject]@{
            'Original Domain' = $defangedOriginal
            'Converted Domain' = $defangedConverted
            'Conversion Type' = $conversionType
        }
    }

    try {
        # Clear file content if it exists
        if (Test-Path $outputPath) {
            Clear-Content -Path $outputPath
        }

        # Write results to file
        $results | Format-Table -AutoSize | Out-String | Set-Content -Path $outputPath -Encoding UTF8

        # Open the text file
        Invoke-Item $outputPath
    } catch {
        # Fallback to console output if file writing fails
        Write-Host "Failed to write to file. Writing results to console:"
        $results | Format-Table -AutoSize
    }
}

# Set console output to UTF-8 if not running in ISE
if (-not $psISE) {
    try {
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    } catch {
        Write-Host "Unable to set console output encoding to UTF-8. Proceeding with default encoding." -ForegroundColor Yellow
    }
}

# Execute the function
Convert-Domains -domains $domains
