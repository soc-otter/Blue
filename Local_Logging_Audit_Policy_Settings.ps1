<#

.SYNOPSIS
Retrieves the local logging audit policy settings from the system.

.DESCRIPTION
This script runs 'auditpol /get /category:*' to retrieve all local logging audit policy settings and exports the data to a CSV file. These settings provide an overview of what security-related events are being logged on the system which can help in monitoring for suspicious activity, identifying security misconfigurations, and supporting incident response efforts.

.NOTES
Requires PowerShell v5+ and administrative privileges.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Local_Logging_Audit_Policy_Settings.ps1

.EXAMPLE
PS> .\Local_Logging_Audit_Policy_Settings.ps1

#>

# Define output directory and file
$outputDirectory = 'C:\BlueTeam'
$outputFile = Join-Path $outputDirectory "Local_Logging_Audit_Policy_Settings.csv"

# Ensure output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Run Auditpol command and capture output
$auditpolOutput = auditpol /get /category:* | Out-String

# Convert output into an array of lines
$auditpolLines = $auditpolOutput -split "`r`n"

# Initialize the current category
$currentCategory = ""

# Process output
$auditPolicySettings = foreach ($line in $auditpolLines) {
    if ($line -match 'Category/Subcategory') {
        $currentCategory = ""
        continue
    }

    if ($line -match '^\S') {
        $currentCategory = $line -replace '^(.+)\s{2,}.*$', '$1'
    }
    elseif ($line -match '^\s{2,}') {
        if ($currentCategory -ne "") {
            $line = $line.Trim()
            $policyParts = $line -split "\s{2,}", 2
            if ($policyParts.Count -eq 2) {
                [PSCustomObject]@{
                    'Log Category'    = $currentCategory
                    'Log Subcategory' = $policyParts[0]
                    'Log Setting'     = $policyParts[1]
                }
            }
        }
    }
}

# Export to CSV
$auditPolicySettings | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
