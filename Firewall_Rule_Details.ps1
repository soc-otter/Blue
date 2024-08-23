<#
.SYNOPSIS
Extracts all firewall rule details and exports them to a CSV file.

.DESCRIPTION
This script retrieves all firewall rules on a local system using the 'netsh' command. It parses each rule to extract key details, such as rule name, enabled status, direction, profiles, grouping, IPs, protocol, ports, edge traversal, and action. This is useful for identifying firewall configurations that may expose the system to adversarial behavior or potential misconfigurations.

.NOTES
Requires PowerShell v5+ and administrative privileges.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Firewall_Rule_Details.ps1

.EXAMPLE
PS> .\Firewall_Rule_Details.ps1
#>

# Set the output directory
$outputDirectory = 'C:\BlueTeam'

Write-Progress -Activity "Processing Firewall Rules" -Status "Initializing Directory Setup" -PercentComplete 10

# Ensure the output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

Write-Progress -Activity "Processing Firewall Rules" -Status "Fetching Firewall Rules" -PercentComplete 30

# Retrieve firewall rules using netsh
$rules = netsh advfirewall firewall show rule name=all
$output = New-Object System.Collections.Generic.List[Object]
$fields = @("Rule Name", "Enabled", "Direction", "Profiles", "Grouping", "LocalIP", "RemoteIP", "Protocol", "LocalPort", "RemotePort", "Edge traversal", "Action")

# Define the mapping of fields to match
$fieldsToMatch = @{
    "Rule Name" = "Rule Name:"
    "Enabled" = "Enabled:"
    "Direction" = "Direction:"
    "Profiles" = "Profiles:"
    "Grouping" = "Grouping:"
    "LocalIP" = "LocalIP:"
    "RemoteIP" = "RemoteIP:"
    "Protocol" = "Protocol:"
    "LocalPort" = "LocalPort:"
    "RemotePort" = "RemotePort:"
    "Edge traversal" = "Edge traversal:"
    "Action" = "Action:"
}

# Initialize rule processing variables
$rule = [ordered]@{}
$distinctRuleCount = ($rules | Where-Object { $_ -match "Rule Name:" }).Count
$ruleIndex = 0
$progressPerRule = 50 / $distinctRuleCount

# Process each rule
foreach ($line in $rules) {
    if ($line -match "Rule Name:") {
        $ruleIndex++
    }
    
    # Update progress
    $currentProgress = [math]::Min(30 + ($ruleIndex * $progressPerRule), 100)
    Write-Progress -Activity "Processing Firewall Rules" -Status "Processing Rule $ruleIndex of $distinctRuleCount" -PercentComplete $currentProgress

    $splitLine = $line.Trim().Split(":", 2)
    $keyMatched = $fieldsToMatch.Keys | Where-Object { $fieldsToMatch[$_] -eq ($splitLine[0] + ":") }
    
    if ($keyMatched) {
        if ($keyMatched -eq "Rule Name" -and $rule.Count -gt 0) {
            $copiedRule = New-Object System.Collections.Specialized.OrderedDictionary
            foreach ($key in $rule.Keys) {
                $copiedRule[$key] = $rule[$key]
            }
            $output.Add($copiedRule)
            $rule.Clear()
        }
        $rule[$keyMatched] = $splitLine[1].Trim()
    }
}

# Add rules if exists
if ($rule.Count -gt 0) {
    $output.Add($rule)
}

Write-Progress -Activity "Processing Firewall Rules" -Status "Preparing Data for Export" -PercentComplete 80

# Convert to PSCustomObject for CSV export
$objectOutput = $output | ForEach-Object { New-Object PSCustomObject -Property $_ }

Write-Progress -Activity "Processing Firewall Rules" -Status "Exporting to CSV" -PercentComplete 90

# Export to CSV
$objectOutput | Select-Object $fields | Export-Csv -Path "$outputDirectory\Firewall_Rule_Details.csv" -NoTypeInformation

Write-Progress -Activity "Processing Firewall Rules" -Status "Completed" -PercentComplete 100
