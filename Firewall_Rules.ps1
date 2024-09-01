<#
.SYNOPSIS
Extracts all firewall rule details on the host and exports them to a CSV file.

.DESCRIPTION
This script retrieves all firewall rules on a local system using the 'netsh' command. It parses each rule to extract key details such as rule name, enabled status, direction, profiles, grouping, IPs, protocol, ports, edge traversal, and action. This is useful for identifying firewall configurations that may expose the system to adversarial behavior or potential misconfigurations.

.NOTES
Requires PowerShell v5+ and administrative privileges.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Firewall_Rules.ps1

.EXAMPLE
PS> .\Firewall_Rules.ps1
#>

# Set the output directory
$outputDirectory = 'C:\BlueTeam'
$outputFile = Join-Path $outputDirectory 'Firewall_Rules.csv'

# Ensure the output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Define the fields and their corresponding netsh output
$fieldsToMatch = [ordered]@{
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

# Retrieve firewall rules using netsh
$rules = netsh advfirewall firewall show rule name=all

# Initialize variables
$output = [System.Collections.Generic.List[PSCustomObject]]::new()
$rule = [ordered]@{}
$totalRules = ($rules -match "Rule Name:").Count
$ruleCount = 0

# Process each line of the netsh output
foreach ($line in $rules) {
    if ($line -match "Rule Name:") {
        if ($rule.Count -gt 0) {
            $output.Add([PSCustomObject]$rule)
            $rule = [ordered]@{}
        }
        $ruleCount++
        Write-Progress -Activity "Processing Firewall Rules" -Status "Rule $ruleCount of $totalRules" -PercentComplete (($ruleCount / $totalRules) * 100)
    }

    foreach ($field in $fieldsToMatch.GetEnumerator()) {
        if ($line -match "^$($field.Value)\s*(.*)") {
            $rule[$field.Key] = $matches[1].Trim()
            break
        }
    }
}

# Add the last rule if it exists
if ($rule.Count -gt 0) {
    $output.Add([PSCustomObject]$rule)
}

# Export to CSV
$output | Export-Csv -Path $outputFile -NoTypeInformation
