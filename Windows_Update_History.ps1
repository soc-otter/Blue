<#
.SYNOPSIS
Retrieves the history of Windows updates applied to the system and exports them to a CSV.

.DESCRIPTION
This script collects information about Windows updates applied to the system including update titles, IDs, installation dates, operations, result codes, and Knowledge Base (KB) article IDs. The script is useful for auditing update histories, identifying potential issues with updates, and ensuring that patches have been applied.

.NOTES
Requires PowerShell v5+ and administrative privileges.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Windows_Update_History.ps1

.EXAMPLE
PS> .\Windows_Update_History.ps1
#>

# Set the output directory
$outputDirectory = 'C:\BlueTeam'
$csvFileName = 'Windows_Update_History.csv'

# Progress
Write-Progress -Activity "Setup" -Status "Initializing directory setup" -PercentComplete 10

# Ensure the output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Function to retrieve Windows Update history
function Get-WindowsUpdateHistory {
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()

    try {
        $historyCount = $updateSearcher.GetTotalHistoryCount()
        $updates = $updateSearcher.QueryHistory(0, $historyCount)
        $processedUpdates = 0

        $updates | ForEach-Object {
            $processedUpdates++
            Write-Progress -Activity "Collecting Windows Update History" -Status "Processing update $processedUpdates of $historyCount" -PercentComplete (($processedUpdates / $historyCount) * 100)

            $operation = switch ($_.Operation) {
                1 { "Installation" }
                2 { "Uninstallation" }
                3 { "Other" }
                Default { "Unknown" }
            }

            $resultCodeDescription = switch ($_.ResultCode) {
                0 { "Not Started" }
                1 { "In Progress" }
                2 { "Succeeded" }
                3 { "Succeeded With Errors" }
                4 { "Failed" }
                5 { "Aborted" }
                Default { "Unknown" }
            }

            $kbArticleID = if ($_.KnowledgeBaseArticles.Count -gt 0) { $_.KnowledgeBaseArticles[0] } else { "Not Available" }
            
            [PSCustomObject]@{
                Title                 = $_.Title
                UpdateID              = $_.UpdateIdentity.UpdateID
                DateInstalled         = $_.Date
                Operation             = $operation
                ResultCodeDescription = $resultCodeDescription
                KnowledgeBaseID       = $kbArticleID
                SupportURL            = $_.SupportUrl
                Description           = $_.Description
            }
        } 
    } catch {
        Write-Error "Error fetching Windows Update history: $_"
    }

    Write-Progress -Activity "Collecting Windows Update History" -Status "Completed" -Completed
}

# Progress
Write-Progress -Activity "Collecting Windows Update History" -Status "Starting collection..." -PercentComplete 20

# Retrieve and export Windows Update history to CSV
$updateHistoryDetails = Get-WindowsUpdateHistory
$outputFilePath = Join-Path -Path $outputDirectory -ChildPath $csvFileName

# Progress
Write-Progress -Activity "Exporting Data" -Status "Exporting update history to CSV" -PercentComplete 90
$updateHistoryDetails | Export-Csv -Path $outputFilePath -NoTypeInformation

# Progress
Write-Progress -Activity "Exporting Data" -Status "Completed" -PercentComplete 100 -Completed
