<#
.SYNOPSIS
Gathers information on all scheduled tasks and writes to CSV.

.DESCRIPTION
This script scans for all scheduled tasks and collects details like task status, author, the user it runs as, last and next run times, task name, path, action details, and triggers. Results are exported to a CSV.

.NOTES
Requires PowerShell v5+ and admin rights.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Scheduled_Tasks.ps1

.EXAMPLE
PS> .\Scheduled_Tasks.ps1
#>

# Define the output file path
$outputFilePath = 'C:\BlueTeam\Scheduled_Tasks.csv'

# Ensure the output directory exists
New-Item -ItemType Directory -Path (Split-Path $outputFilePath) -Force -ErrorAction SilentlyContinue | Out-Null

# Function to replace null or empty values with a hyphen for clarity
function Replace-WithHyphen {
    param($value)
    if ([string]::IsNullOrWhiteSpace($value)) { "-" } else { $value }
}

# Function to format strings to prevent unwanted behavior in Excel (backtick prefix for special characters)
function Format-ForExcel {
    param($inputString)
    if ($inputString -match "^[=\-+@]") { "'$inputString" } else { $inputString }
}

# Get scheduled tasks information
$allScheduledTasks = @(Get-ScheduledTask | Get-ScheduledTaskInfo)
$totalTaskCount = $allScheduledTasks.Count

# Collect the task details
$taskDetailsCollection = foreach ($taskInfo in $allScheduledTasks) {
    $currentTaskIndex++
    Write-Progress -Activity "Processing Scheduled Tasks" -Status "Task $currentTaskIndex of $totalTaskCount" -PercentComplete (($currentTaskIndex / $totalTaskCount) * 100)

    $taskData = Get-ScheduledTask -TaskName $taskInfo.TaskName -TaskPath $taskInfo.TaskPath
    $formattedTriggers = ($taskData.Triggers | Format-List | Out-String).Trim()

    foreach ($taskAction in $taskData.Actions) {
        [PSCustomObject]@{
            TaskName       = Replace-WithHyphen $taskData.TaskName
            TaskPath       = Replace-WithHyphen $taskData.TaskPath
            State          = Replace-WithHyphen $taskData.State
            RunAs          = Replace-WithHyphen $taskData.Principal.UserId
            LastRunTime    = Replace-WithHyphen $taskInfo.LastRunTime
            NextRunTime    = Replace-WithHyphen $taskInfo.NextRunTime
            LastUpdated    = Replace-WithHyphen $taskData.Date
            Author         = Replace-WithHyphen $taskData.Author
            Description    = Replace-WithHyphen $taskData.Description
            Triggers       = Replace-WithHyphen $formattedTriggers
            Execute        = Replace-WithHyphen $taskAction.Execute
            Arguments      = Replace-WithHyphen (Format-ForExcel $taskAction.Arguments)
            ActionId       = Replace-WithHyphen $taskAction.Id
            WorkDirectory  = Replace-WithHyphen $taskAction.WorkDirectory
            PSComputerName = Replace-WithHyphen $taskAction.PSComputerName
            StopTask       = "Stop-ScheduledTask -TaskName '$($taskData.TaskName)' -TaskPath '$($taskData.TaskPath)'"
            DeleteTask     = "Unregister-ScheduledTask -TaskName '$($taskData.TaskName)' -TaskPath '$($taskData.TaskPath)' -Confirm:`$false"
            DisableTask    = "Disable-ScheduledTask -TaskName '$($taskData.TaskName)' -TaskPath '$($taskData.TaskPath)'"
            EnableTask     = "Enable-ScheduledTask -TaskName '$($taskData.TaskName)' -TaskPath '$($taskData.TaskPath)'"
            StartTask      = "Start-ScheduledTask -TaskName '$($taskData.TaskName)' -TaskPath '$($taskData.TaskPath)'"
        }
    }
}

# Export results to CSV
$taskDetailsCollection | Sort-Object LastUpdated -Descending | Export-Csv -Path $outputFilePath -NoTypeInformation

Write-Progress -Activity "Processing Scheduled Tasks" -Completed
