<#

.SYNOPSIS
Captures and saves clipboard contents from all logged-in users for forensic analysis.

.DESCRIPTION
This script captures clipboard content from all logged-in users by creating and immediately triggering scheduled tasks that run under each user's context. The captured content is saved to individual text files named after the respective user in the `C:\BlueTeam` directory. This approach is useful in forensic investigations to determine what information a potentially compromised user had in their clipboard at the time of the incident. The collected data provides valuable context for understanding user activities during an investigation. The script ensures the output directory exists and cleans up the tasks after they run.

.NOTES
Requires PowerShell v5+ and administrative privileges.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Clipboard_Contents_All_Users.ps1

.EXAMPLE
PS> .\Clipboard_Contents_All_Users.ps1

#>

# Define the output directory
$outputDirectory = 'C:\BlueTeam'

# Ensure the output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Get all user profiles from C:\Users (excluding default and system profiles)
$userProfiles = Get-ChildItem 'C:\Users' | Where-Object { $_.PSIsContainer -and $_.Name -notmatch '^(Default|Public|All Users|Default User|systemprofile)$' }

# Track files created and tasks
$createdFiles = @()
$tasksCreated = @()

# Function to create scheduled task for clipboard capture
function Create-CaptureTask {
    param (
        [string]$username,
        [string]$filePath,
        [string]$userId = "SYSTEM"
    )

    $taskName = "GetClipboardContents_$username"
    $action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "-NoProfile -WindowStyle Hidden -Command `"Get-Clipboard -Raw | Out-File -FilePath '$filePath' -Encoding UTF8; Start-Sleep -Seconds 10`""
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)
    
    # Check if running for SYSTEM or a specific user
    if ($userId -eq "SYSTEM") {
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    } else {
        $principal = New-ScheduledTaskPrincipal -UserId $username -LogonType Interactive -RunLevel Highest
    }

    try {
        # Register the task
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force

        # Start the task immediately
        Start-ScheduledTask -TaskName $taskName

        # Track the task created
        $tasksCreated += $taskName
        $createdFiles += $filePath

    } catch {
        Write-Progress -Activity "Creating Task" -Status "Failed to create task for user: $username. Error: $_" -PercentComplete 0
    }
}

# Create tasks for each user profile
foreach ($profile in $userProfiles) {
    $username = $profile.Name
    $filePath = Join-Path $outputDirectory "${username}_Clipboard_Contents.txt"
    Create-CaptureTask -username $username -filePath $filePath -userId $username
}

# Attempt to capture SYSTEM clipboard
$systemFilePath = Join-Path $outputDirectory "SYSTEM_Clipboard_Contents.txt"
Create-CaptureTask -username "SYSTEM" -filePath $systemFilePath

# Wait for all tasks to complete
$taskCompleted = $false
$attempts = 0
while (-not $taskCompleted -and $attempts -lt 15) {
    Start-Sleep -Seconds 2
    $tasksStatus = Get-ScheduledTask | Where-Object { $tasksCreated -contains $_.TaskName -and ($_.State -eq 'Ready' -or $_.State -eq 'Disabled') }
    if ($tasksStatus.Count -eq $tasksCreated.Count) {
        $taskCompleted = $true
    }
    $attempts++
}

# Attempt to read captured clipboard contents
try {
    foreach ($filePath in $createdFiles) {
        if (Test-Path $filePath) {
            $fileContent = Get-Content -Path $filePath
            if (-not [string]::IsNullOrWhiteSpace($fileContent)) {
                Write-Progress -Activity "Clipboard Capture" -Status "Clipboard content saved to: $filePath" -PercentComplete 100
            } else {
                Write-Progress -Activity "Clipboard Capture" -Status "No clipboard content found for file: $filePath" -PercentComplete 100
                Remove-Item -Path $filePath -Force
            }
        } else {
            Write-Progress -Activity "Clipboard Capture" -Status "Failed to capture clipboard content. No file created at: $filePath" -PercentComplete 100
        }
    }
} catch {
    Write-Progress -Activity "Clipboard Capture" -Status "An error occurred while reading clipboard data: $_" -PercentComplete 100
}

# Clean up tasks
foreach ($taskName in $tasksCreated) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

Write-Progress -Activity "Clipboard Capture" -Status "Clipboard data capture process completed." -PercentComplete 100
