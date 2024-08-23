<#

.SYNOPSIS
Captures a single screenshot of each monitors for every logged-in user.

.DESCRIPTION
This script automates the process of capturing screenshots from all connected monitors for each logged-in user. It uses scheduled tasks to run the screenshot capture process in the context of each user.

.NOTES
Requires PowerShell v5+ and administrative privileges.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Capture_Screenshot_All_Users.ps1

.EXAMPLE
PS> .\Capture_Screenshot_All_Users.ps1

#>

# Define the output directory
$outputDirectory = 'C:\BlueTeam'

# Ensure the output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

Write-Progress -Activity "Screenshot Capture" -Status "Initializing" -PercentComplete 0

# Load required assemblies for capturing screen images
Add-Type -AssemblyName System.Windows.Forms, System.Drawing

# Function to create scheduled task for screenshot capture
function Create-ScreenshotTask {
    param (
        [string]$username,
        [string]$outputPath,
        [string]$userId = "SYSTEM"
    )

    $taskName = "CaptureScreenshots_$username"
    $scriptBlock = @"
Add-Type -AssemblyName System.Windows.Forms, System.Drawing;
`$screens = [System.Windows.Forms.Screen]::AllScreens;
`$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss';
for (`$i = 0; `$i -lt `$screens.Length; `$i++) {
    `$screen = `$screens[`$i];
    `$bitmap = New-Object System.Drawing.Bitmap(`$screen.Bounds.Width, `$screen.Bounds.Height);
    `$graphics = [System.Drawing.Graphics]::FromImage(`$bitmap);
    `$graphics.CopyFromScreen(`$screen.Bounds.Location, [System.Drawing.Point]::Empty, `$screen.Bounds.Size);
    `$filePath = Join-Path '$outputPath' ('$username' + '_monitor_' + `$i + '_' + `$timestamp + '.png');
    `$bitmap.Save(`$filePath, [System.Drawing.Imaging.ImageFormat]::Png);
    `$graphics.Dispose();
    `$bitmap.Dispose();
}
Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false
"@

    $bytes = [System.Text.Encoding]::Unicode.GetBytes($scriptBlock)
    $encodedCommand = [Convert]::ToBase64String($bytes)
    $action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "-NoProfile -WindowStyle Hidden -EncodedCommand $encodedCommand"
    
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)
    
    if ($userId -eq "SYSTEM") {
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    } else {
        $principal = New-ScheduledTaskPrincipal -UserId $username -LogonType Interactive -RunLevel Highest
    }

    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force
        Start-ScheduledTask -TaskName $taskName
        return $taskName
    } catch {
        Write-Progress -Activity "Screenshot Capture" -Status "Failed to create task for user: $username" -PercentComplete -1
        return $null
    }
}

# Get all user profiles
$userProfiles = Get-ChildItem 'C:\Users' | Where-Object { $_.PSIsContainer -and $_.Name -notmatch '^(Default|Public|All Users|Default User|systemprofile)$' }

# Track tasks created
$tasksCreated = @()

# Create tasks for each user profile
$totalUsers = $userProfiles.Count + 1 # +1 for SYSTEM
$currentUser = 0

foreach ($profile in $userProfiles) {
    $currentUser++
    $username = $profile.Name
    Write-Progress -Activity "Screenshot Capture" -Status "Creating task for user: $username" -PercentComplete (($currentUser / $totalUsers) * 50)
    $taskName = Create-ScreenshotTask -username $username -outputPath $outputDirectory -userId $username
    if ($taskName) { $tasksCreated += $taskName }
}

# Attempt to capture screenshots
$currentUser++
Write-Progress -Activity "Screenshot Capture" -Status "Creating task for SYSTEM" -PercentComplete (($currentUser / $totalUsers) * 50)
$taskName = Create-ScreenshotTask -username "SYSTEM" -outputPath $outputDirectory
if ($taskName) { $tasksCreated += $taskName }

# Wait for all tasks to complete
Write-Progress -Activity "Screenshot Capture" -Status "Waiting for tasks to complete" -PercentComplete 60
$taskCompleted = $false
$attempts = 0
while (-not $taskCompleted -and $attempts -lt 60) {
    Start-Sleep -Seconds 1
    $runningTasks = Get-ScheduledTask | Where-Object { $tasksCreated -contains $_.TaskName -and $_.State -eq 'Running' } -ErrorAction SilentlyContinue
    if ($runningTasks.Count -eq 0) {
        $taskCompleted = $true
    } else {
        Write-Progress -Activity "Screenshot Capture" -Status "Waiting for tasks to complete" -PercentComplete (60 + ($attempts / 60 * 40))
    }
    $attempts++
}

# Final status update
$screenshots = Get-ChildItem -Path $outputDirectory -Filter "*_monitor_*.png"
if ($screenshots.Count -gt 0) {
    Write-Progress -Activity "Screenshot Capture" -Status "Completed. Captured $($screenshots.Count) screenshots." -PercentComplete 100
} else {
    Write-Progress -Activity "Screenshot Capture" -Status "Completed. No screenshots were captured." -PercentComplete 100
}

Write-Progress -Activity "Screenshot Capture" -Completed
