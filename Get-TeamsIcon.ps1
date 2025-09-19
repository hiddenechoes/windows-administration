[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Directory to copy the Teams icon into.")]
    [string]$DestinationDirectory = "$env:ProgramData\RemoteAppIcons",

    [Parameter(HelpMessage = "File name to use for the copied icon.")]
    [string]$OutputFileName = "MicrosoftTeams.png",

    [Parameter(HelpMessage = "Return the FileInfo object for the copied icon.")]
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-TeamsMsixPackage {
    [CmdletBinding()] param()

    try {
        return Get-AppxPackage -Name 'MSTeams' -AllUsers -ErrorAction Stop | Select-Object -First 1
    } catch {
        Write-Verbose 'Get-AppxPackage -AllUsers did not find MSTeams.'
        return $null
    }
}

function Find-TeamsIconPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$InstallPath
    )

    $candidateRelativePaths = @(
        'Images\TeamsForWorkNewAppList.targetsize-256_altform-unplated.png',
        'Images\TeamsForWorkNewAppList.targetsize-256.png',
        'Images\TeamsForWorkAppList.targetsize-256_altform-unplated.png',
        'Images\TeamsForWorkAppList.targetsize-256.png',
        'Images\TeamsAppList.targetsize-256_altform-unplated.png',
        'Images\TeamsAppList.targetsize-256.png',
        'Assets\TeamsForWorkIcon.targetsize-256_altform-unplated.png',
        'Assets\TeamsForWorkIcon.targetsize-256.png'
    )

    foreach ($relativePath in $candidateRelativePaths) {
        $fullPath = Join-Path -Path $InstallPath -ChildPath $relativePath
        if (Test-Path -LiteralPath $fullPath) {
            return (Resolve-Path -LiteralPath $fullPath).Path
        }
    }

    # Fallback: look for any 256px icon that matches typical naming
    $fallbackIcon = Get-ChildItem -Path $InstallPath -Recurse -Filter '*targetsize-256*_unplated.png' -ErrorAction SilentlyContinue |
        Sort-Object -Property Length -Descending |
        Select-Object -First 1

    if ($fallbackIcon) {
        return $fallbackIcon.FullName
    }

    return $null
}

if (-not (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue)) {
    throw 'Get-AppxPackage cmdlet is not available. Run this script in PowerShell 5.1+ or PowerShell 7+ on Windows.'
}

$teamsPackage = Get-TeamsMsixPackage
if (-not $teamsPackage) {
    throw 'Microsoft Teams (New) is not installed from the Microsoft Store on this device.'
}

$installLocation = $teamsPackage.InstallLocation
if (-not $installLocation -or -not (Test-Path -LiteralPath $installLocation)) {
    throw "Unable to resolve the MSTeams package install location. Reported path: '$installLocation'."
}

Write-Verbose ("Found MSTeams package at '{0}'." -f $installLocation)

$iconPath = Find-TeamsIconPath -InstallPath $installLocation
if (-not $iconPath) {
    throw "Could not locate a Teams icon PNG within the MSTeams package at '$installLocation'."
}

Write-Verbose ("Teams icon located at '{0}'." -f $iconPath)

if (-not (Test-Path -LiteralPath $DestinationDirectory)) {
    Write-Verbose ("Creating destination directory '{0}'." -f $DestinationDirectory)
    New-Item -Path $DestinationDirectory -ItemType Directory -Force | Out-Null
}

$destinationPath = Join-Path -Path $DestinationDirectory -ChildPath $OutputFileName

Copy-Item -LiteralPath $iconPath -Destination $destinationPath -Force

Write-Verbose ("Copied Teams icon to '{0}'." -f $destinationPath)

if ($PassThru) {
    Get-Item -LiteralPath $destinationPath
} else {
    Write-Output $destinationPath
}
