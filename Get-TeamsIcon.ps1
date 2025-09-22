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

    $imageRoot = Join-Path -Path $InstallPath -ChildPath 'Images'
    if (-not (Test-Path -LiteralPath $imageRoot)) {
        return $null
    }

    $badgeName = 'TeamsForWorkNewStoreLogo'
    $scaleValues = 400, 200, 150, 125, 100

    foreach ($scale in $scaleValues) {
        $fileName = '{0}.scale-{1}.png' -f $badgeName, $scale
        $fullPath = Join-Path -Path $imageRoot -ChildPath $fileName
        if (Test-Path -LiteralPath $fullPath) {
            return (Resolve-Path -LiteralPath $fullPath).Path
        }
    }

    # Fallback: choose the largest Teams PNG in the Images directory
    $fallbackIcon = Get-ChildItem -Path $imageRoot -Filter '*.png' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'Teams' } |
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
