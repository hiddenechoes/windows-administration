<#
.SYNOPSIS
    Extracts the Microsoft Teams (New) logo from the MSIX install for use with RemoteApp icons.

.DESCRIPTION
    Finds the all-users MSTeams Store package, resolves the highest available TeamsForWorkNewStoreLogo PNG,
    and copies it to a shared destination so RemoteApp or other tooling can reference it.
    Requires running in an elevated PowerShell session.

.PARAMETER DestinationDirectory
    The directory where the icon PNG will be copied. Defaults to $env:ProgramData\RemoteAppIcons.

.PARAMETER OutputFileName
    File name to use for the exported PNG. Defaults to MicrosoftTeams.png.

.EXAMPLE
    .\Get-TeamsIcon.ps1
    Copies the Teams icon to $env:ProgramData\RemoteAppIcons\MicrosoftTeams.png and outputs the path.

.EXAMPLE
    .\Get-TeamsIcon.ps1 -DestinationDirectory 'C:\RemoteApps\Icons' -OutputFileName 'Teams.png'
    Copies the icon into C:\RemoteApps\Icons\Teams.png and outputs the path.

.NOTES
    Author: Corwin Robins
    Running as administrator is required to enumerate MSTeams for all users and write under ProgramData.
#>

# Extract the Microsoft Teams icon from the New Teams MSIX so RemoteApp can use it.
[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Directory to copy the Teams icon into.")]
    [string]$DestinationDirectory = "$env:ProgramData\RemoteAppIcons",

    [Parameter(HelpMessage = "File name to use for the copied icon.")]
    [string]$OutputFileName = "MicrosoftTeams.png"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Require elevation since we enumerate all-user packages and write under ProgramData.
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    throw 'Run this script in an elevated PowerShell session (Run as Administrator).'
}

function Get-TeamsMsixPackage {
    [CmdletBinding()] param()

    try {
        # Query the Store-based New Teams package that installs for all users.
        return Get-AppxPackage -Name 'MSTeams' -AllUsers -ErrorAction Stop | Select-Object -First 1
    }
    catch {
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
        # Prefer the highest scale badge logo for the sharpest image.
        $fileName = '{0}.scale-{1}.png' -f $badgeName, $scale
        $fullPath = Join-Path -Path $imageRoot -ChildPath $fileName
        if (Test-Path -LiteralPath $fullPath) {
            return (Resolve-Path -LiteralPath $fullPath).Path
        }
    }

    # Fall back to any Teams PNG, favoring larger files.
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

# Ensure the destination folder exists before placing the icon.
if (-not (Test-Path -LiteralPath $DestinationDirectory)) {
    Write-Verbose ("Creating destination directory '{0}'." -f $DestinationDirectory)
    New-Item -Path $DestinationDirectory -ItemType Directory -Force | Out-Null
}

$destinationPath = Join-Path -Path $DestinationDirectory -ChildPath $OutputFileName

# Copy the PNG and report where it landed.
Copy-Item -LiteralPath $iconPath -Destination $destinationPath -Force

Write-Verbose ("Copied Teams icon to '{0}'." -f $destinationPath)

Write-Output $destinationPath

