<#
.SYNOPSIS
Installs the new Microsoft Teams client optimized for Azure Virtual Desktop (AVD).

.DESCRIPTION
Downloads the Microsoft Teams bootstrapper, removes legacy Teams deployments, installs the Remote Desktop WebRTC Redirector service, and installs the new Teams client with VDI optimizations for Azure Virtual Desktop hosts. The script provisions Teams using the bootstrapper for future profiles (when requested), registers it for the current session, and configures required registry keys.

.PARAMETER TeamsBootstrapperUrl
Location of the Microsoft Teams bootstrapper executable (x64). Defaults to the evergreen link supplied by Microsoft.

.PARAMETER WebRtcInstallerUrl
Download location of the Remote Desktop WebRTC Redirector Service (MSI). Defaults to the Microsoft evergreen link.

.PARAMETER DownloadDirectory
Local directory used for caching the Teams bootstrapper and WebRTC Redirector MSI. Defaults to %ProgramData%\Microsoft\TeamsVDI.

.PARAMETER SkipRemoveClassicTeams
Skips removal of the Teams Machine-Wide Installer and classic Teams per-user folders.

.PARAMETER SkipWebRtcRedirectorInstall
Skips installation of the Remote Desktop WebRTC Redirector service.

.PARAMETER NoProvisioning
Installs Teams for the current session only (bootstrapper without provisioning switch).

.PARAMETER Force
Forces re-download of cached installers even if they already exist locally.

.EXAMPLE
PS C:\> .\Install-Teams-VDI.ps1
Installs the latest Teams client, provisions it for all users on the host using the bootstrapper, and ensures the WebRTC Redirector Service is present.

.NOTES
Requires administrative privileges and network access to the Teams and Azure Virtual Desktop content delivery networks.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TeamsBootstrapperUrl = 'https://go.microsoft.com/fwlink/?linkid=2248151',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$WebRtcInstallerUrl = 'https://aka.ms/msrdcwebrtcsvc',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DownloadDirectory = "$env:ProgramData\Microsoft\TeamsVDI",

    [Parameter()]
    [switch]$SkipRemoveClassicTeams,

    [Parameter()]
    [switch]$SkipWebRtcRedirectorInstall,

    [Parameter()]
    [switch]$NoProvisioning,

    [Parameter()]
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Cyan
}

function Write-WarningMessage {
    param([Parameter(Mandatory)][string]$Message)
    Write-Warning $Message
}

function Ensure-Directory {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -Path $Path)) {
        Write-Step "Creating directory: $Path"
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Get-DownloadTarget {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Directory,
        [Parameter()][string]$FallbackFileName = 'download.bin'
    )

    $uri = [System.Uri]::new($Url)
    $fileName = [System.IO.Path]::GetFileName($uri.AbsolutePath)
    if ([string]::IsNullOrWhiteSpace($fileName) -or ($fileName -notmatch '\.')) {
        $fileName = $FallbackFileName
    }

    return [System.IO.Path]::Combine($Directory, $fileName)
}

function Download-File {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Destination,
        [switch]$ForceDownload
    )

    if ((Test-Path -Path $Destination) -and -not $ForceDownload) {
        Write-Step "Using cached package: $Destination"
        return
    }

    Write-Step "Downloading from $Url"
    Invoke-WebRequest -Uri $Url -UseBasicParsing -OutFile $Destination
}

function Remove-ClassicTeams {
    Write-Step 'Checking for legacy Teams Machine-Wide Installer'

    $registryRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    $foundLegacy = $false

    foreach ($root in $registryRoots) {
        try {
            $entries = Get-ChildItem -Path $root -ErrorAction Stop | ForEach-Object { Get-ItemProperty -Path $_.PSPath }
        } catch {
            continue
        }

        foreach ($entry in $entries | Where-Object { $_.DisplayName -eq 'Teams Machine-Wide Installer' }) {
            $foundLegacy = $true
            $uninstallCmd = $entry.UninstallString
            if (-not $uninstallCmd) {
                continue
            }

            Write-Step 'Removing Teams Machine-Wide Installer'
            if ($uninstallCmd -match '\{[0-9A-F-]{36}\}') {
                $productCode = $matches[0]
                Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/x', $productCode, '/qn', '/norestart') -Wait -WindowStyle Hidden | Out-Null
            } else {
                $cmdArguments = @('/d', '/c', $uninstallCmd)
                if ($uninstallCmd -notmatch '/S') {
                    $cmdArguments[-1] = "$uninstallCmd /S"
                }

                Start-Process -FilePath 'cmd.exe' -ArgumentList $cmdArguments -Wait -WindowStyle Hidden | Out-Null
            }
        }
    }

    if (-not $foundLegacy) {
        Write-Step 'Teams Machine-Wide Installer not found'
    }

    Write-Step 'Removing cached per-user classic Teams folders'
    $systemRoot = Split-Path -Path $env:ProgramData -Parent
    $userProfileRoot = Join-Path -Path $systemRoot -ChildPath 'Users'
    if (Test-Path -Path $userProfileRoot) {
        $teamsRelativePath = [System.IO.Path]::Combine('AppData', 'Local', 'Microsoft', 'Teams')
        Get-ChildItem -Path $userProfileRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $appDataPath = Join-Path -Path $_.FullName -ChildPath $teamsRelativePath
            if (Test-Path -Path $appDataPath) {
                try {
                    Remove-Item -Path $appDataPath -Recurse -Force -ErrorAction Stop
                    Write-Step "Removed $appDataPath"
                } catch {
                    Write-WarningMessage "Failed to clean $appDataPath. $_"
                }
            }
        }
    }
}

function Remove-ExistingNewTeams {
    Write-Step 'Removing existing Microsoft Teams MSIX packages if found'

    $existingPackages = Get-AppxPackage -AllUsers -Name 'MSTeams' -ErrorAction SilentlyContinue
    foreach ($package in $existingPackages) {
        Write-Step "Removing installed package: $($package.PackageFullName)"
        try {
            Remove-AppxPackage -Package $package.PackageFullName -AllUsers
        } catch {
            Write-WarningMessage "Failed to remove package $($package.PackageFullName). $_"
        }
    }

    $provisioned = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq 'MSTeams' }
    foreach ($entry in $provisioned) {
        Write-Step "Removing provisioned package: $($entry.PackageName)"
        try {
            Remove-AppxProvisionedPackage -Online -PackageName $entry.PackageName | Out-Null
        } catch {
            Write-WarningMessage "Failed to remove provisioned package $($entry.PackageName). $_"
        }
    }
}

function Install-NewTeams {
    param(
        [Parameter(Mandatory)][string]$BootstrapperPath,
        [switch]$Provision
    )

    if (-not (Test-Path -Path $BootstrapperPath)) {
        throw "Teams bootstrapper not found at $BootstrapperPath"
    }

    $args = @()
    if ($Provision) {
        $args += '-p'
    }

    Write-Step "Installing Microsoft Teams via Teams bootstrapper"
    $process = Start-Process -FilePath $BootstrapperPath -ArgumentList $args -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -ne 0) {
        throw "Teams bootstrapper returned exit code $($process.ExitCode)"
    }
}

function Install-WebRtcRedirector {
    param([Parameter(Mandatory)][string]$InstallerPath)

    if (-not (Test-Path -Path $InstallerPath)) {
        throw "WebRTC Redirector installer not found at $InstallerPath"
    }

    Write-Step "Installing Remote Desktop WebRTC Redirector Service from $InstallerPath"
    $arguments = @('/i', "`"$InstallerPath`"", '/qn', '/norestart')
    try {
        Start-Process -FilePath 'msiexec.exe' -ArgumentList $arguments -Wait -WindowStyle Hidden | Out-Null
    } catch {
        throw "Failed to install WebRTC Redirector Service. $_"
    }
}

function Ensure-WebRtcRedirector {
    param(
        [Parameter(Mandatory)][string]$InstallerUrl,
        [Parameter(Mandatory)][string]$CacheDirectory,
        [switch]$ForceDownload
    )

    $service = Get-Service -Name 'WebSocketService' -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        Write-Step 'WebRTC Redirector Service already installed'
        return
    }

    Write-Step 'WebRTC Redirector Service not detected. Installing.'
    $installerPath = Get-DownloadTarget -Url $InstallerUrl -Directory $CacheDirectory -FallbackFileName 'MsRdcWebRTCSvc.msi'
    Download-File -Url $InstallerUrl -Destination $installerPath -ForceDownload:$ForceDownload
    Install-WebRtcRedirector -InstallerPath $installerPath

    $service = Get-Service -Name 'WebSocketService' -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        Write-WarningMessage 'WebRTC Redirector Service installation completed but service was not detected. Validate manually.'
    }
}

function Configure-TeamsVDI {
    Write-Step 'Configuring Teams VDI optimization settings'

    $teamsRegPath = 'HKLM:\SOFTWARE\Microsoft\Teams'
    if (-not (Test-Path -Path $teamsRegPath)) {
        New-Item -Path $teamsRegPath -Force | Out-Null
    }

    New-ItemProperty -Path $teamsRegPath -Name 'IsWVDEnvironment' -PropertyType DWord -Value 1 -Force | Out-Null
    New-ItemProperty -Path $teamsRegPath -Name 'MediaRedirectionEnabled' -PropertyType DWord -Value 1 -Force | Out-Null

    $serviceName = 'WebSocketService'
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        if ($service.StartType -ne 'Automatic') {
            Set-Service -Name $serviceName -StartupType Automatic
        }

        if ($service.Status -ne 'Running') {
            Start-Service -Name $serviceName -ErrorAction SilentlyContinue
        }
    } else {
        Write-WarningMessage 'AVD WebSocket redirection service not found. Confirm the Azure Virtual Desktop agent components are installed.'
    }
}

if (-not (Test-IsAdministrator)) {
    throw 'This script must be executed from an elevated PowerShell session.'
}

Write-Step 'Validating host platform'
$osInfo = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
if (-not ($osInfo.ProductName -like '*Windows*') -or -not ($osInfo.ProductName -like '*Virtual*' -or $osInfo.ProductName -like '*Enterprise*')) {
    Write-WarningMessage "Host reports ProductName '$($osInfo.ProductName)'. Ensure this VM is an Azure Virtual Desktop session host."
}

Ensure-Directory -Path $DownloadDirectory

if (-not $SkipWebRtcRedirectorInstall) {
    Ensure-WebRtcRedirector -InstallerUrl $WebRtcInstallerUrl -CacheDirectory $DownloadDirectory -ForceDownload:$Force
} else {
    Write-Step 'Skipping WebRTC Redirector Service installation as requested'
}

$bootstrapperPath = Get-DownloadTarget -Url $TeamsBootstrapperUrl -Directory $DownloadDirectory -FallbackFileName 'TeamsBootstrapper.exe'
Download-File -Url $TeamsBootstrapperUrl -Destination $bootstrapperPath -ForceDownload:$Force

if (-not $SkipRemoveClassicTeams) {
    Remove-ClassicTeams
} else {
    Write-Step 'Skipping legacy Teams removal as requested'
}

Remove-ExistingNewTeams

Install-NewTeams -BootstrapperPath $bootstrapperPath -Provision:(-not $NoProvisioning)
Configure-TeamsVDI

Write-Step 'Microsoft Teams (new) installation and VDI configuration complete'
