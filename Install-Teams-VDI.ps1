<#
.SYNOPSIS
Installs Microsoft Teams (new) and the Azure Virtual Desktop WebRTC Redirector on a fresh Windows 11 session host image.

.DESCRIPTION
Downloads the Teams bootstrapper and the Remote Desktop WebRTC Redirector service, installs both, and applies the minimal registry configuration required for Teams media redirection on Azure Virtual Desktop. The script validates each download and retries the Teams bootstrapper from the CDN if the evergreen link delivers the wrong payload.

.PARAMETER TeamsBootstrapperUrl
Primary download link for the Teams bootstrapper executable (defaults to the evergreen URL).

.PARAMETER WebRtcInstallerUrl
Download link for the Remote Desktop WebRTC Redirector MSI.

.PARAMETER DownloadDirectory
Cache folder for the downloaded installers. Defaults to %ProgramData%\\Microsoft\\TeamsVDI.

.PARAMETER Force
Forces re-download of cached installers.

.EXAMPLE
PS C:\> .\Install-Teams-VDI.ps1
Downloads Teams and the WebRTC Redirector, installs both, and configures Teams for Azure Virtual Desktop.
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
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session.'
}

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
} catch {
    # TLS selection not available on down-level PowerShell.
}

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Cyan
}

function Ensure-Directory {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -Path $Path)) {
        Write-Step "Creating cache directory: $Path"
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Get-DownloadTarget {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string]$FallbackName
    )

    $uri = [System.Uri]::new($Url)
    $fileName = [System.IO.Path]::GetFileName($uri.AbsolutePath)
    if ([string]::IsNullOrWhiteSpace($fileName) -or ($fileName -notmatch '\.')) {
        $fileName = $FallbackName
    }

    return [System.IO.Path]::Combine($Directory, $fileName)
}

function Test-BinarySignature {
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('PE','MSI','AnyBinary')][string]$ExpectedType = 'AnyBinary'
    )

    if (-not (Test-Path -Path $Path)) {
        return $false
    }

    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        try {
            $buffer = New-Object byte[] 8
            $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
            if ($bytesRead -lt 4) {
                return $false
            }

            $isPe = ($buffer[0] -eq 0x4D -and $buffer[1] -eq 0x5A)
            $isMsi = ($buffer[0] -eq 0xD0 -and $buffer[1] -eq 0xCF -and $buffer[2] -eq 0x11 -and $buffer[3] -eq 0xE0)

            switch ($ExpectedType) {
                'PE' { return $isPe }
                'MSI' { return $isMsi }
                'AnyBinary' { return ($isPe -or $isMsi) }
            }
        } finally {
            $stream.Dispose()
        }
    } catch {
        return $false
    }
}

function Download-Installer {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Destination,
        [ValidateSet('None','PE','MSI','AnyBinary')][string]$EnsureBinary = 'None',
        [switch]$ForceDownload,
        [string]$FallbackUrl
    )

    $userAgent = 'Mozilla/5.0 (Windows NT 10.0; TeamsVDI Installer)'

    foreach ($candidateUrl in @($Url, $FallbackUrl) | Where-Object { $_ }) {
        $useFallback = ($candidateUrl -ne $Url)

        if (-not $useFallback -and (Test-Path -Path $Destination) -and -not $ForceDownload) {
            if ($EnsureBinary -eq 'None' -or (Test-BinarySignature -Path $Destination -ExpectedType $EnsureBinary)) {
                Write-Step "Using cached copy: $Destination"
                return $Destination
            }

            Write-Step "Cached copy at $Destination failed validation. Re-downloading."
            Remove-Item -Path $Destination -ErrorAction SilentlyContinue
        }

        if ($useFallback) {
            Write-Step "Retrying download from CDN fallback: $candidateUrl"
        } else {
            Write-Step "Downloading from: $candidateUrl"
        }

        $headers = @{ 'User-Agent' = $userAgent }
        Invoke-WebRequest -Uri $candidateUrl -Headers $headers -UseBasicParsing -OutFile $Destination

        if ($EnsureBinary -eq 'None' -or (Test-BinarySignature -Path $Destination -ExpectedType $EnsureBinary)) {
            return $Destination
        }

        Remove-Item -Path $Destination -ErrorAction SilentlyContinue

        if ($useFallback) {
            break
        }
    }

    throw "Download from '$Url' (and fallback '$FallbackUrl') failed validation for expected type '$EnsureBinary'."
}

function Install-TeamsBootstrapper {
    param([Parameter(Mandatory)][string]$BootstrapperPath)

    Write-Step "Installing Teams (new) via bootstrapper"
    $arguments = '-p'
    $process = Start-Process -FilePath $BootstrapperPath -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -ne 0) {
        throw "Teams bootstrapper exited with code $($process.ExitCode)."
    }
}

function Install-WebRtcRedirector {
    param([Parameter(Mandatory)][string]$MsiPath)

    Write-Step 'Installing Remote Desktop WebRTC Redirector service'
    $arguments = @('/i', "`"$MsiPath`"", '/qn', '/norestart')
    $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -ne 0) {
        throw "WebRTC Redirector MSI exited with code $($process.ExitCode)."
    }
}

function Configure-TeamsForVDI {
    Write-Step 'Configuring Teams VDI registry keys'
    $teamsKey = 'HKLM:\SOFTWARE\Microsoft\Teams'
    if (-not (Test-Path -Path $teamsKey)) {
        New-Item -Path $teamsKey -Force | Out-Null
    }

    New-ItemProperty -Path $teamsKey -Name 'IsWVDEnvironment' -PropertyType DWord -Value 1 -Force | Out-Null
    New-ItemProperty -Path $teamsKey -Name 'MediaRedirectionEnabled' -PropertyType DWord -Value 1 -Force | Out-Null

    $service = Get-Service -Name 'WebSocketService' -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        if ($service.StartType -ne 'Automatic') {
            Set-Service -Name 'WebSocketService' -StartupType Automatic
        }
        if ($service.Status -ne 'Running') {
            Write-Step 'Starting WebSocketService'
            Start-Service -Name 'WebSocketService' -ErrorAction SilentlyContinue
        }
    } else {
        Write-Warning 'WebSocketService not detected. Ensure the Azure Virtual Desktop agent components are installed.'
    }
}

Ensure-Directory -Path $DownloadDirectory

$bootstrapperPath = Get-DownloadTarget -Url $TeamsBootstrapperUrl -Directory $DownloadDirectory -FallbackName 'TeamsBootstrapper.exe'
$bootstrapperPath = Download-Installer -Url $TeamsBootstrapperUrl -Destination $bootstrapperPath -EnsureBinary PE -ForceDownload:$Force -FallbackUrl 'https://statics.teams.cdn.office.net/production-windows-x64/teamsbootstrapper.exe'

$webRtcPath = Get-DownloadTarget -Url $WebRtcInstallerUrl -Directory $DownloadDirectory -FallbackName 'MsRdcWebRTCSvc.msi'
$webRtcPath = Download-Installer -Url $WebRtcInstallerUrl -Destination $webRtcPath -EnsureBinary MSI -ForceDownload:$Force

Install-TeamsBootstrapper -BootstrapperPath $bootstrapperPath
Install-WebRtcRedirector -MsiPath $webRtcPath
Configure-TeamsForVDI

Write-Step 'Teams installation and VDI configuration complete.'
