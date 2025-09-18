<#
.SYNOPSIS
Downloads and installs the Microsoft Teams (new) client using the Teams bootstrapper.

.DESCRIPTION
Fetches the Teams bootstrapper executable from Microsoft's evergreen link and runs it with provisioning enabled so Teams is installed for all users on the host. Intended for use on Azure Virtual Desktop session hosts or other managed images.

.EXAMPLE
PS C:\> .\Install-Teams-VDI.ps1
Downloads the Teams bootstrapper (if not already cached) and installs Teams (new).
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TeamsBootstrapperUrl = 'https://go.microsoft.com/fwlink/?linkid=2243204',

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
    # Ignore if TLS selection is unavailable.
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

function Get-BootstrapperPath {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Directory
    )

    $fileName = [System.IO.Path]::GetFileName([System.Uri]$Url)
    if ([string]::IsNullOrWhiteSpace($fileName) -or ($fileName -notmatch '\.')) {
        $fileName = 'TeamsBootstrapper.exe'
    }

    return [System.IO.Path]::Combine($Directory, $fileName)
}

function Download-Bootstrapper {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Destination,
        [switch]$ForceDownload
    )

    if ((Test-Path -Path $Destination) -and -not $ForceDownload) {
        Write-Step "Using cached bootstrapper: $Destination"
        return $Destination
    }

    Write-Step "Downloading Teams bootstrapper from $Url"
    $headers = @{ 'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; TeamsBootstrapper Script)' }
    Invoke-WebRequest -Uri $Url -Headers $headers -UseBasicParsing -OutFile $Destination

    return $Destination
}

function Install-Teams {
    param([Parameter(Mandatory)][string]$BootstrapperPath)

    Write-Step "Executing Teams bootstrapper"
    $process = Start-Process -FilePath $BootstrapperPath -ArgumentList '-p' -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -ne 0) {
        throw "Teams bootstrapper exited with code $($process.ExitCode)."
    }
}

function Configure-TeamsForVDI {
    Write-Step 'Applying Teams VDI optimizations'
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

$bootstrapperPath = Get-BootstrapperPath -Url $TeamsBootstrapperUrl -Directory $DownloadDirectory
$bootstrapperPath = Download-Bootstrapper -Url $TeamsBootstrapperUrl -Destination $bootstrapperPath -ForceDownload:$Force

Install-Teams -BootstrapperPath $bootstrapperPath
Configure-TeamsForVDI

Write-Step 'Teams installation and VDI optimization complete.'
