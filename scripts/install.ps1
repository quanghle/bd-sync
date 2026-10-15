# Install bd from a GitHub release (Windows, PowerShell 5.1 and 7).
#
#   irm https://raw.githubusercontent.com/quanghle/bd-sync/main/scripts/install.ps1 | iex
#   .\install.ps1 -Version v0.3.0 -InstallDir C:\tools\bd
#
# Downloads the release zip for this machine, checks its SHA-256 against the
# release's SHA256SUMS (and its build attestation when gh is logged in), and
# installs bd.exe into %LOCALAPPDATA%\Programs\bd or $env:BD_INSTALL_DIR. It adds
# that directory to your user PATH (not the machine PATH) unless told not to, and
# never asks for elevation. Linux and macOS: use install.sh.
#
# Parameters: -Version TAG      release to install (default: the latest; v is optional)
#             -InstallDir DIR   install directory
#             -NoModifyPath     leave the user PATH alone
# Env:        BD_VERSION, BD_INSTALL_DIR, BD_REPO (default quanghle/bd-sync),
#             BD_RELEASES_URL (a mirror; file:// for tests),
#             BD_ATTESTATION=auto|require|skip (default auto), BD_NO_MODIFY_PATH=1
#
# Errors are thrown, never `exit`ed, so `irm | iex` does not close your shell.
param(
    [string]$Version,
    [string]$InstallDir,
    [switch]$NoModifyPath
)

# Windows PowerShell 5.1 negotiates TLS 1.0/1.1 by default; GitHub needs 1.2.
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    # Not available on this platform; PowerShell 7 negotiates TLS itself.
    $null = $_
}

function Get-BdFile {
    param([string]$Url, [string]$OutFile)
    try {
        if ($Url -like 'file://*') {
            # Invoke-WebRequest does not reliably read file:// URIs on PowerShell 7.
            Copy-Item -LiteralPath ([Uri]$Url).LocalPath -Destination $OutFile -Force
        } else {
            Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $OutFile | Out-Null
        }
    } catch {
        throw "install.ps1: cannot fetch ${Url}: $($_.Exception.Message)"
    }
}

function Get-BdTarget {
    $arch = $null
    try {
        $arch = [string][Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    } catch {
        $arch = $null
    }
    if (-not $arch) {
        # An x86 PowerShell on a 64-bit OS reports its own architecture here.
        $arch = $env:PROCESSOR_ARCHITEW6432
        if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    }
    switch -Regex ($arch) {
        '^(X64|AMD64)$' { return 'x86_64-pc-windows-msvc' }
        '^ARM64$' { return 'aarch64-pc-windows-msvc' }
        default { throw "install.ps1: unsupported architecture: $arch (bd has x64 and arm64 builds for Windows)" }
    }
}

# Parses SHA256SUMS lines ("<hash>  <name>", a leading * on the name allowed).
function Read-BdSums {
    param([string]$Path)
    $rows = @()
    foreach ($line in (Get-Content -LiteralPath $Path)) {
        if ($line -match '^([0-9A-Fa-f]{64}) [ *]?(\S+)\s*$') {
            $rows += [pscustomobject]@{ Hash = $Matches[1].ToLowerInvariant(); Name = $Matches[2] }
        }
    }
    return $rows
}

function Test-BdAttestation {
    param([string]$Archive, [string]$Repo, [string]$Mode)
    if ($Mode -eq 'skip') { return }
    if ($Mode -ne 'auto' -and $Mode -ne 'require') {
        throw "install.ps1: BD_ATTESTATION must be auto, require or skip (got: $Mode)"
    }
    $why = $null
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        $why = 'gh is not installed'
    } else {
        # gh writes to stderr; do not let that turn into a terminating error on 5.1.
        $saved = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            & gh auth status *> $null
            if ($LASTEXITCODE -ne 0) { $why = 'gh is not logged in' }
        } finally {
            $ErrorActionPreference = $saved
        }
    }
    if ($why) {
        if ($Mode -eq 'require') { throw "install.ps1: attestation required but $why" }
        Write-Host "Skipping attestation check ($why); the SHA-256 check passed."
        return
    }
    Write-Host 'Verifying build attestation with gh...'
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & gh attestation verify $Archive --repo $Repo --signer-workflow "$Repo/.github/workflows/release.yml" *> $null
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $saved
    }
    if ($code -ne 0) { throw 'install.ps1: attestation verification failed; nothing was installed' }
}

function Install-Bd {
    param([string]$Version, [string]$InstallDir, [bool]$SkipPath)

    # Under `irm | iex` this runs in the caller's scope: put the preferences back after.
    $savedEap = $ErrorActionPreference
    $savedProgress = $ProgressPreference
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    try {
        Install-BdCore -Version $Version -InstallDir $InstallDir -SkipPath $SkipPath
    } finally {
        $ErrorActionPreference = $savedEap
        $ProgressPreference = $savedProgress
    }
}

function Install-BdCore {
    param([string]$Version, [string]$InstallDir, [bool]$SkipPath)

    if (-not $Version) { $Version = $env:BD_VERSION }
    if (-not $InstallDir) { $InstallDir = $env:BD_INSTALL_DIR }
    if (-not $InstallDir) {
        if (-not $env:LOCALAPPDATA) { throw 'install.ps1: LOCALAPPDATA is not set; pass -InstallDir or set BD_INSTALL_DIR' }
        $InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\bd'
    }
    if ($env:BD_NO_MODIFY_PATH -eq '1') { $SkipPath = $true }
    $repo = $env:BD_REPO
    if (-not $repo) { $repo = 'quanghle/bd-sync' }
    if ($repo -cnotmatch '^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$') {
        throw "install.ps1: invalid repository: $repo (expected OWNER/NAME)"
    }
    $mode = $env:BD_ATTESTATION
    if (-not $mode) { $mode = 'auto' }

    $semver = '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
    $tag = $null
    if ($Version) {
        $tag = $Version
        if (-not $tag.StartsWith('v')) { $tag = "v$tag" }
        if ($tag -cnotmatch $semver) {
            throw "install.ps1: invalid version: $Version (expected like 0.3.0 or v0.3.0-rc.1)"
        }
    }

    $base = $env:BD_RELEASES_URL
    if (-not $base) { $base = "https://github.com/$repo/releases" }
    $base = $base.TrimEnd('/')
    $target = Get-BdTarget

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('bd-install-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        $sumsFile = Join-Path $tmp 'SHA256SUMS'
        if (-not $tag) {
            Write-Host 'Looking up the latest release...'
            Get-BdFile "$base/latest/download/SHA256SUMS" $sumsFile
            $pattern = '^bd-(v[0-9A-Za-z.+-]+)-' + [regex]::Escape($target) + '\.zip$'
            $found = @(Read-BdSums $sumsFile | Where-Object { $_.Name -cmatch $pattern })
            if ($found.Count -ne 1) {
                throw "install.ps1: expected exactly one bd-v*-$target.zip in the latest SHA256SUMS, found $($found.Count)"
            }
            $null = $found[0].Name -cmatch $pattern
            $tag = $Matches[1]
            if ($tag -cnotmatch $semver) { throw "install.ps1: unexpected release tag in SHA256SUMS: $tag" }
        } else {
            Get-BdFile "$base/download/$tag/SHA256SUMS" $sumsFile
        }

        $asset = "bd-$tag-$target.zip"
        $found = @(Read-BdSums $sumsFile | Where-Object { $_.Name -ceq $asset })
        if ($found.Count -ne 1) { throw "install.ps1: $asset is not listed exactly once in SHA256SUMS for $tag" }
        $want = $found[0].Hash

        Write-Host "Installing bd $tag ($target)..."
        $archive = Join-Path $tmp $asset
        Get-BdFile "$base/download/$tag/$asset" $archive
        $got = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($got -ne $want) {
            throw "install.ps1: checksum mismatch for $asset (expected $want, got $got); nothing was installed"
        }
        Write-Host 'SHA-256 verified.'
        Test-BdAttestation -Archive $archive -Repo $repo -Mode $mode

        # Extract only the bd.exe entry, never trusting other names in the archive.
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $newExe = Join-Path $tmp 'bd.exe'
        $zip = [IO.Compression.ZipFile]::OpenRead($archive)
        try {
            $entry = $zip.Entries | Where-Object { $_.FullName -ceq 'bd.exe' } | Select-Object -First 1
            if (-not $entry) { throw "install.ps1: $asset does not hold bd.exe at its root" }
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $newExe, $true)
        } finally {
            $zip.Dispose()
        }

        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
        $dest = Join-Path $InstallDir 'bd.exe'
        if (Test-Path -LiteralPath $dest) {
            # A running bd.exe cannot be overwritten, but it can be renamed.
            $old = "$dest.old"
            try { Remove-Item -LiteralPath $old -Force -ErrorAction Stop } catch { $null = $_ }
            try {
                Move-Item -LiteralPath $dest -Destination $old -Force
            } catch {
                throw "install.ps1: cannot replace $dest (is bd running?): $($_.Exception.Message)"
            }
        }
        try {
            Move-Item -LiteralPath $newExe -Destination $dest -Force
        } catch {
            # Put the previous binary back so a failed install leaves things as they were.
            if (Test-Path -LiteralPath "$dest.old") {
                try { Move-Item -LiteralPath "$dest.old" -Destination $dest -Force } catch { $null = $_ }
            }
            throw "install.ps1: cannot install into ${InstallDir}: $($_.Exception.Message)"
        }

        $out = & $dest --version
        if ($LASTEXITCODE -ne 0) { throw "install.ps1: installed $dest but it failed to run" }
        Write-Host "Installed $out to $dest"

        if (-not $SkipPath) {
            $trimmed = $InstallDir.TrimEnd('\')
            $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
            if (-not $key) { $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment') }
            $changed = $false
            try {
                # Raw read and ExpandString write keep %VAR% entries unexpanded.
                $userPath = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $parts = @()
                if ($userPath) { $parts = $userPath.Split(';') | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') } }
                if ($parts -notcontains $trimmed) {
                    $joined = $trimmed
                    if ($userPath) { $joined = $userPath.TrimEnd(';') + ';' + $trimmed }
                    $key.SetValue('Path', $joined, [Microsoft.Win32.RegistryValueKind]::ExpandString)
                    $changed = $true
                }
            } finally {
                $key.Close()
            }
            if ($changed) {
                # Setting and clearing a user variable broadcasts WM_SETTINGCHANGE.
                try {
                    [Environment]::SetEnvironmentVariable('BD_INSTALL_PATH_REFRESH', '1', 'User')
                    [Environment]::SetEnvironmentVariable('BD_INSTALL_PATH_REFRESH', $null, 'User')
                } catch { $null = $_ }
                Write-Host "Added $trimmed to your user PATH. Open a new terminal to use bd."
            }
            $sessionParts = @($env:Path.Split(';') | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') })
            if ($sessionParts -notcontains $trimmed) { $env:Path = $env:Path.TrimEnd(';') + ';' + $trimmed }
        }
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Install-Bd -Version $Version -InstallDir $InstallDir -SkipPath ([bool]$NoModifyPath)
