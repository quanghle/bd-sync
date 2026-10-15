# Tests scripts/install.ps1 against a file:// fixture holding a real bd.exe.
#   ./scripts/test-install.ps1 -Binary target/release/bd.exe
# Runs install.ps1 in child processes under pwsh and, when present, Windows PowerShell 5.1.
param([Parameter(Mandatory)][string]$Binary)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$installer = Join-Path $here 'install.ps1'
$Binary = (Resolve-Path -LiteralPath $Binary).Path

$expected = (& $Binary --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or -not $expected) { throw "$Binary --version failed" }
if ($expected -notmatch '(\d+\.\d+\.\d+\S*)') { throw "cannot find a version in: $expected" }
$ver = $Matches[1]
$tag = "v$ver"

$arch = [string][Runtime.InteropServices.RuntimeInformation]::OSArchitecture
$target = if ($arch -eq 'Arm64') { 'aarch64-pc-windows-msvc' } else { 'x86_64-pc-windows-msvc' }

$work = Join-Path ([IO.Path]::GetTempPath()) ('bd-test-install-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null

$script:failures = 0
function Assert-That([bool]$Condition, [string]$Message) {
    if ($Condition) { Write-Host "ok   - $Message" } else { Write-Host "FAIL - $Message"; $script:failures++ }
}

# Six lines like a real release (one per release.yml target), sorted in byte order.
function Write-Sums([string]$Root, [string]$HostHash) {
    $names = @(
        "bd-$tag-aarch64-apple-darwin.tar.gz",
        "bd-$tag-aarch64-pc-windows-msvc.zip",
        "bd-$tag-aarch64-unknown-linux-musl.tar.gz",
        "bd-$tag-x86_64-apple-darwin.tar.gz",
        "bd-$tag-x86_64-pc-windows-msvc.zip",
        "bd-$tag-x86_64-unknown-linux-musl.tar.gz")
    [Array]::Sort($names, [StringComparer]::Ordinal)
    $i = 0
    $text = ''
    foreach ($n in $names) {
        $i++
        if ($n -ceq "bd-$tag-$target.zip") { $h = $HostHash } else { $h = ([string]$i) * 64 }
        $text += "$h  $n`n"
    }
    [IO.File]::WriteAllText((Join-Path $Root "download/$tag/SHA256SUMS"), $text)
    [IO.File]::WriteAllText((Join-Path $Root 'latest/download/SHA256SUMS'), $text)
}

function New-Fixture([string]$Root) {
    $dl = Join-Path $Root "download/$tag"
    New-Item -ItemType Directory -Force -Path $dl, (Join-Path $Root 'latest/download') | Out-Null
    $zipPath = Join-Path $dl "bd-$tag-$target.zip"
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::Open($zipPath, 'Create')
    try {
        [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $Binary, 'bd.exe') | Out-Null
    } finally {
        $zip.Dispose()
    }
    $hash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Sums $Root $hash
}

# Runs install.ps1 in a child process; returns its exit code.
function Invoke-Installer([string]$Shell, [string[]]$ShellArgs, [string]$Releases, [string]$Dir, [string[]]$ScriptArgs) {
    $env:BD_RELEASES_URL = $Releases
    $env:BD_ATTESTATION = 'skip'
    $env:BD_NO_MODIFY_PATH = '1'
    $env:BD_INSTALL_DIR = $Dir
    Remove-Item Env:BD_VERSION -ErrorAction SilentlyContinue
    & $Shell @ShellArgs -File $installer @ScriptArgs *> $null
    return $LASTEXITCODE
}

function Test-Shell([string]$Name, [string]$Shell, [string[]]$ShellArgs) {
    Write-Host "# install.ps1 under $Name"
    $root = Join-Path $work $Name
    $fixture = Join-Path $root 'releases'
    New-Fixture $fixture
    $url = ([Uri](Resolve-Path -LiteralPath $fixture).Path).AbsoluteUri

    # Latest.
    $dir = Join-Path $root 'bin-latest'
    $code = Invoke-Installer $Shell $ShellArgs $url $dir @()
    Assert-That ($code -eq 0) "$Name latest install exits 0"
    $got = if (Test-Path -LiteralPath (Join-Path $dir 'bd.exe')) { (& (Join-Path $dir 'bd.exe') --version | Out-String).Trim() } else { '' }
    Assert-That ($got -eq $expected) "$Name installed bd.exe reports '$expected'"

    # Explicit version, with and without the v.
    foreach ($v in @($tag, $ver)) {
        $dir = Join-Path $root "bin-$v"
        $code = Invoke-Installer $Shell $ShellArgs $url $dir @('-Version', $v)
        Assert-That ($code -eq 0) "$Name -Version $v exits 0"
        Assert-That (Test-Path -LiteralPath (Join-Path $dir 'bd.exe')) "$Name -Version $v installs bd.exe"
    }

    # A version that does not exist.
    $dir = Join-Path $root 'bin-missing'
    $code = Invoke-Installer $Shell $ShellArgs $url $dir @('-Version', '0.0.1')
    Assert-That ($code -ne 0) "$Name unknown version exits non-zero"
    Assert-That (-not (Test-Path -LiteralPath (Join-Path $dir 'bd.exe'))) "$Name unknown version installs nothing"

    # Reinstall over an existing bd.exe replaces it (the old one is renamed aside).
    $dir = Join-Path $root 'bin-latest'
    $code = Invoke-Installer $Shell $ShellArgs $url $dir @()
    Assert-That ($code -eq 0) "$Name reinstall over an existing bd.exe exits 0"

    # Tampered checksums: non-zero exit, existing bd.exe unchanged.
    $bad = Join-Path $root 'releases-bad'
    New-Fixture $bad
    Write-Sums $bad ('0' * 64)
    $badUrl = ([Uri](Resolve-Path -LiteralPath $bad).Path).AbsoluteUri
    $dir = Join-Path $root 'bin-tamper'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    [IO.File]::WriteAllText((Join-Path $dir 'bd.exe'), 'previous install')
    $before = (Get-FileHash -LiteralPath (Join-Path $dir 'bd.exe') -Algorithm SHA256).Hash
    $code = Invoke-Installer $Shell $ShellArgs $badUrl $dir @()
    Assert-That ($code -ne 0) "$Name tampered checksum exits non-zero"
    $after = (Get-FileHash -LiteralPath (Join-Path $dir 'bd.exe') -Algorithm SHA256).Hash
    Assert-That ($before -eq $after) "$Name tampered checksum leaves bd.exe unchanged"
    $code = Invoke-Installer $Shell $ShellArgs $badUrl (Join-Path $root 'bin-bad') @('-Version', $tag)
    Assert-That ($code -ne 0) "$Name tampered checksum with -Version exits non-zero"
    Assert-That (-not (Test-Path -LiteralPath (Join-Path $root 'bin-bad/bd.exe'))) "$Name tampered checksum installs nothing"
}

try {
    $pwshCmd = Get-Command pwsh -ErrorAction SilentlyContinue
    if ($pwshCmd) {
        Test-Shell 'pwsh' $pwshCmd.Source @('-NoProfile')
    }
    $winPs = Get-Command powershell.exe -ErrorAction SilentlyContinue
    if ($winPs) {
        Test-Shell 'powershell' $winPs.Source @('-NoProfile', '-ExecutionPolicy', 'Bypass')
    }
    if (-not $pwshCmd -and -not $winPs) { throw 'neither pwsh nor powershell.exe is on PATH' }
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:failures -gt 0) { throw "$($script:failures) install.ps1 test(s) failed" }
Write-Host 'install.ps1 tests passed'
# The last installer run failed on purpose: its $LASTEXITCODE must not
# become this script's exit code (GitHub's pwsh steps exit with it).
exit 0
