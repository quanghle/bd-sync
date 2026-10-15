# Install

## Install script

The scripts download the archive for this machine from a release, check its
SHA-256 against the release's `SHA256SUMS`, and install `bd`.

Linux and macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/quanghle/bd-sync/main/scripts/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/quanghle/bd-sync/main/scripts/install.ps1 | iex
```

To read the script before running it, download it first:

```bash
curl -fsSL -o install.sh https://raw.githubusercontent.com/quanghle/bd-sync/main/scripts/install.sh
less install.sh
sh install.sh
```

```powershell
irm https://raw.githubusercontent.com/quanghle/bd-sync/main/scripts/install.ps1 -OutFile install.ps1
Get-Content install.ps1 | more
./install.ps1
```

Without a version the latest release is installed. To pin one:

```bash
curl -fsSL https://raw.githubusercontent.com/quanghle/bd-sync/main/scripts/install.sh | sh -s -- --version v0.3.0
```

```powershell
$env:BD_VERSION = "v0.3.0"; irm https://raw.githubusercontent.com/quanghle/bd-sync/main/scripts/install.ps1 | iex
```

A release's notes carry the same commands with the script pinned to the
release's tag.

| `install.sh` option | `install.ps1` parameter | Environment | Meaning |
|---|---|---|---|
| `--version TAG` | `-Version TAG` | `BD_VERSION` | Release to install (the `v` is optional); default: the latest. |
| `--dir DIR` | `-InstallDir DIR` | `BD_INSTALL_DIR` | Install directory; default `~/.local/bin`, on Windows `%LOCALAPPDATA%\Programs\bd`. |
| `--repo OWNER/NAME` | | `BD_REPO` | Repository to download from; default `quanghle/bd-sync`. |
| | `-NoModifyPath` | `BD_NO_MODIFY_PATH=1` | Windows only: leave the user `PATH` alone. |
| | | `BD_ATTESTATION` | `auto` (default), `require` or `skip`, see below. |
| | | `BD_RELEASES_URL` | A mirror of the releases URL (`file://` works on Linux, macOS and Windows with curl or PowerShell; used by the tests). |

What is verified: the archive's SHA-256 is always checked against the
release's `SHA256SUMS`, and a mismatch (or a missing line) stops the install
before anything is written to the install directory. With `BD_ATTESTATION=auto`
the build-provenance attestation is also checked with
`gh attestation verify` when `gh` is installed and logged in, and a failed check
aborts. `require` fails if `gh` is missing or not logged in; `skip` skips the
check. The `SHA256SUMS` file and the archive come from the same release over
HTTPS, so the checksum catches corrupt or partial downloads; the attestation is
what ties the archive to this repository's release workflow.

Where it installs: `install.sh` puts `bd` in `~/.local/bin` (or `--dir`), never
uses `sudo` and never edits shell startup files; if the directory is not on
`PATH` it prints a hint. `install.ps1` installs to `%LOCALAPPDATA%\Programs\bd`,
adds that directory to the user `PATH` (not the machine one; no elevation)
unless `-NoModifyPath` is given, and replaces a running `bd.exe` by renaming it
to `bd.exe.old`. Both finish by running `bd --version`.

## Prebuilt binaries

Each [release](https://github.com/quanghle/bd-sync/releases) has an archive
per platform, holding `bd` (`bd.exe` on Windows), the README, this `docs/`
directory, the license and, from the first release whose `bd` has
`bd completion`, a `completions/` directory, plus a `SHA256SUMS` file and a signed
build-provenance attestation for every archive:

| Platform | Archive |
|---|---|
| Linux x86_64 (static, any distro) | `bd-<tag>-x86_64-unknown-linux-musl.tar.gz` |
| Linux arm64 (static, any distro) | `bd-<tag>-aarch64-unknown-linux-musl.tar.gz` |
| macOS Apple silicon (11+) | `bd-<tag>-aarch64-apple-darwin.tar.gz` |
| macOS Intel (11+) | `bd-<tag>-x86_64-apple-darwin.tar.gz` |
| Windows x86_64 | `bd-<tag>-x86_64-pc-windows-msvc.zip` |
| Windows arm64 | `bd-<tag>-aarch64-pc-windows-msvc.zip` |

Linux and macOS:

```bash
tag=v0.2.0 target=x86_64-unknown-linux-musl     # a release tag and a target from the table
base=https://github.com/quanghle/bd-sync/releases/download/$tag
curl -fL -O "$base/bd-$tag-$target.tar.gz" -O "$base/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS   # macOS: shasum -a 256 --check --ignore-missing SHA256SUMS
gh attestation verify "bd-$tag-$target.tar.gz" --repo quanghle/bd-sync   # optional: built by this repo's release workflow
tar -xzf "bd-$tag-$target.tar.gz" bd
mkdir -p ~/.local/bin && mv bd ~/.local/bin/   # or any other directory on PATH
bd --version
```

Windows (PowerShell):

```powershell
$tag = "v0.2.0"; $target = "x86_64-pc-windows-msvc"    # or aarch64-pc-windows-msvc
$base = "https://github.com/quanghle/bd-sync/releases/download/$tag"
Invoke-WebRequest "$base/bd-$tag-$target.zip" -OutFile "bd-$tag-$target.zip"
Invoke-WebRequest "$base/SHA256SUMS" -OutFile SHA256SUMS
(Get-FileHash "bd-$tag-$target.zip" -Algorithm SHA256).Hash   # must match its line in SHA256SUMS
Expand-Archive "bd-$tag-$target.zip" -DestinationPath "$env:LOCALAPPDATA\Programs\bd"
# then add $env:LOCALAPPDATA\Programs\bd to your user PATH and open a new terminal
```

The Windows binaries link the C runtime statically, so no Visual C++
redistributable is needed. The macOS binaries are not notarized: if a browser
download is blocked by Gatekeeper, run `xattr -d com.apple.quarantine bd`
(downloads with `curl` are not quarantined).

## Shell completions

From the first release whose `bd` has the `bd completion` command, each
archive holds a `completions/` directory with `bd.bash`, `_bd` (zsh),
`bd.fish` and `_bd.ps1`, generated by the shipped binary. The install scripts
do not install them; copy the one for your shell (or, in any release with the
command, run `bd completion <shell>` yourself):

```bash
# bash
mkdir -p ~/.local/share/bash-completion/completions && cp completions/bd.bash ~/.local/share/bash-completion/completions/bd
# zsh: any directory on $fpath, before compinit
mkdir -p ~/.zfunc && cp completions/_bd ~/.zfunc/_bd      # fpath=(~/.zfunc $fpath)
# fish
cp completions/bd.fish ~/.config/fish/completions/bd.fish
```

```powershell
# PowerShell: load it from your profile
Add-Content $PROFILE '. "C:\path\to\completions\_bd.ps1"'
```

## Package managers

Homebrew, winget and npm packaging (a formula, manifests and per-platform
npm packages) is rendered for every release by the release workflow, but it
is not published to a tap, winget-pkgs or the npm registry yet. Use the
install script or the archives above. How the packaging is rendered, and
regenerated for any release: [RELEASING.md](../RELEASING.md#packaging-homebrew-winget-npm).

## From source

```bash
cargo install --path crates/bd          # installs ~/.cargo/bin/bd
```

Either way the binary is named `bd`; if another `bd` is installed, put this
one's directory first on `PATH` (coming from beads: see
[Migrating](beads.md#migrating-from-go-beads)). How releases are built,
checked and published: [RELEASING.md](../RELEASING.md).

## Shell completions

`bd completion <shell>` prints a completion script for bash, zsh, fish,
PowerShell or elvish, generated from bd's command grammar: subcommands, flags
and fixed values complete (issue ids do not). It needs no workspace. Install it
once per shell, and again after upgrading bd:

| Shell | Install |
|---|---|
| bash | `bd completion bash > ~/.local/share/bash-completion/completions/bd` (needs the bash-completion package) |
| zsh | `bd completion zsh > ~/.zfunc/_bd`, with `fpath+=~/.zfunc; autoload -Uz compinit && compinit` in `~/.zshrc` |
| fish | `bd completion fish > ~/.config/fish/completions/bd.fish` |
| PowerShell | add `bd completion powershell \| Out-String \| Invoke-Expression` to `$PROFILE` |
| elvish | `bd completion elvish > ~/.config/elvish/lib/bd.elv`, with `use bd` in `~/.config/elvish/rc.elv` |

Create the target directory first if it does not exist (`mkdir -p
~/.zfunc`, and so on). For zsh, the `fpath` line goes before `compinit` runs;
frameworks such as oh-my-zsh run `compinit` themselves, so there only the
`fpath` line is needed, before the framework is loaded. Start a new shell to
load the script.

Next: the [quick start](../README.md#quick-start), then [Concepts](concepts.md).
