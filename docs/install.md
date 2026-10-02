# Install

## Prebuilt binaries

Each [GitHub Release](https://github.com/quanghle/bd-sync/releases) has an
archive per platform, holding `bd` (`bd.exe` on Windows) and this README, plus
a `SHA256SUMS` file and a signed build-provenance attestation for every archive:

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
tag=v0.1.0 target=x86_64-unknown-linux-musl     # a release tag and a target from the table
base=https://github.com/quanghle/bd-sync/releases/download/$tag
curl -fL -O "$base/bd-$tag-$target.tar.gz" -O "$base/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS   # macOS: shasum -a 256 --check --ignore-missing SHA256SUMS
gh attestation verify "bd-$tag-$target.tar.gz" --repo quanghle/bd-sync   # optional: built by this repo's release workflow
tar -xzf "bd-$tag-$target.tar.gz" bd
mkdir -p ~/.local/bin && mv bd ~/.local/bin/   # or any other directory on PATH
bd version
```

Windows (PowerShell):

```powershell
$tag = "v0.1.0"; $target = "x86_64-pc-windows-msvc"    # or aarch64-pc-windows-msvc
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

## From source

```bash
cargo install --path crates/bd-cli      # installs ~/.cargo/bin/bd
```

Either way the binary is named `bd`, so put its directory ahead of any Go
beads install on `PATH`, or
[migrate from Go beads](beads.md#migrating-from-go-beads) first. How releases are built,
checked and published: [RELEASING.md](../RELEASING.md).

Next: the [quick start](../README.md#quick-start), then [Concepts](concepts.md).
