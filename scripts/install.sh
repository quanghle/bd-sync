#!/bin/sh
# Install bd from a GitHub release (Linux and macOS).
#
#   curl -fsSL https://raw.githubusercontent.com/quanghle/bd-sync/main/scripts/install.sh | sh
#   sh install.sh --version v0.3.0 --dir ~/bin
#
# Downloads the release archive for this machine, checks its SHA-256 against the
# release's SHA256SUMS (and its build attestation when gh is logged in), and
# installs bd into ~/.local/bin or $BD_INSTALL_DIR. It never uses sudo and never
# edits shell startup files. Windows: use install.ps1.
#
# Options:  --version TAG   release to install (default: the latest; v is optional)
#           --dir DIR       install directory (default: $BD_INSTALL_DIR or ~/.local/bin)
#           --repo O/N      GitHub repository (default: $BD_REPO or quanghle/bd-sync)
#           -h, --help      this help
# Env:      BD_VERSION, BD_INSTALL_DIR, BD_REPO, BD_RELEASES_URL (a mirror; file://
#           for tests), BD_ATTESTATION=auto|require|skip (default auto)
set -eu
umask 022

bd_tmp=
bd_cleanup() {
    if [ -n "$bd_tmp" ] && [ -d "$bd_tmp" ]; then
        rm -rf "$bd_tmp"
    fi
}
trap bd_cleanup EXIT
trap 'exit 1' INT TERM HUP

die() {
    printf 'install.sh: %s\n' "$*" >&2
    exit 1
}

say() {
    printf '%s\n' "$*"
}

usage() {
    cat <<'USAGE'
Usage: install.sh [--version TAG] [--dir DIR] [--repo OWNER/NAME]

Installs bd from a GitHub release into DIR (default: $BD_INSTALL_DIR or ~/.local/bin).
  --version TAG   release to install (default: the latest; the v is optional)
  --repo O/N      GitHub repository (default: $BD_REPO or quanghle/bd-sync)
Env: BD_VERSION, BD_INSTALL_DIR, BD_REPO, BD_RELEASES_URL (a mirror),
     BD_ATTESTATION=auto|require|skip (default auto)
USAGE
}

# Prints the release target for this machine.
detect_target() {
    dt_os=$(uname -s)
    dt_arch=$(uname -m)
    case "$dt_os" in
    Linux)
        case "$dt_arch" in
        x86_64 | amd64) say x86_64-unknown-linux-musl ;;
        aarch64 | arm64) say aarch64-unknown-linux-musl ;;
        *) die "unsupported Linux architecture: $dt_arch" ;;
        esac
        ;;
    Darwin)
        case "$dt_arch" in
        arm64) say aarch64-apple-darwin ;;
        x86_64)
            # An Intel shell under Rosetta on Apple silicon still wants the native build.
            if [ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then
                say aarch64-apple-darwin
            else
                say x86_64-apple-darwin
            fi
            ;;
        *) die "unsupported macOS architecture: $dt_arch" ;;
        esac
        ;;
    MINGW* | MSYS* | CYGWIN*)
        die "this is a Windows shell: use scripts/install.ps1 from PowerShell (irm https://raw.githubusercontent.com/quanghle/bd-sync/main/scripts/install.ps1 | iex)"
        ;;
    *)
        die "unsupported OS: $dt_os (install.sh supports Linux and macOS; see docs/install.md to build from source)"
        ;;
    esac
}

# download URL FILE
download() {
    dl_url=$1
    dl_out=$2
    case "$bd_base" in
    file://*)
        command -v curl >/dev/null 2>&1 || die "a file:// mirror needs curl"
        curl -fsSL "$dl_url" -o "$dl_out" || die "cannot fetch $dl_url"
        ;;
    *)
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL --proto =https --tlsv1.2 "$dl_url" -o "$dl_out" || die "cannot fetch $dl_url"
        elif command -v wget >/dev/null 2>&1; then
            wget -q --https-only -O "$dl_out" "$dl_url" || die "cannot fetch $dl_url"
        else
            die "curl or wget is required"
        fi
        ;;
    esac
}

# Prints the lowercase SHA-256 of FILE.
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print tolower($1)}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print tolower($1)}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | awk '{print tolower($NF)}'
    else
        die "sha256sum, shasum or openssl is required to verify the download"
    fi
}

# gh attestation verify ARCHIVE, per BD_ATTESTATION.
verify_attestation() {
    va_mode=${BD_ATTESTATION:-auto}
    case "$va_mode" in
    skip) return 0 ;;
    auto | require) ;;
    *) die "BD_ATTESTATION must be auto, require or skip (got: $va_mode)" ;;
    esac
    va_ready=1
    if ! command -v gh >/dev/null 2>&1; then
        va_ready=0
        va_why="gh is not installed"
    elif ! gh auth status >/dev/null 2>&1; then
        va_ready=0
        va_why="gh is not logged in"
    fi
    if [ "$va_ready" = 0 ]; then
        if [ "$va_mode" = require ]; then
            die "attestation required but $va_why"
        fi
        say "Skipping attestation check ($va_why); the SHA-256 check passed."
        return 0
    fi
    say "Verifying build attestation with gh..."
    gh attestation verify "$1" --repo "$bd_repo" \
        --signer-workflow "$bd_repo/.github/workflows/release.yml" >/dev/null ||
        die "attestation verification failed; nothing was installed"
}

main() {
    m_version=${BD_VERSION:-}
    m_dir=${BD_INSTALL_DIR:-}
    bd_repo=${BD_REPO:-quanghle/bd-sync}
    while [ $# -gt 0 ]; do
        case "$1" in
        --version | --dir | --repo)
            [ $# -ge 2 ] || die "$1 needs a value"
            case "$1" in
            --version) m_version=$2 ;;
            --dir) m_dir=$2 ;;
            --repo) bd_repo=$2 ;;
            esac
            shift 2
            ;;
        --version=*) m_version=${1#--version=}; shift ;;
        --dir=*) m_dir=${1#--dir=}; shift ;;
        --repo=*) bd_repo=${1#--repo=}; shift ;;
        -h | --help) usage; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
        esac
    done

    if ! printf '%s\n' "$bd_repo" | grep -Eq '^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$'; then
        die "invalid repository: $bd_repo (expected OWNER/NAME)"
    fi
    m_tag=
    if [ -n "$m_version" ]; then
        case "$m_version" in v*) m_tag=$m_version ;; *) m_tag=v$m_version ;; esac
        if ! printf '%s\n' "$m_tag" |
            grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'; then
            die "invalid version: $m_version (expected like 0.3.0 or v0.3.0-rc.1)"
        fi
    fi
    if [ -z "$m_dir" ]; then
        [ -n "${HOME:-}" ] || die "HOME is not set; pass --dir or set BD_INSTALL_DIR"
        m_dir=$HOME/.local/bin
    fi

    bd_base=${BD_RELEASES_URL:-https://github.com/$bd_repo/releases}
    bd_base=${bd_base%/}
    m_target=$(detect_target)

    bd_tmp=$(mktemp -d "${TMPDIR:-/tmp}/bd-install.XXXXXX") || die "cannot create a temporary directory"

    # The checksum list names the asset, and for the latest release, the tag.
    if [ -z "$m_tag" ]; then
        say "Looking up the latest release..."
        download "$bd_base/latest/download/SHA256SUMS" "$bd_tmp/SHA256SUMS"
        m_names=$(awk -v t="$m_target" '
            { n = $2; sub(/^\*/, "", n) }
            n ~ ("^bd-v[0-9A-Za-z.+-]+-" t "\\.tar\\.gz$") { print n }' "$bd_tmp/SHA256SUMS")
        m_count=$(printf '%s\n' "$m_names" | grep -c . || true)
        [ "$m_count" = 1 ] || die "expected exactly one bd-v*-$m_target.tar.gz in the latest SHA256SUMS, found $m_count"
        m_asset=$m_names
        m_tag=${m_asset#bd-}
        m_tag=${m_tag%-"$m_target".tar.gz}
        printf '%s\n' "$m_tag" |
            grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$' ||
            die "unexpected release tag in SHA256SUMS: $m_tag"
    else
        download "$bd_base/download/$m_tag/SHA256SUMS" "$bd_tmp/SHA256SUMS"
        m_asset=bd-$m_tag-$m_target.tar.gz
    fi

    m_want=$(awk -v a="$m_asset" '
        { n = $2; sub(/^\*/, "", n) }
        n == a { print tolower($1) }' "$bd_tmp/SHA256SUMS")
    m_count=$(printf '%s\n' "$m_want" | grep -c . || true)
    [ "$m_count" = 1 ] || die "$m_asset is not listed exactly once in SHA256SUMS for $m_tag"
    printf '%s\n' "$m_want" | grep -Eq '^[0-9a-f]{64}$' || die "malformed checksum for $m_asset in SHA256SUMS"

    say "Installing bd $m_tag ($m_target)..."
    download "$bd_base/download/$m_tag/$m_asset" "$bd_tmp/$m_asset"
    m_got=$(sha256_of "$bd_tmp/$m_asset")
    if [ "$m_got" != "$m_want" ]; then
        die "checksum mismatch for $m_asset (expected $m_want, got $m_got); nothing was installed"
    fi
    say "SHA-256 verified."
    verify_attestation "$bd_tmp/$m_asset"

    mkdir "$bd_tmp/x"
    tar -xzf "$bd_tmp/$m_asset" -C "$bd_tmp/x" bd || die "cannot extract bd from $m_asset"
    [ -f "$bd_tmp/x/bd" ] && [ ! -L "$bd_tmp/x/bd" ] || die "$m_asset does not hold a regular file named bd"

    mkdir -p "$m_dir" 2>/dev/null || die "cannot create $m_dir; set BD_INSTALL_DIR (or pass --dir) to a directory you can write"
    [ -d "$m_dir" ] && [ -w "$m_dir" ] || die "$m_dir is not writable; set BD_INSTALL_DIR (or pass --dir) to a directory you can write"
    m_stage=$m_dir/.bd.tmp.$$
    # Clean up the staged copy if anything below fails.
    if ! { cp "$bd_tmp/x/bd" "$m_stage" && chmod 0755 "$m_stage" && mv -f "$m_stage" "$m_dir/bd"; }; then
        rm -f "$m_stage"
        die "cannot install into $m_dir"
    fi

    m_out=$("$m_dir/bd" --version) || die "installed $m_dir/bd but it failed to run"
    say "Installed $m_out to $m_dir/bd"
    case ":$PATH:" in
    *":$m_dir:"*) ;;
    *) say "Note: $m_dir is not on your PATH. Add it, for example: export PATH=\"$m_dir:\$PATH\"" ;;
    esac
}

main "$@"
