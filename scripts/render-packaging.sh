#!/usr/bin/env bash
# Render the Homebrew, winget and npm packaging templates in packaging/ for a release.
# Nothing is published: the output is files for a maintainer (or a workflow artifact).
#
#   scripts/render-packaging.sh --version 0.3.0 --tag v0.3.0 --dist DIR --out DIR \
#       [--repo OWNER/NAME] [--npm-scope @scope]
#
# DIR (--dist) holds the release's SHA256SUMS and its six archives. Every archive is
# verified against SHA256SUMS before a binary is copied into an npm package.
# Output: OUT/homebrew/bd.rb, OUT/winget/manifests/<l>/<owner>/bd/<version>/*.yaml,
# OUT/npm/bd and OUT/npm/bd-<os>-<cpu>/.
# Written for bash 3.2 (macOS).
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)

# target:npm-os:npm-cpu:extension, the one list. Must equal the build matrix of release.yml
# (scripts/test-packaging.sh checks).
TARGETS="x86_64-unknown-linux-musl:linux:x64:tar.gz
aarch64-unknown-linux-musl:linux:arm64:tar.gz
x86_64-apple-darwin:darwin:x64:tar.gz
aarch64-apple-darwin:darwin:arm64:tar.gz
x86_64-pc-windows-msvc:win32:x64:zip
aarch64-pc-windows-msvc:win32:arm64:zip"

die() {
    echo "render-packaging: $*" >&2
    exit 1
}

usage() {
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
}

version=
tag=
dist=
out=
repo=${GITHUB_REPOSITORY:-quanghle/bd-sync}
scope=
templates=$ROOT/packaging

while [ $# -gt 0 ]; do
    case "$1" in
    --version | --tag | --dist | --out | --repo | --npm-scope | --templates)
        [ $# -ge 2 ] || die "$1 needs a value"
        case "$1" in
        --version) version=$2 ;;
        --tag) tag=$2 ;;
        --dist) dist=$2 ;;
        --out) out=$2 ;;
        --repo) repo=$2 ;;
        --npm-scope) scope=$2 ;;
        --templates) templates=$2 ;;
        esac
        shift 2
        ;;
    -h | --help)
        usage
        exit 0
        ;;
    *) die "unknown option: $1" ;;
    esac
done

[ -n "$version" ] || die "--version is required"
[ -n "$tag" ] || die "--tag is required"
[ -n "$dist" ] || die "--dist is required"
[ -n "$out" ] || die "--out is required"

# Strict validation: the values go into sed and into file names.
semver='(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?'
printf '%s\n' "$version" | grep -Eq "^$semver\$" || die "invalid --version: $version"
printf '%s\n' "$tag" | grep -Eq "^v$semver\$" || die "invalid --tag: $tag"
case "$tag" in
"v$version" | "v$version"-*) ;;
*) die "--tag $tag does not belong to --version $version" ;;
esac
printf '%s\n' "$repo" | grep -Eq '^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$' || die "invalid --repo: $repo"
owner=${repo%%/*}
if [ -z "$scope" ]; then
    scope=@$(printf '%s' "$owner" | tr 'A-Z' 'a-z')
fi
printf '%s\n' "$scope" | grep -Eq '^@[a-z0-9][a-z0-9._-]*$' || die "invalid --npm-scope: $scope"
[ -d "$dist" ] || die "--dist is not a directory: $dist"
[ -f "$dist/SHA256SUMS" ] || die "$dist/SHA256SUMS not found"
[ -d "$templates" ] || die "--templates is not a directory: $templates"
for f in homebrew/bd.rb winget/bd.yaml winget/bd.installer.yaml winget/bd.locale.en-US.yaml \
    npm/bd/package.json npm/bd/bin/bd.js npm/platform/package.json; do
    [ -f "$templates/$f" ] || die "template missing: $templates/$f"
done

sha256_check() {
    # sha256_check FILE EXPECTED
    local got
    if command -v sha256sum >/dev/null 2>&1; then
        got=$(sha256sum "$1" | awk '{print $1}')
    else
        got=$(shasum -a 256 "$1" | awk '{print $1}')
    fi
    [ "$got" = "$2" ]
}

# Hashes from SHA256SUMS: exactly one line per expected archive, 64 lowercase hex.
SEDARGS=
for entry in $TARGETS; do
    IFS=: read -r target os cpu ext <<<"$entry"
    name=bd-$tag-$target.$ext
    lines=$(awk -v n="$name" '{ f = $2; sub(/^\*/, "", f); if (f == n) print $1 }' "$dist/SHA256SUMS")
    count=$(printf '%s' "$lines" | grep -c . || true)
    [ "$count" = 1 ] || die "SHA256SUMS must name $name exactly once (found $count)"
    printf '%s\n' "$lines" | grep -Eq '^[0-9a-f]{64}$' || die "malformed checksum for $name in SHA256SUMS"
    [ -f "$dist/$name" ] || die "$dist/$name not found (all six archives are required)"
    sha256_check "$dist/$name" "$lines" || die "$name does not match SHA256SUMS"
    key=$(printf '%s' "$target" | tr 'a-z-' 'A-Z_')
    SEDARGS="$SEDARGS -e s|@SHA256_${key}@|$lines|g"
done

# render FILE [SED_ARGS...] : the template with every placeholder replaced, on stdout.
render() {
    local file=$1
    shift
    # shellcheck disable=SC2086
    sed -e "s|@VERSION@|$version|g" -e "s|@TAG@|$tag|g" -e "s|@REPO@|$repo|g" \
        -e "s|@OWNER@|$owner|g" -e "s|@NPM_SCOPE@|$scope|g" $SEDARGS ${1+"$@"} "$file"
}

rm -rf "$out"
mkdir -p "$out"

mkdir -p "$out/homebrew"
render "$templates/homebrew/bd.rb" >"$out/homebrew/bd.rb"

lower=$(printf '%s' "$owner" | tr 'A-Z' 'a-z')
first=$(printf '%s' "$lower" | cut -c1)
wdir=$out/winget/manifests/$first/$owner/bd/$version
mkdir -p "$wdir"
for part in "" .installer .locale.en-US; do
    render "$templates/winget/bd$part.yaml" >"$wdir/$owner.bd$part.yaml"
done

mkdir -p "$out/npm/bd/bin"
render "$templates/npm/bd/package.json" >"$out/npm/bd/package.json"
render "$templates/npm/bd/bin/bd.js" >"$out/npm/bd/bin/bd.js"
chmod 0755 "$out/npm/bd/bin/bd.js"
[ ! -f "$ROOT/LICENSE" ] || cp -f "$ROOT/LICENSE" "$out/npm/bd/LICENSE"

extract_zip_member() {
    # extract_zip_member ZIP DEST : the bd.exe entry
    if command -v python3 >/dev/null 2>&1; then
        python3 -I -c 'import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z, open(sys.argv[2], "wb") as o:
    o.write(z.read("bd.exe"))' "$1" "$2"
    elif command -v unzip >/dev/null 2>&1; then
        unzip -p "$1" bd.exe >"$2"
    else
        die "python3 or unzip is needed to unpack $1"
    fi
}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/bd-render.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
for entry in $TARGETS; do
    IFS=: read -r target os cpu ext <<<"$entry"
    pkg=$out/npm/bd-$os-$cpu
    mkdir -p "$pkg/bin"
    render "$templates/npm/platform/package.json" -e "s|@NPM_OS@|$os|g" -e "s|@NPM_CPU@|$cpu|g" -e "s|@BIN@|bd|g" >"$pkg/package.json"
    archive=$dist/bd-$tag-$target.$ext
    if [ "$ext" = zip ]; then
        extract_zip_member "$archive" "$pkg/bin/bd.exe"
        chmod 0755 "$pkg/bin/bd.exe"
    else
        rm -rf "$tmp/x"
        mkdir -p "$tmp/x"
        tar -xzf "$archive" -C "$tmp/x" bd || die "cannot unpack bd from $archive"
        [ -f "$tmp/x/bd" ] || die "$archive has no bd"
        cp -f "$tmp/x/bd" "$pkg/bin/bd"
        chmod 0755 "$pkg/bin/bd"
    fi
    [ ! -f "$ROOT/LICENSE" ] || cp -f "$ROOT/LICENSE" "$pkg/LICENSE"
done

left=$(grep -rIE '@[A-Z][A-Z0-9_]*@' "$out" 2>/dev/null | head -5 || true)
[ -z "$left" ] || die "unrendered placeholders left:
$left"

echo "rendered packaging for $tag into $out"
