#!/usr/bin/env bash
# Tests for the distribution scripts: scripts/install.sh against a file:// fixture,
# and that the target and asset names agree with .github/workflows/release.yml.
# Needs bash, curl, tar and python3 (or zip). Runs on Linux and macOS (bash 3.2).
#   bash scripts/test-packaging.sh
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
RELEASE_YML=$ROOT/.github/workflows/release.yml
RENDER_SH=$ROOT/scripts/render-packaging.sh
INSTALL_SH=$ROOT/scripts/install.sh
INSTALL_PS1=$ROOT/scripts/install.ps1
TAG=v9.9.9
VERSION=9.9.9
TARGETS="aarch64-apple-darwin aarch64-pc-windows-msvc aarch64-unknown-linux-musl x86_64-apple-darwin x86_64-pc-windows-msvc x86_64-unknown-linux-musl"

PASS=0
FAIL=0
WORK=$(mktemp -d "${TMPDIR:-/tmp}/bd-packaging.XXXXXX") || exit 1
trap 'rm -rf "$WORK"' EXIT

ok() {
    PASS=$((PASS + 1))
    echo "ok   - $1"
}
bad() {
    FAIL=$((FAIL + 1))
    echo "FAIL - $1"
}
# check DESCRIPTION COMMAND... : passes when the command succeeds.
check() {
    local desc=$1
    shift
    if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi
}
# check_fails DESCRIPTION COMMAND... : passes when the command fails.
check_fails() {
    local desc=$1
    shift
    if "$@" >/dev/null 2>&1; then bad "$desc"; else ok "$desc"; fi
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

mode_of() {
    ls -l "$1" | cut -c1-10
}

# ---------------------------------------------------------------- consistency

release_targets() {
    sed -n 's/^ *- target: //p' "$RELEASE_YML" | LC_ALL=C sort
}

# Targets a script can choose: the known target strings it contains literally.
targets_in() {
    local t
    for t in $TARGETS; do
        if grep -qF "$t" "$1"; then echo "$t"; fi
    done | LC_ALL=C sort
}

test_consistency() {
    echo "# consistency with release.yml"
    local want
    want=$(release_targets)
    [ -n "$want" ] || { bad "release.yml build matrix has targets"; return; }
    ok "release.yml build matrix has targets"

    # The list in this test must itself match the workflow.
    local mine
    mine=$(echo "$TARGETS" | tr ' ' '\n' | LC_ALL=C sort)
    if [ "$mine" = "$want" ]; then ok "test target list equals release.yml"; else bad "test target list equals release.yml"; fi

    # install.sh handles every non-Windows target, and no other.
    local sh_want sh_got
    sh_want=$(echo "$want" | grep -v windows)
    sh_got=$(targets_in "$INSTALL_SH")
    if [ "$sh_got" = "$sh_want" ]; then ok "install.sh targets equal release.yml (non-Windows)"; else bad "install.sh targets equal release.yml (non-Windows): got $sh_got"; fi
    # Anything target-shaped in install.sh must be a release target.
    local stray
    stray=$(grep -Eo '(x86_64|aarch64)-[a-z]+-[a-z]+(-[a-z]+)?' "$INSTALL_SH" | LC_ALL=C sort -u | while read -r t; do
        if ! echo "$want" | grep -qx "$t"; then echo "$t"; fi
    done)
    if [ -z "$stray" ]; then ok "install.sh names no target outside release.yml"; else bad "install.sh names no target outside release.yml: $stray"; fi

    # install.ps1 handles every Windows target, and no other.
    local ps_want ps_got
    ps_want=$(echo "$want" | grep windows)
    ps_got=$(targets_in "$INSTALL_PS1")
    if [ "$ps_got" = "$ps_want" ]; then ok "install.ps1 targets equal release.yml (Windows)"; else bad "install.ps1 targets equal release.yml (Windows): got $ps_got"; fi
    stray=$(grep -Eo '(x86_64|aarch64)-[a-z]+-[a-z]+(-[a-z]+)?' "$INSTALL_PS1" | LC_ALL=C sort -u | while read -r t; do
        if ! echo "$want" | grep -qx "$t"; then echo "$t"; fi
    done)
    if [ -z "$stray" ]; then ok "install.ps1 names no target outside release.yml"; else bad "install.ps1 names no target outside release.yml: $stray"; fi
    check "install.ps1 fetches .zip assets and SHA256SUMS" grep -qE '\.zip' "$INSTALL_PS1"
    check "install.ps1 never exits the host" bash -c '! grep -nE "^[[:space:]]*exit([[:space:]]|$)" "$1"' _ "$INSTALL_PS1"

    # render-packaging.sh renders exactly the release targets.
    local rtargets
    rtargets=$(sed -n '/^TARGETS="/,/"$/p' "$RENDER_SH" | grep -Eo '(x86_64|aarch64)-[a-z]+-[a-z]+(-[a-z]+)?' | LC_ALL=C sort)
    if [ "$rtargets" = "$want" ]; then ok "render-packaging.sh TARGETS equal release.yml"; else bad "render-packaging.sh TARGETS equal release.yml: got $rtargets"; fi
    local tmpl_stray
    tmpl_stray=$(grep -rhEo '(x86_64|aarch64)-[a-z]+-[a-z]+(-[a-z]+)?' "$ROOT/packaging" | LC_ALL=C sort -u | while read -r t; do
        if ! echo "$want" | grep -qx "$t"; then echo "$t"; fi
    done)
    if [ -z "$tmpl_stray" ]; then ok "templates name no target outside release.yml"; else bad "templates name no target outside release.yml: $tmpl_stray"; fi
    local missing_in_tmpl=
    for t in $want; do
        case "$t" in
        *windows*) grep -rqF "$t" "$ROOT/packaging/winget" || missing_in_tmpl="$missing_in_tmpl $t" ;;
        *) grep -qF "$t" "$ROOT/packaging/homebrew/bd.rb" || missing_in_tmpl="$missing_in_tmpl $t" ;;
        esac
    done
    if [ -z "$missing_in_tmpl" ]; then ok "templates cover every release target"; else bad "templates cover every release target: missing$missing_in_tmpl"; fi

    # The workflow still names archives the way the installers expect.
    check "release.yml names archives bd-\$LABEL-\$TARGET" grep -qF 'name="bd-$LABEL-$TARGET"' "$RELEASE_YML"
    check "release.yml builds .tar.gz archives" grep -qF '.tar.gz' "$RELEASE_YML"
    check "release.yml builds .zip archives" grep -qF '.zip' "$RELEASE_YML"
    check "release.yml writes SHA256SUMS" grep -qF 'SHA256SUMS' "$RELEASE_YML"
}

# ------------------------------------------------------------------- fixture

make_zip() {
    # make_zip ZIPFILE DIR: a zip holding DIR/bd.exe
    if command -v python3 >/dev/null 2>&1; then
        python3 -I -c 'import sys, zipfile
z = zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED)
z.write(sys.argv[2] + "/bd.exe", "bd.exe")
z.close()' "$1" "$2"
    elif command -v zip >/dev/null 2>&1; then
        (cd "$2" && zip -q "$1" bd.exe)
    elif command -v 7z >/dev/null 2>&1; then
        (cd "$2" && 7z a -bd -bso0 "$1" bd.exe)
    else
        return 1
    fi
}

# build_fixture DIR : release assets for every target under DIR/download/$TAG,
# with SHA256SUMS there and in latest/download.
build_fixture() {
    local fx=$1 t stage asset
    mkdir -p "$fx/download/$TAG" "$fx/latest/download"
    stage=$fx/stage
    for t in $TARGETS; do
        rm -rf "$stage"
        mkdir -p "$stage"
        case "$t" in
        *windows*)
            printf 'MZ dummy\n' >"$stage/bd.exe"
            asset=bd-$TAG-$t.zip
            make_zip "$fx/download/$TAG/$asset" "$stage" || return 1
            ;;
        *)
            printf '#!/bin/sh\necho "bd %s"\n' "$VERSION" >"$stage/bd"
            chmod 0755 "$stage/bd"
            asset=bd-$TAG-$t.tar.gz
            tar -czf "$fx/download/$TAG/$asset" -C "$stage" bd || return 1
            ;;
        esac
    done
    rm -rf "$stage"
    (
        cd "$fx/download/$TAG" || exit 1
        for f in bd-*; do
            printf '%s  %s\n' "$(sha256_of "$f")" "$f"
        done | LC_ALL=C sort -k2 >SHA256SUMS
    ) || return 1
    cp -f "$fx/download/$TAG/SHA256SUMS" "$fx/latest/download/SHA256SUMS"
}

FIXTURE=$WORK/fixture
FIXTURE_OK=0
setup_fixture() {
    if build_fixture "$FIXTURE"; then FIXTURE_OK=1; ok "fixture built"; else bad "fixture built"; fi
}

# -------------------------------------------------------------- install.sh

# run_install SH [ARGS...] with the fixture environment; extra env via ENVX.
run_install() {
    local shell=$1
    shift
    env -u BD_VERSION -u BD_REPO -u BD_INSTALL_DIR BD_RELEASES_URL="file://$FIXTURE" BD_ATTESTATION=skip \
        BD_INSTALL_DIR="$BIN" $ENVX "$shell" "$INSTALL_SH" "$@"
}

assert_installed() {
    local desc=$1 out mode
    out=$("$BIN/bd" --version 2>&1)
    mode=$(mode_of "$BIN/bd")
    if [ "$out" = "bd $VERSION" ] && [ "$mode" = "-rwxr-xr-x" ]; then ok "$desc"; else bad "$desc (got '$out', mode $mode)"; fi
}

host_is_supported() {
    case "$(uname -s)-$(uname -m)" in
    Linux-x86_64 | Linux-aarch64 | Linux-arm64 | Darwin-arm64 | Darwin-x86_64) return 0 ;;
    *) return 1 ;;
    esac
}

test_install_sh() {
    echo "# install.sh"
    if [ "$FIXTURE_OK" != 1 ]; then bad "install.sh tests need the fixture"; return; fi
    if ! host_is_supported; then echo "skip - unsupported host for install.sh"; return; fi
    local sh_cmd=sh
    ENVX=
    BIN=$WORK/bin

    rm -rf "$BIN"
    check "install latest" run_install "$sh_cmd"
    assert_installed "latest installs a 0755 bd that runs"

    rm -rf "$BIN"
    check "install --version 9.9.9" run_install "$sh_cmd" --version 9.9.9
    assert_installed "--version 9.9.9 installs"
    rm -rf "$BIN"
    check "install --version v9.9.9" run_install "$sh_cmd" --version v9.9.9
    assert_installed "--version v9.9.9 installs"
    rm -rf "$BIN"
    check "install with BD_VERSION" env BD_VERSION=9.9.9 BD_RELEASES_URL="file://$FIXTURE" BD_ATTESTATION=skip BD_INSTALL_DIR="$BIN" "$sh_cmd" "$INSTALL_SH"
    assert_installed "BD_VERSION installs"

    # --dir overrides BD_INSTALL_DIR.
    local other=$WORK/other/nested
    rm -rf "$WORK/other" "$BIN"
    check "install --dir" run_install "$sh_cmd" --dir "$other"
    if [ ! -e "$BIN/bd" ] && [ "$("$other/bd" --version)" = "bd $VERSION" ] && [ "$(mode_of "$other/bd")" = "-rwxr-xr-x" ]; then ok "--dir overrides BD_INSTALL_DIR"; else bad "--dir overrides BD_INSTALL_DIR"; fi
    if ls -A "$other" | grep -q '^\.bd\.tmp'; then bad "no staging file left behind"; else ok "no staging file left behind"; fi

    # Reinstall over an existing binary replaces it.
    rm -rf "$BIN"
    mkdir -p "$BIN"
    printf '#!/bin/sh\necho old\n' >"$BIN/bd"
    chmod 0755 "$BIN/bd"
    check "install over an existing bd" run_install "$sh_cmd" --version 9.9.9
    assert_installed "existing bd is replaced"

    # A tampered archive: failure, and the existing bd is untouched.
    local fx2=$WORK/fixture-tampered
    rm -rf "$fx2"
    cp -R "$FIXTURE" "$fx2"
    local t
    case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) t=x86_64-unknown-linux-musl ;;
    Linux-*) t=aarch64-unknown-linux-musl ;;
    Darwin-*) t=aarch64-apple-darwin ;;
    esac
    case "$(uname -s)-$(uname -m)-$(sysctl -n hw.optional.arm64 2>/dev/null || true)" in
    Darwin-x86_64-) t=x86_64-apple-darwin ;;
    esac
    printf 'tampered' >>"$fx2/download/$TAG/bd-$TAG-$t.tar.gz"
    rm -rf "$BIN"
    mkdir -p "$BIN"
    printf '#!/bin/sh\necho old\n' >"$BIN/bd"
    chmod 0755 "$BIN/bd"
    local before
    before=$(sha256_of "$BIN/bd")
    check_fails "tampered archive is refused" env BD_RELEASES_URL="file://$fx2" BD_ATTESTATION=skip BD_INSTALL_DIR="$BIN" "$sh_cmd" "$INSTALL_SH" --version 9.9.9
    if [ "$(sha256_of "$BIN/bd")" = "$before" ] && [ "$("$BIN/bd" --version)" = old ] && [ "$(ls -A "$BIN" | wc -l | tr -d ' ')" = 1 ]; then ok "tampered archive leaves the install dir untouched"; else bad "tampered archive leaves the install dir untouched"; fi
    check_fails "tampered archive is refused for latest" env BD_RELEASES_URL="file://$fx2" BD_ATTESTATION=skip BD_INSTALL_DIR="$BIN" "$sh_cmd" "$INSTALL_SH"

    # A SHA256SUMS without the asset's line.
    local fx3=$WORK/fixture-missing
    rm -rf "$fx3"
    cp -R "$FIXTURE" "$fx3"
    grep -v -- "-$t\." "$FIXTURE/download/$TAG/SHA256SUMS" >"$fx3/download/$TAG/SHA256SUMS"
    check_fails "a missing checksum line is refused" env BD_RELEASES_URL="file://$fx3" BD_ATTESTATION=skip BD_INSTALL_DIR="$BIN" "$sh_cmd" "$INSTALL_SH" --version 9.9.9

    # Bad inputs.
    rm -rf "$BIN"
    check_fails "a version that does not exist fails" run_install "$sh_cmd" --version 1.2.3
    check_fails "an invalid version fails" run_install "$sh_cmd" --version 'x;rm -rf /'
    check_fails "an invalid version with a path fails" run_install "$sh_cmd" --version '../9.9.9'
    check_fails "an invalid repo fails" run_install "$sh_cmd" --repo 'a/b;c'
    check_fails "an unknown option fails" run_install "$sh_cmd" --bogus
    check_fails "a bad BD_ATTESTATION fails" env BD_RELEASES_URL="file://$FIXTURE" BD_ATTESTATION=maybe BD_INSTALL_DIR="$BIN" "$sh_cmd" "$INSTALL_SH"
    if [ ! -e "$BIN/bd" ]; then ok "failed installs leave nothing behind"; else bad "failed installs leave nothing behind"; fi
    check_fails "BD_ATTESTATION=require without a logged-in gh fails" env PATH="$(make_nogh_bin)" BD_RELEASES_URL="file://$FIXTURE" BD_ATTESTATION=require BD_INSTALL_DIR="$BIN" "$sh_cmd" "$INSTALL_SH" --version 9.9.9
    check "BD_ATTESTATION=auto without gh still installs" env PATH="$(make_nogh_bin)" BD_RELEASES_URL="file://$FIXTURE" BD_ATTESTATION=auto BD_INSTALL_DIR="$BIN" "$sh_cmd" "$INSTALL_SH" --version 9.9.9

    # A failing gh (installed but not logged in): auto skips, require fails.
    mkdir -p "$WORK/fakegh"
    printf '#!/bin/sh\nexit 1\n' >"$WORK/fakegh/gh"
    chmod 0755 "$WORK/fakegh/gh"
    rm -rf "$BIN"
    check "auto skips attestation when gh is not logged in" env PATH="$WORK/fakegh:$PATH" BD_RELEASES_URL="file://$FIXTURE" BD_ATTESTATION=auto BD_INSTALL_DIR="$BIN" "$sh_cmd" "$INSTALL_SH" --version 9.9.9
    rm -rf "$BIN"
    check_fails "require fails when gh is not logged in" env PATH="$WORK/fakegh:$PATH" BD_RELEASES_URL="file://$FIXTURE" BD_ATTESTATION=require BD_INSTALL_DIR="$BIN" "$sh_cmd" "$INSTALL_SH" --version 9.9.9
    # A logged-in gh whose verification fails aborts, leaving nothing installed.
    printf '#!/bin/sh\n[ "$1" = auth ] && exit 0\nexit 1\n' >"$WORK/fakegh/gh"
    rm -rf "$BIN"
    check_fails "a failed attestation aborts the install" env PATH="$WORK/fakegh:$PATH" BD_RELEASES_URL="file://$FIXTURE" BD_ATTESTATION=auto BD_INSTALL_DIR="$BIN" "$sh_cmd" "$INSTALL_SH" --version 9.9.9
    if [ ! -e "$BIN/bd" ]; then ok "a failed attestation installs nothing"; else bad "a failed attestation installs nothing"; fi
    printf '#!/bin/sh\nexit 0\n' >"$WORK/fakegh/gh"
    check "a passing attestation installs" env PATH="$WORK/fakegh:$PATH" BD_RELEASES_URL="file://$FIXTURE" BD_ATTESTATION=auto BD_INSTALL_DIR="$BIN" "$sh_cmd" "$INSTALL_SH" --version 9.9.9

    # An unwritable install dir (not as root, which ignores modes).
    if [ "$(id -u)" != 0 ]; then
        mkdir -p "$WORK/ro"
        chmod 0555 "$WORK/ro"
        check_fails "an unwritable install dir fails" run_install "$sh_cmd" --version 9.9.9 --dir "$WORK/ro/bin"
        check_fails "a read-only install dir fails" run_install "$sh_cmd" --version 9.9.9 --dir "$WORK/ro"
        chmod 0755 "$WORK/ro"
    fi

    # Other shells.
    if command -v dash >/dev/null 2>&1; then
        rm -rf "$BIN"
        check "install under dash" run_install dash --version 9.9.9
        assert_installed "dash installs a working bd"
    else
        echo "skip - dash not found"
    fi
    rm -rf "$BIN"
    check "install under bash --posix" env BD_RELEASES_URL="file://$FIXTURE" BD_ATTESTATION=skip BD_INSTALL_DIR="$BIN" bash --posix "$INSTALL_SH" --version 9.9.9
    assert_installed "bash --posix installs a working bd"

    check "-h prints usage" sh "$INSTALL_SH" -h
    check "install.sh has no sudo command" test -z "$(grep -v '^[[:space:]]*#' "$INSTALL_SH" | grep -E '(^|[;&|( ])sudo[ ;]')"
}

# A directory of symlinks to the tools install.sh needs, without gh: a PATH
# on which gh is missing.
make_nogh_bin() {
    local d=$WORK/nogh-bin tool p
    mkdir -p "$d"
    for tool in sh curl tar gzip awk sed grep cat mkdir cp chmod mv rm mktemp uname sysctl sha256sum shasum openssl wc tr cut head; do
        p=$(type -P "$tool" 2>/dev/null) || continue
        ln -sf "$p" "$d/$tool"
    done
    echo "$d"
}

# ------------------------------------------------------------------- render

# render_to OUT [ARGS...] : render-packaging.sh on the fixture.
render_to() {
    local o=$1
    shift
    bash "$RENDER_SH" --version "$VERSION" --tag "$TAG" --repo octo/bd-sync --dist "$FIXTURE/download/$TAG" --out "$o" ${1+"$@"}
}

json_ok() {
    if command -v node >/dev/null 2>&1; then
        node -e 'JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))' "$1"
    else
        python3 -I -m json.tool "$1" >/dev/null
    fi
}

test_render() {
    echo "# render-packaging.sh"
    if [ "$FIXTURE_OK" != 1 ]; then bad "render tests need the fixture"; return; fi
    local out=$WORK/render t h
    check "render succeeds" render_to "$out"
    if grep -rIqE '@[A-Z][A-Z0-9_]*@' "$out"; then bad "no placeholders left"; else ok "no placeholders left"; fi

    local brew=$out/homebrew/bd.rb
    local wd=$out/winget/manifests/o/octo/bd/$VERSION
    local winst=$wd/octo.bd.installer.yaml
    for t in $TARGETS; do
        h=$(awk -v n="bd-$TAG-$t." 'index($2, n) == 1 { print $1 }' "$FIXTURE/download/$TAG/SHA256SUMS")
        case "$t" in
        *windows*)
            if grep -qF "InstallerSha256: \"$h\"" "$winst" && grep -qF "InstallerUrl: \"https://github.com/octo/bd-sync/releases/download/$TAG/bd-$TAG-$t.zip\"" "$winst"; then ok "winget installer has $t url and hash"; else bad "winget installer has $t url and hash"; fi
            ;;
        *)
            if grep -qF "sha256 \"$h\"" "$brew" && grep -qF "url \"https://github.com/octo/bd-sync/releases/download/$TAG/bd-$TAG-$t.tar.gz\"" "$brew"; then ok "bd.rb has $t url and hash"; else bad "bd.rb has $t url and hash"; fi
            ;;
        esac
    done
    check "bd.rb has the version" grep -qF 'version "9.9.9"' "$brew"
    check "bd.rb installs bd" grep -qF 'bin.install "bd"' "$brew"
    check "bd.rb guards completions" grep -qF 'if File.exist?("completions/bd.bash")' "$brew"
    if command -v ruby >/dev/null 2>&1; then
        check "ruby -c accepts bd.rb" ruby -c "$brew"
    else
        echo "skip - ruby not found"
    fi

    check "winget has three manifests" test "$(ls "$wd" | wc -l | tr -d ' ')" = 3
    check "winget version manifest" grep -qF 'PackageIdentifier: "octo.bd"' "$wd/octo.bd.yaml"
    check "winget installer is a zip with a nested portable" grep -qF 'NestedInstallerType: "portable"' "$winst"
    check "winget installer aliases bd" grep -qF 'PortableCommandAlias: "bd"' "$winst"
    check "winget manifests are 1.10.0" grep -qF 'ManifestVersion: "1.10.0"' "$wd/octo.bd.locale.en-US.yaml"
    check "winget version is 9.9.9" grep -qF 'PackageVersion: "9.9.9"' "$winst"

    # npm
    local f json_all=1
    for f in "$out"/npm/*/package.json; do
        json_ok "$f" || { json_all=0; bad "valid JSON: $f"; }
    done
    if [ "$json_all" = 1 ]; then ok "npm package.json files parse"; fi
    local want_deps got_deps
    want_deps=$(printf '%s\n' @octo/bd-darwin-arm64 @octo/bd-darwin-x64 @octo/bd-linux-arm64 @octo/bd-linux-x64 @octo/bd-win32-arm64 @octo/bd-win32-x64)
    got_deps=$(sed -n '/"optionalDependencies"/,/}/p' "$out/npm/bd/package.json" | grep -Eo '"@octo/[a-z0-9-]+": "9\.9\.9"' | cut -d'"' -f2 | LC_ALL=C sort)
    if [ "$got_deps" = "$want_deps" ]; then ok "optionalDependencies are the six packages at 9.9.9"; else bad "optionalDependencies are the six packages at 9.9.9: $got_deps"; fi
    local d n=0
    for d in "$out"/npm/bd-*; do
        if grep -qF '"version": "9.9.9"' "$d/package.json" && grep -qF "\"name\": \"@octo/$(basename "$d")\"" "$d/package.json"; then n=$((n + 1)); fi
    done
    if [ "$n" = 6 ]; then ok "six platform packages at 9.9.9"; else bad "six platform packages at 9.9.9 (got $n)"; fi
    check "main package has no scripts" test -z "$(grep -E '"scripts"|install"' "$out/npm/bd/package.json")"

    if command -v node >/dev/null 2>&1; then
        local plat o
        plat=$(node -p 'process.platform + "-" + process.arch')
        if [ -f "$out/npm/bd-$plat/bin/bd" ]; then
            local nm=$WORK/nm
            rm -rf "$nm"
            mkdir -p "$nm/node_modules/@octo"
            cp -R "$out/npm/bd" "$nm/node_modules/@octo/bd"
            cp -R "$out/npm/bd-$plat" "$nm/node_modules/@octo/bd-$plat"
            o=$(node "$nm/node_modules/@octo/bd/bin/bd.js" --version 2>&1)
            if [ "$o" = "bd $VERSION" ]; then ok "bd.js runs the platform binary"; else bad "bd.js runs the platform binary (got '$o')"; fi
            printf '#!/bin/sh\nexit 3\n' >"$nm/node_modules/@octo/bd-$plat/bin/bd"
            node "$nm/node_modules/@octo/bd/bin/bd.js" >/dev/null 2>&1
            if [ $? = 3 ]; then ok "bd.js passes the exit code through"; else bad "bd.js passes the exit code through"; fi
            rm -rf "$nm/node_modules/@octo/bd-$plat"
            if o=$(node "$nm/node_modules/@octo/bd/bin/bd.js" --version 2>&1); then bad "bd.js fails without its platform package"; elif echo "$o" | grep -q "omit=optional"; then ok "bd.js explains a missing platform package"; else bad "bd.js explains a missing platform package: $o"; fi
        else
            echo "skip - no platform package for $plat"
        fi
    else
        echo "skip - node not found"
    fi
    if command -v npm >/dev/null 2>&1; then
        for d in "$out"/npm/*/; do
            check "npm pack --dry-run $(basename "$d")" bash -c 'cd "$1" && npm pack --dry-run --ignore-scripts' _ "$d"
        done
    else
        echo "skip - npm not found"
    fi

    # Negative cases.
    local fx=$WORK/render-bad
    rm -rf "$fx"
    cp -R "$FIXTURE" "$fx"
    printf 'tampered' >>"$fx/download/$TAG/bd-$TAG-x86_64-unknown-linux-musl.tar.gz"
    check_fails "render refuses a tampered archive" bash "$RENDER_SH" --version "$VERSION" --tag "$TAG" --dist "$fx/download/$TAG" --out "$WORK/o1"
    cp -f "$FIXTURE/download/$TAG/bd-$TAG-x86_64-unknown-linux-musl.tar.gz" "$fx/download/$TAG/"
    grep -v -- '-aarch64-pc-windows-msvc' "$FIXTURE/download/$TAG/SHA256SUMS" >"$fx/download/$TAG/SHA256SUMS"
    check_fails "render refuses a SHA256SUMS missing a target" bash "$RENDER_SH" --version "$VERSION" --tag "$TAG" --dist "$fx/download/$TAG" --out "$WORK/o2"
    check_fails "render refuses a bad --version" render_to "$WORK/o3" --version 'x;y'
    check_fails "render refuses a mismatched tag" bash "$RENDER_SH" --version 1.0.0 --tag "$TAG" --dist "$FIXTURE/download/$TAG" --out "$WORK/o4"
    check_fails "render refuses a bad --repo" bash "$RENDER_SH" --version "$VERSION" --tag "$TAG" --repo 'a/b|c' --dist "$FIXTURE/download/$TAG" --out "$WORK/o5"
    local tp=$WORK/templates
    rm -rf "$tp"
    cp -R "$ROOT/packaging" "$tp"
    printf '// @BOGUS@\n' >>"$tp/npm/bd/bin/bd.js"
    check_fails "render fails on an unrendered placeholder" render_to "$WORK/o6" --templates "$tp"
}

# --------------------------------------------------------------------- main

test_consistency
setup_fixture
test_install_sh
test_render

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
