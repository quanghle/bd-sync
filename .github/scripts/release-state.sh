#!/usr/bin/env bash
# Usage: release-state.sh TAG SHA256SUMS
#
# Prints the state of the GitHub release for TAG in $GH_REPO (token in
# $GH_TOKEN): "none", "draft" or "published". A token without write access
# does not see drafts, so it gets "none" for them. A published release must
# already have exactly this SHA256SUMS: published assets are never replaced,
# so anything else fails. The release workflow runs this before attesting, so
# a re-run never attests archives it would not publish, and again in publish.
set -euo pipefail

usage="usage: release-state.sh TAG SHA256SUMS"
tag=${1:?$usage}
sums=${2:?$usage}
if [[ ! -f $sums ]]; then
  echo "::error::$sums does not exist." >&2
  exit 1
fi

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

if ! is_draft=$(gh release view "$tag" --json isDraft --jq .isDraft 2>"$scratch/err"); then
  if [[ $(<"$scratch/err") == *"release not found"* ]]; then
    echo none
    exit 0
  fi
  cat "$scratch/err" >&2
  echo "::error::Could not look up release $tag." >&2
  exit 1
fi

if [[ $is_draft == true ]]; then
  echo draft
  exit 0
fi

if ! gh release download "$tag" --pattern SHA256SUMS --dir "$scratch" >&2; then
  echo "::error::Release $tag is already published, but its SHA256SUMS could not be downloaded, so its assets cannot be compared with this run's. Published assets are never replaced: release a new version instead." >&2
  exit 1
fi
if ! cmp -s "$scratch/SHA256SUMS" "$sums"; then
  echo "::error::Release $tag is already published with different assets (its SHA256SUMS differs from this run's). Published assets are never replaced: release a new version instead." >&2
  diff "$scratch/SHA256SUMS" "$sums" >&2 || true
  exit 1
fi
echo "Release $tag is already published with this exact SHA256SUMS." >&2
echo published
