# Releasing bd

Releases are built and published by
[`.github/workflows/release.yml`](.github/workflows/release.yml) when a tag
`vX.Y.Z` is pushed. The tag must equal `v` + `[workspace.package] version` in
`Cargo.toml`. A tag with a SemVer pre-release suffix (`v0.2.0-rc.1`) is
published as a GitHub pre-release; `+build` metadata is rejected.

The [`release` playbook](.bd/playbooks/release.toml) turns the steps below
into bd issues, with a human approval gate before tagging and a `gh:run` gate
that waits for the release workflow:

```bash
bd playbook plan release --var version=0.2.0    # preview; writes nothing
bd playbook run release --var version=0.2.0     # then: bd ready --run <run-id>
bd gate check                                   # opens the gh:run gate once the release run succeeds
```

The `gh:run` gate watches the first `release.yml` run for the tag push
(`branch = "v<version>"`, `event = "push"`) created after it arms, and it
arms when the playbook's `tag` step closes, so close `tag` before pushing the
tag. Dry runs are ignored. If the tag is deleted and re-created on another
commit, the gate moves to the new tag's run (the playbook's `push` step shows
how to check).

## Cut a release

1. **Bump the version** in `Cargo.toml`:

   ```toml
   [workspace.package]
   version = "0.2.0"
   ```

   Both crates inherit it (`version.workspace = true`), and `bd` depends on
   `bd-core` by path only, so this is the only place to change.

2. **Refresh `Cargo.lock`**: `cargo update --workspace` (it only rewrites the
   workspace's own entries), or any `cargo build`. The workflow builds with
   `--locked` and fails early if the lock file is stale.

3. **Run the quality gates** from [AGENTS.md](AGENTS.md):
   `cargo test --workspace`, `cargo clippy --workspace --all-targets`,
   `cargo fmt --all --check`.

4. **Commit and land it on `main`** (for example "Release v0.2.0"), and wait
   for CI to pass.

5. **Optionally dry-run the release workflow** on `main` (see [Dry run](#dry-run)).

6. **Tag the release commit and push the tag**:

   ```bash
   git tag -a v0.2.0 -m "bd v0.2.0"
   git push origin v0.2.0
   ```

7. **Watch the run** and then [verify the release](#verify-a-release):

   ```bash
   gh run list --workflow release.yml --limit 3
   gh run watch <run-id> --exit-status
   ```

Never move or re-push a tag once its release has been published; release a new
patch version instead.

`v*` tags are protected by the repository ruleset "Release tags": only
repository admins can create, move, or delete them (everyone else is refused
on push), so the tag steps above and the tag deletions under
[If something fails](#if-something-fails) need an admin.

## What the workflow does

| Job | Runs on | Does |
|---|---|---|
| Check tag and version | ubuntu-24.04 | Reads the version with `cargo metadata`, fails unless the tag is `v<version>` and `Cargo.lock` is current, and decides whether this is a pre-release. |
| Build (one per target) | see below | Builds `cargo build --release --locked -p bd --target <target>` with symbols stripped, checks the binary (static on Linux, no dynamic C runtime on Windows, macOS 11 minimum and system libraries only on macOS), packages it, then unpacks the archive and smoke-tests it (`bd version`, `bd init`, `bd create`, `bd ready`). |
| Write SHA256SUMS | ubuntu-24.04 | Writes `SHA256SUMS` for all archives. |
| Attest build provenance | ubuntu-24.04 | Tags only. Signs a SLSA build-provenance attestation for every archive. |
| Publish GitHub Release | ubuntu-24.04 | Tags only. Creates the release with generated notes, the archives and `SHA256SUMS`. On a re-run it completes a draft left by an interrupted publish, but never replaces the assets of a published release (see [If something fails](#if-something-fails)). |

| Target | Runner | Archive |
|---|---|---|
| `x86_64-unknown-linux-musl` | `ubuntu-24.04` | `bd-<tag>-x86_64-unknown-linux-musl.tar.gz` |
| `aarch64-unknown-linux-musl` | `ubuntu-24.04-arm` | `bd-<tag>-aarch64-unknown-linux-musl.tar.gz` |
| `aarch64-apple-darwin` | `macos-26` | `bd-<tag>-aarch64-apple-darwin.tar.gz` |
| `x86_64-apple-darwin` | `macos-26` (cross-compiled, tested under Rosetta 2) | `bd-<tag>-x86_64-apple-darwin.tar.gz` |
| `x86_64-pc-windows-msvc` | `windows-2025` | `bd-<tag>-x86_64-pc-windows-msvc.zip` |
| `aarch64-pc-windows-msvc` | `windows-11-arm` | `bd-<tag>-aarch64-pc-windows-msvc.zip` |

Each archive holds the binary and `README.md` at its root, plus any `LICENSE*`,
`COPYING*` or `NOTICE*` files present in the repository root.

Build settings live in the workflow's `env`, not in `Cargo.toml`:
`CARGO_PROFILE_RELEASE_STRIP=symbols`; `CC_<target>=musl-gcc` for the static
musl builds (the bundled SQLite is compiled against musl from `musl-tools`);
`-C target-feature=+crt-static` for Windows (no Visual C++ redistributable
needed); `MACOSX_DEPLOYMENT_TARGET=11.0`; and `RUST_TOOLCHAIN=stable` (the
exact `rustc` version is printed in each build log; set an exact version such
as `1.99.0` there to pin it). `ring` (the rustls crypto provider) compiles its
C code with clang for `aarch64-pc-windows-msvc`; a step before the build puts
the runner image's LLVM (`C:\Program Files\LLVM\bin`) on `PATH` if needed and
fails early when clang is missing.

Supply chain: every action is pinned to a full commit SHA, the default token
is read-only and only the attest job (`id-token`, `attestations`) and the
publish job (`contents: write`) get write scopes, checkouts do not persist
credentials, no build caches are used, and runs for the same tag are queued,
never run in parallel.

## Dry run

Run the workflow by hand from the Actions tab (Release, Run workflow), or
dispatch it and watch exactly that run:

```bash
repo=quanghle/bd-sync
dispatch_runs() { gh run list --repo "$repo" --workflow release.yml --event workflow_dispatch --limit 50 --json databaseId --jq "$1"; }
before=$(dispatch_runs '[.[].databaseId]')                    # dry runs that already exist
url=$(gh workflow run release.yml --repo "$repo" --ref main)  # gh >= 2.87 prints the new run's URL
run=${url##*/runs/}; run=${run%%/*}
for _ in {1..24}; do                  # older gh prints nothing: wait for the first run not seen before
  [[ $run =~ ^[0-9]+$ ]] && break
  sleep 5
  run=$(dispatch_runs "[.[].databaseId] - $before | last // empty")
done
gh run watch "$run" --repo "$repo" --exit-status              # exits non-zero if the run fails
```

Listing the newest run right after dispatching can return the previous dry
run, because a new run takes a few seconds to appear. The fallback therefore
compares run ids from before and after the dispatch, which, unlike a
timestamp, does not depend on the local clock matching GitHub's.

It builds, checks, packages and smoke-tests every target and writes
`SHA256SUMS`, but attests and publishes nothing. The archives are workflow
artifacts named `bd-v<version>-dev.<commit>-<target>` (or `bd-<tag>-<target>`
when run on a tag); fetch them with `gh run download <run-id>`.

## Verify a release

```bash
tag=v0.2.0
gh release download "$tag" --repo quanghle/bd-sync --dir "bd-$tag"
cd "bd-$tag"
sha256sum -c SHA256SUMS                        # macOS: shasum -a 256 -c SHA256SUMS
for f in bd-*.tar.gz bd-*.zip; do
  gh attestation verify "$f" --repo quanghle/bd-sync
done
```

For a stricter check, add
`--signer-workflow quanghle/bd-sync/.github/workflows/release.yml --source-ref "refs/tags/$tag"`
to `gh attestation verify`.

## If something fails

Nothing is attested or published unless every build succeeds.

A re-run ("Re-run failed jobs" or "Re-run all jobs") uses the original run's
commit, so it also uses the workflow file at the tagged commit: a fix landed
on `main` never reaches a re-run of an existing tag. Such fixes need the tag
re-created on the fixed commit (deleting and creating `v*` tags needs a
repository admin, because of the ruleset above), or a new patch version.

- **"Tag does not match Cargo.toml"** or **"Cargo.lock is out of date"**:
  nothing was built. Delete the tag (`git push --delete origin vX.Y.Z` and
  `git tag -d vX.Y.Z`), fix the version or lock file on `main`, and tag again.
- **A build fails**: open its log. For a flaky runner or network error, use
  "Re-run failed jobs". If the code or workflow needs a fix, land it on `main`,
  then delete and re-create the tag on the fixed commit (safe only because
  nothing was published), or release the next patch version.
- **Attest or publish fails**: use "Re-run failed jobs", which reuses the
  archives this run already built. Publishing never replaces a published
  release's assets:
  - a draft left by an interrupted publish gets all assets uploaded again
    (`--clobber`) and is then published;
  - a published release only gets the assets it is missing, and only when the
    run's `SHA256SUMS` is byte-identical to the published one. Otherwise the job
    fails ("already published with different assets"). "Re-run all jobs"
    rebuilds the archives with new hashes, so it hits this check;
  - an immutable release cannot gain assets: if any are missing, the job fails.

  In the last two cases, release the next patch version.
- **A new stable Rust breaks the build**: pin `RUST_TOOLCHAIN` in the workflow
  to the last good version and land that on `main`. Then delete and re-create
  the tag on that commit (safe only because nothing was published; needs an
  admin), or release the next patch version.
- **A runner label goes away**: GitHub's Intel macOS images end in August 2027,
  which is why `x86_64-apple-darwin` is cross-compiled on Apple silicon. Runner
  labels are pinned (`ubuntu-24.04`, `macos-26`, `windows-2025`): update them
  on `main` when GitHub deprecates an image. Then delete and re-create the tag
  on that commit (safe only because nothing was published; needs an admin),
  or release the next patch version.
