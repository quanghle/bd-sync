# npm packaging for bd

`scripts/render-packaging.sh` renders these templates for a release. Nothing is published
by the release workflow; a maintainer runs `npm publish` by hand (see RELEASING.md).

## Design

- `bd/` is the main package, `<scope>/bd`. It holds only `bin/bd.js`, a small node launcher.
- `platform/` is the template for six packages, `<scope>/bd-<os>-<cpu>` (linux, darwin and
  win32 on x64 and arm64). Each holds one prebuilt binary in `bin/` and declares `os` and
  `cpu`, so npm installs only the one that fits the machine.
- The main package lists all six as `optionalDependencies`, pinned to the exact version.
- Neither kind of package has install scripts.

## Why not a postinstall download

A postinstall that downloads the binary from GitHub is simpler to publish, but:

- It runs code at install time. pnpm 10 and Bun skip dependency lifecycle scripts by default,
  and `--ignore-scripts` is common, so the binary would silently be missing.
- It needs a second channel to github.com, which fails behind registries-only proxies and
  offline mirrors.
- Integrity rests on code that runs on the user's machine. With platform packages, the
  registry and lockfile hashes cover the binary, and rendering checks every archive against
  the release's `SHA256SUMS` before the binary is copied in.

The accepted cost is npm's known lockfile problem with optional dependencies across
platforms: a lockfile written on one OS can lack the others' packages. The launcher says
what to do when its package is missing (reinstall without `--omit=optional`, or regenerate
the lockfile).
