#!/usr/bin/env node
// Launcher: runs the bd binary from the platform package npm installed for this machine.
"use strict";
const { spawnSync } = require("child_process");

const scope = "@NPM_SCOPE@";
const packages = {
  "linux x64": "bd-linux-x64",
  "linux arm64": "bd-linux-arm64",
  "darwin x64": "bd-darwin-x64",
  "darwin arm64": "bd-darwin-arm64",
  "win32 x64": "bd-win32-x64",
  "win32 arm64": "bd-win32-arm64",
};

const key = `${process.platform} ${process.arch}`;
const name = packages[key];
if (!name) {
  console.error(`bd: no prebuilt binary for ${key}; see https://github.com/@REPO@/releases`);
  process.exit(1);
}
const pkg = `${scope}/${name}`;
const exe = process.platform === "win32" ? "bd.exe" : "bd";

let binary;
try {
  binary = require.resolve(`${pkg}/bin/${exe}`);
} catch (_) {
  console.error(
    `bd: the package ${pkg} is not installed.\n` +
      `It holds the binary for ${key} and is an optional dependency of ${scope}/bd.\n` +
      `Reinstall without --omit=optional / --no-optional (and without --ignore-optional), ` +
      `or delete node_modules and the lockfile and install again.`,
  );
  process.exit(1);
}

const result = spawnSync(binary, process.argv.slice(2), { stdio: "inherit", windowsHide: true });
if (result.error) {
  console.error(`bd: cannot run ${binary}: ${result.error.message}`);
  process.exit(1);
}
if (result.signal) {
  process.kill(process.pid, result.signal);
  // Still here: the signal was ignored or is not fatal.
  process.exit(1);
}
process.exit(result.status === null ? 1 : result.status);
