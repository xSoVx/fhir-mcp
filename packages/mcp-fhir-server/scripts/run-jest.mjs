#!/usr/bin/env node
/**
 * Portable ESM-aware jest launcher.
 *
 * Jest needs `--experimental-vm-modules` to run ES modules. Putting
 * `NODE_OPTIONS=--experimental-vm-modules` inline in an npm script is not
 * portable -- that syntax is POSIX-shell only and fails on Windows -- and
 * adding `cross-env` would mean a new dependency plus a lockfile change.
 *
 * Instead this wrapper re-execs node with the flag and resolves jest's bin
 * through node's own resolution, so it works identically on Windows, macOS and
 * Linux, and under npm workspaces where jest is hoisted to the repo root.
 *
 * Any extra CLI arguments are forwarded to jest verbatim, so
 * `npm test -- --coverage` and `npm test -- phi-canary` both behave as usual.
 */
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import process from 'node:process';

const require = createRequire(import.meta.url);

let jestBin;
try {
  jestBin = require.resolve('jest/bin/jest');
} catch (error) {
  console.error(
    '[run-jest] Could not resolve the jest CLI. Run `npm ci` at the repo root first.'
  );
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}

const nodeOptions = [process.env.NODE_OPTIONS, '--experimental-vm-modules']
  .filter(Boolean)
  .join(' ');

const result = spawnSync(
  process.execPath,
  ['--experimental-vm-modules', jestBin, ...process.argv.slice(2)],
  {
    stdio: 'inherit',
    env: { ...process.env, NODE_OPTIONS: nodeOptions }
  }
);

if (result.error) {
  console.error('[run-jest] Failed to start jest:', result.error.message);
  process.exit(1);
}

process.exit(result.status ?? 1);