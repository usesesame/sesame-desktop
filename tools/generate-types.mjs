#!/usr/bin/env node
import { spawnSync } from 'node:child_process'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const workspace = dirname(dirname(fileURLToPath(import.meta.url)))

// tauri-build validates every declared sidecar, and exporting the bindings is
// the one cargo command that has no reason to need the staged browser host.
// Without this a fresh clone has to build the sidecar before it can generate
// a type.
const environment = { ...process.env, TAURI_CONFIG: '{"bundle":{"externalBin":[]}}' }

const args = ['test', '--manifest-path', join(workspace, 'src-tauri', 'Cargo.toml'), '--lib', 'export_bindings']
const run = spawnSync('cargo', args, { stdio: 'inherit', env: environment, shell: false })
if (run.status !== 0) {
  throw new Error('The TypeScript bindings could not be generated.')
}
