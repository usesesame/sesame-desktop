#!/usr/bin/env node
import { spawnSync } from 'node:child_process'
import { copyFileSync, chmodSync, mkdirSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { buildBrowserHost, hostTargetTriple, executableSuffix } from './browser-host.mjs'

const workspace = dirname(dirname(fileURLToPath(import.meta.url)))
const manifest = join(workspace, 'src-tauri', 'Cargo.toml')

buildBrowserHost({ manifest, release: true })

const triple = hostTargetTriple()
const suffix = executableSuffix()

const metadata = spawnSync(
  'cargo',
  ['metadata', '--manifest-path', manifest, '--no-deps', '--format-version', '1'],
  { encoding: 'utf8', shell: false },
)
if (metadata.status !== 0) {
  throw new Error('Cargo metadata could not be read.')
}
const { target_directory: targetDirectory } = JSON.parse(metadata.stdout)

const source = join(targetDirectory, 'release', `sesame-browser-host${suffix}`)
try {
  if (!statSync(source).isFile()) throw new Error('not a file')
} catch {
  throw new Error(`The built Sesame browser host was not found at ${source}.`)
}

const stageDirectory = join(workspace, 'src-tauri', 'binaries')
mkdirSync(stageDirectory, { recursive: true })
const destination = join(stageDirectory, `sesame-browser-host-${triple}${suffix}`)
copyFileSync(source, destination)
if (process.platform !== 'win32') {
  chmodSync(destination, 0o755)
}

process.stdout.write(`Staged the Sesame browser host sidecar for ${triple}.\n`)
