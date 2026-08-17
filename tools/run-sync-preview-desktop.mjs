// For development only; a release build is unaffected.

import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { resolve } from 'node:path'

const root = resolve(import.meta.dirname, '..')

const environment = {
  ...process.env,
  VITE_SESAME_SYNC_PREVIEW: 'true',
}

console.log(
  [
    'Starting Sesame with the Sync preview enabled.',
    '  API:   run `npm run sync:preview:api` in another terminal. It replaces the',
    '         Compose API on the same port, so the desktop needs no rebuild and an',
    '         existing account link stays valid.',
    '  Panel: Settings, under Connections',
    '',
    'The first run rebuilds the Rust host with the sync-preview feature, so it is slow.',
    '',
  ].join('\n'),
)

const cli = resolve(root, 'node_modules', '@tauri-apps', 'cli', 'tauri.js')
if (!existsSync(cli)) {
  console.error('The Tauri CLI is not installed. Run `npm ci` first.')
  process.exit(1)
}
const app = spawn(process.execPath, [cli, 'dev', '--features', 'sync-preview'], {
  cwd: root,
  env: environment,
  stdio: 'inherit',
})

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => app.kill(signal))
}

app.on('error', (error) => {
  console.error(`Could not start the desktop app: ${error.message}`)
  process.exitCode = 1
})

app.on('exit', (code, signal) => {
  if (signal) process.kill(process.pid, signal)
  else process.exit(code ?? 1)
})
