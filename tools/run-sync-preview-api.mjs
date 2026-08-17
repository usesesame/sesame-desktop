// Development-only preview API; Sync stays disabled in production.

import { spawnSync } from 'node:child_process'
import { createConnection } from 'node:net'
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const root = resolve(import.meta.dirname, '..')

function readEnvFile(path) {
  const values = new Map()
  if (!existsSync(path)) return values
  for (const line of readFileSync(path, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/)
    if (match) values.set(match[1], match[2].trim().replace(/^(['"])(.*)\1$/, '$2'))
  }
  return values
}

const file = readEnvFile(resolve(root, '.env'))
const required = [
  'SESAME_ADMIN_ENCRYPTION_KEY',
  'SESAME_ADMIN_IP_PEPPER',
  'SESAME_CAPABILITY_SIGNING_KEY',
]
const missing = required.filter((name) => !process.env[name] && !file.get(name))
if (missing.length > 0) {
  console.error(
    `Missing local secrets: ${missing.join(', ')}.\nRun \`npm run api:up\` once to create them in the repository root .env.`,
  )
  process.exit(2)
}

const environment = {
  ...process.env,
  SESAME_ENV: 'development',
  DATABASE_URL:
    process.env.DATABASE_URL ||
    file.get('DATABASE_URL') ||
    'postgres://sesame:sesame-development-only@127.0.0.1:5432/sesame?sslmode=disable',
  SESAME_API_ADDR: process.env.SESAME_API_ADDR || '127.0.0.1:8787',
  SESAME_WEB_ORIGIN: process.env.SESAME_WEB_ORIGIN || 'http://localhost:4173',
  SESAME_ADMIN_ORIGIN: process.env.SESAME_ADMIN_ORIGIN || 'http://localhost:4174',
}
for (const name of required) {
  environment[name] = process.env[name] || file.get(name)
}

const [host, port] = (environment.SESAME_API_ADDR ?? '').split(':')
const inUse = await new Promise((resolve) => {
  const probe = createConnection({ host: host || '127.0.0.1', port: Number(port) })
  probe.on('connect', () => { probe.destroy(); resolve(true) })
  probe.on('error', () => resolve(false))
  setTimeout(() => { probe.destroy(); resolve(false) }, 1500)
})
if (inUse) {
  console.error(
    [
      `Port ${port} is already in use, most likely by the Compose API.`,
      'The Sync preview replaces it for the session so the desktop keeps talking to',
      'the same URL it was built against. Stop just that container, which leaves',
      'PostgreSQL running because this API needs it:',
      '  npm run api:stop',
    ].join('\n'),
  )
  process.exit(2)
}

const result = spawnSync('go', ['run', './cmd/api-sync-preview'], {
  cwd: resolve(root, 'backend'),
  env: environment,
  stdio: 'inherit',
})
if (result.error) {
  console.error(`Could not start the Sync preview API: ${result.error.message}`)
  process.exit(1)
}
process.exit(result.status ?? 1)
