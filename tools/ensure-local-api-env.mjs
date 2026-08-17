import { createPrivateKey, createPublicKey, randomBytes } from 'node:crypto'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

const root = resolve(import.meta.dirname, '..')
const envPath = resolve(root, '.env')
let source = existsSync(envPath) ? readFileSync(envPath, 'utf8') : ''
let generated = false

function decodedBase64URLLength(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return 0
  try {
    return Buffer.from(value, 'base64url').length
  } catch {
    return 0
  }
}

const regenerated = []

function requiredLocalSecret(name, isValid, description) {
  const expression = new RegExp(`^${name}=(.*)$`, 'm')
  const match = source.match(expression)
  const value = match?.[1]?.trim()
  if (value) {
    if (!isValid(value)) throw new Error(`${name} in .env ${description}.`)
    return
  }

  const entry = `${name}=${randomBytes(32).toString('base64url')}`
  source = match
    ? source.replace(expression, entry)
    : `${source}${source && !source.endsWith('\n') ? '\n' : ''}${entry}\n`
  generated = true
  regenerated.push(name)
}

if (!source) {
  source = '# Generated locally for Docker Compose development. Never use these secrets in production.\n'
}

requiredLocalSecret(
  'SESAME_CAPABILITY_SIGNING_KEY',
  (value) => [32, 64].includes(decodedBase64URLLength(value)),
  'must be a base64url-encoded 32-byte seed or 64-byte private key',
)
requiredLocalSecret(
  'SESAME_ADMIN_ENCRYPTION_KEY',
  (value) => /^[a-fA-F0-9]{64}$/.test(value) || decodedBase64URLLength(value) === 32,
  'must encode exactly 32 bytes',
)
requiredLocalSecret(
  'SESAME_ADMIN_IP_PEPPER',
  (value) => decodedBase64URLLength(value) === 32,
  'must be a base64url-encoded 32-byte value',
)

if (generated) {
  writeFileSync(envPath, source, { encoding: 'utf8', mode: 0o600 })
  console.log('Generated missing local API secrets in .env for Docker Compose development.')
}

if (regenerated.includes('SESAME_ADMIN_ENCRYPTION_KEY')) {
  console.log(
    'A new SESAME_ADMIN_ENCRYPTION_KEY was generated. Any admin account created under the\n' +
      'previous key can no longer sign in, because its MFA secret was encrypted with that key.\n' +
      'Issue a fresh setup link for each one:\n' +
      '  npm run backend:admin:bootstrap -- reset admin@example.com',
  )
}

function capabilityPublicKey(seedValue) {
  const seed = Buffer.from(seedValue, 'base64url')
  if (seed.length !== 32 && seed.length !== 64) return ''
  const der = Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    seed.subarray(0, 32),
  ])
  const priv = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' })
  const spki = createPublicKey(priv).export({ format: 'der', type: 'spki' })
  return spki.subarray(spki.length - 32).toString('base64url')
}

function ensureLocalValue(path, name, value, header) {
  const existing = existsSync(path) ? readFileSync(path, 'utf8') : header
  const expression = new RegExp(`^${name}=(.*)$`, 'm')
  const match = existing.match(expression)
  if (match?.[1]?.trim()) return false
  const entry = `${name}=${value}`
  const next = match
    ? existing.replace(expression, entry)
    : `${existing}${existing && !existing.endsWith('\n') ? '\n' : ''}${entry}\n`
  writeFileSync(path, next, { encoding: 'utf8', mode: 0o600 })
  return true
}

const websiteWrote = ensureLocalValue(
  resolve(root, 'website', '.env.local'),
  'VITE_SESAME_ACCOUNT_URL',
  'http://localhost:4175',
  '# Development-only. Written by `npm run api:up`; ignored by Git.\n'
    + 'VITE_SESAME_SITE_ORIGIN=http://localhost:4173\n'
    + 'VITE_SESAME_API_URL=http://localhost:8787\n'
    + 'VITE_SESAME_PRIVACY_EMAIL=privacy@localhost\n',
)
if (websiteWrote) {
  console.log('Wrote website/.env.local so the public site links to the local account portal.')
}

const adminWrote = ensureLocalValue(
  resolve(root, 'admin', '.env.local'),
  'VITE_SESAME_API_URL',
  'http://localhost:8787',
  '# Development-only. Written by `npm run api:up`; ignored by Git.\n',
)
if (adminWrote) {
  console.log(
    'Wrote admin/.env.local so the admin app talks to the local API. Restart\n' +
      '`npm run admin:dev` if it is already running.',
  )
}

const signingSeed = source.match(/^SESAME_CAPABILITY_SIGNING_KEY=(.*)$/m)?.[1]?.trim()
const publicKey = signingSeed ? capabilityPublicKey(signingSeed) : ''
if (publicKey) {
  const wrote = ensureLocalValue(
    resolve(root, 'account', '.env.local'),
    'VITE_SESAME_CAPABILITY_PUBLIC_KEY',
    publicKey,
    '# Development-only. Written by `npm run api:up`; ignored by Git.\n' +
      'VITE_SESAME_SITE_ORIGIN=http://localhost:4173\n' +
      'VITE_SESAME_API_URL=http://localhost:8787\n',
  )
  const desktopWrote = ensureLocalValue(
    resolve(root, 'src-tauri', '.env.local'),
    'SESAME_CAPABILITY_PUBLIC_KEY',
    publicKey,
    '# Local developer configuration. This file is ignored by Git and is used only\n' +
      '# by debug builds. Keep release endpoints in the build environment instead.\n' +
      'SESAME_API_BASE_URL=http://localhost:8787\n',
  )
  if (wrote || desktopWrote) {
    const targets = [wrote && 'account/.env.local', desktopWrote && 'src-tauri/.env.local']
      .filter(Boolean)
      .join(' and ')
    console.log(
      `Wrote the capability public key to ${targets}, so the account portal and the\n` +
        'desktop can verify the signed capability document. Restart whichever is\n' +
        'already running; the desktop needs a rebuild to pick it up.',
    )
  }
}
