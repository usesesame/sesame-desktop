import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import net from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { randomBytes } from 'node:crypto'

export const REAL_SERVER_TESTS = [
  'the_rust_client_and_engine_round_trip_against_the_real_service',
  'a_hybrid_approver_pairs_an_older_device_only_when_the_person_allows_it',
  'devices_with_the_older_key_replace_it_and_the_vault_key_rotates_through_the_real_service',
]

export const DEVICES_PER_TEST = ['a', 'b']

const CLIENT_EXPORTS = ['connect', 'request', 'expectStatus', 'setupTokenFrom', 'runFirstSetup', 'createMember', 'pairDevice']
const LISTENING_LINE = 'Sesame server listening'
const START_TIMEOUT_MILLISECONDS = 30_000

export function parseArguments(args) {
  const parsed = { server: null, credentials: null }
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]
    const value = args[index + 1]
    if (arg !== '--server' && arg !== '--credentials') throw new Error(`Unknown argument ${arg}. Use --server <path> and optionally --credentials <file>.`)
    if (value === undefined || value.startsWith('--')) throw new Error(`${arg} needs a value.`)
    parsed[arg.slice(2)] = resolve(value)
    index += 1
  }
  if (!parsed.server) throw new Error('Usage: node tools/start-real-sync-server.mjs --server <path to a sesame-server source tree> [--credentials <file>]')
  return parsed
}

export function serverEnvironment(inherited, dataDir, port) {
  const kept = Object.fromEntries(Object.entries(inherited).filter(([name]) => !name.startsWith('SESAME_')))
  return {
    ...kept,
    SESAME_DATA_DIR: dataDir,
    SESAME_ADDR: `127.0.0.1:${port}`,
    SESAME_PUBLIC_URL: `http://127.0.0.1:${port}`,
    SESAME_BACKUP_INTERVAL: '0',
    SESAME_LOG_LEVEL: 'info',
  }
}

export function capabilityKeyOf(instance) {
  const key = instance?.capabilityPublicKey
  assert.equal(typeof key, 'string', 'the server instance document carries no capabilityPublicKey')
  assert.match(key, /^[A-Za-z0-9_-]+$/, 'the capability key is not base64url')
  assert.equal(Buffer.from(key, 'base64url').length, 32, 'the capability key is not 32 bytes')
  return key
}

export function credentialsDocument({ url, key, devices }) {
  assert.deepEqual(Object.keys(devices).sort(), [...REAL_SERVER_TESTS].sort(), 'devices must cover exactly the tests that run on the real server')
  const tests = {}
  for (const [name, tokens] of Object.entries(devices)) {
    assert.deepEqual(Object.keys(tokens).sort(), [...DEVICES_PER_TEST].sort(), `${name} needs one token per device`)
    assert.equal(new Set(Object.values(tokens)).size, DEVICES_PER_TEST.length, `${name} reuses a token`)
    tests[name] = { ...tokens }
  }
  const allTokens = Object.values(tests).flatMap((tokens) => Object.values(tokens))
  assert.equal(new Set(allTokens).size, allTokens.length, 'two tests share a token')
  return { url, key, tests }
}

export function redactServerLog(text) {
  return String(text)
    .replace(/(setup#token=)[A-Za-z0-9_-]+/g, '$1[redacted]')
    .replace(/((?:^|[?&#\s])code=)[A-Za-z0-9_-]+/g, '$1[redacted]')
}

export async function loadServerClient(serverRoot) {
  const file = join(serverRoot, 'scripts', 'selfhost-client.mjs')
  if (!existsSync(file)) throw new Error(`${file} does not exist, so ${serverRoot} is not a sesame-server source tree this station can use.`)
  const client = await import(pathToFileURL(file).href)
  const missing = CLIENT_EXPORTS.filter((name) => typeof client[name] !== 'function')
  if (missing.length > 0) throw new Error(`The server's selfhost-client.mjs no longer exports ${missing.join(', ')}, so the station cannot provision it.`)
  return client
}

function buildServer(serverRoot, output) {
  const result = spawnSync('go', ['build', '-o', output, './cmd/sesame-server'], {
    cwd: serverRoot,
    env: { ...process.env, CGO_ENABLED: '0' },
    encoding: 'utf8',
  })
  if (result.error) throw result.error
  if (result.status !== 0) throw new Error(`go build ./cmd/sesame-server exited ${result.status}\n${result.stdout}${result.stderr}`)
}

function freePort() {
  return new Promise((resolvePort, reject) => {
    const probe = net.createServer()
    probe.once('error', reject)
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address()
      probe.close(() => resolvePort(port))
    })
  })
}

async function startProcess(binary, dataDir) {
  const port = await freePort()
  const child = spawn(binary, ['serve'], { env: serverEnvironment(process.env, dataDir, port), stdio: ['ignore', 'pipe', 'pipe'] })
  let output = ''
  child.stdout.on('data', (chunk) => { output += chunk })
  child.stderr.on('data', (chunk) => { output += chunk })
  const exited = new Promise((resolveExit) => child.once('exit', resolveExit))
  const server = {
    origin: `http://127.0.0.1:${port}`,
    log: () => output,
    async stop() {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM')
      await exited
    },
  }
  const deadline = Date.now() + START_TIMEOUT_MILLISECONDS
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`the server exited early with code ${child.exitCode}\n${redactServerLog(output.slice(-2000))}`)
    if (output.includes(LISTENING_LINE)) return server
    await new Promise((resolveWait) => setTimeout(resolveWait, 50))
  }
  await server.stop()
  throw new Error(`the server did not report that it was listening within ${START_TIMEOUT_MILLISECONDS / 1000} seconds\n${redactServerLog(output.slice(-2000))}`)
}

async function provision(client, server, tests) {
  const instance = client.connect(server.origin)
  const password = `station-${randomBytes(24).toString('base64url')}`
  const setupToken = client.setupTokenFrom(server.log(), server.origin)
  const { session, codes } = await client.runFirstSetup(instance, setupToken, { name: 'station-owner', password })
  client.expectStatus(await session.call('POST', '/v1/owner/step-up', { json: { password, code: await codes.next() } }), 200, 'step-up')
  client.expectStatus(await session.call('PATCH', '/v1/owner/flags/sync_enabled', { json: { enabled: true } }), 200, 'turn Sync on')
  const description = client.expectStatus(await client.request(instance, 'GET', '/v1/instance'), 200, 'instance').json
  const devices = {}
  for (const test of tests) {
    const member = await client.createMember(session, `Station member ${Object.keys(devices).length + 1}`)
    devices[test] = {}
    for (const label of DEVICES_PER_TEST) {
      const paired = await client.pairDevice(instance, session, { memberId: member.id, deviceName: `Station device ${label}` })
      devices[test][label] = paired.token
    }
  }
  return credentialsDocument({ url: server.origin, key: capabilityKeyOf(description), devices })
}

export async function startRealSyncServer({ serverRoot }) {
  const root = resolve(serverRoot)
  const client = await loadServerClient(root)
  const workDir = mkdtempSync(join(tmpdir(), 'sesame-real-sync-'))
  let server = null
  const stop = async () => {
    if (server) await server.stop().catch(() => {})
    rmSync(workDir, { recursive: true, force: true })
  }
  try {
    const binary = join(workDir, 'sesame-server')
    buildServer(root, binary)
    server = await startProcess(binary, join(workDir, 'data'))
    return { credentials: await provision(client, server, REAL_SERVER_TESTS), stop }
  } catch (error) {
    await stop()
    throw error
  }
}

export function writeCredentials(file, credentials) {
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 })
  rmSync(file, { force: true })
  writeFileSync(file, `${JSON.stringify(credentials, null, 2)}\n`, { mode: 0o600, flag: 'wx' })
  chmodSync(file, 0o600)
}

async function main() {
  const options = parseArguments(process.argv.slice(2))
  const station = await startRealSyncServer({ serverRoot: options.server })
  const credentialsDir = options.credentials ? null : mkdtempSync(join(tmpdir(), 'sesame-real-sync-credentials-'))
  const file = options.credentials ?? join(credentialsDir, 'credentials.json')
  try {
    writeCredentials(file, station.credentials)
  } catch (error) {
    await station.stop()
    if (credentialsDir) rmSync(credentialsDir, { recursive: true, force: true })
    throw error
  }
  const finish = async () => {
    await station.stop()
    rmSync(credentialsDir ?? file, { recursive: true, force: true })
    process.exit(0)
  }
  process.once('SIGINT', finish)
  process.once('SIGTERM', finish)
  process.stdout.write(`READY url=${station.credentials.url} credentials=${file}\n`)
  await new Promise(() => {})
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${redactServerLog(error.stack ?? error)}\n`)
    process.exit(1)
  })
}
