import assert from 'node:assert/strict'
import { linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'

import { cargoArguments, exactlyOneTestPassed, parseArguments as parseRunnerArguments, testEnvironment } from './run-real-sync-station.mjs'
import {
  DEVICES_PER_TEST,
  REAL_SERVER_TESTS,
  capabilityKeyOf,
  credentialsDocument,
  loadServerClient,
  parseArguments,
  redactServerLog,
  serverEnvironment,
  writeCredentials,
} from './start-real-sync-server.mjs'

const e2e = readFileSync('src-tauri/sesame-app/src/sync/e2e_tests.rs', 'utf8')

const devicesFor = (tests) => Object.fromEntries(tests.map((name, index) => [name, { a: `token-a-${index}`, b: `token-b-${index}` }]))
const withTemporaryDirectory = async (run) => {
  const directory = mkdtempSync(join(tmpdir(), 'sesame-real-sync-contract-'))
  try {
    return await run(directory)
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
}

test('the provisioning script needs a server source path and takes one optional credentials file', () => {
  assert.deepEqual(parseArguments(['--server', '/srv/source']), { server: resolve('/srv/source'), credentials: null })
  assert.deepEqual(parseArguments(['--credentials', '/tmp/c.json', '--server', '/srv/source']), { server: resolve('/srv/source'), credentials: resolve('/tmp/c.json') })
  assert.throws(() => parseArguments([]), /Usage/)
  assert.throws(() => parseArguments(['--server']), /needs a value/)
  assert.throws(() => parseArguments(['--server', '--credentials', 'x']), /needs a value/)
  assert.throws(() => parseArguments(['--server', '/srv/source', '--keep']), /Unknown argument/)
})

test('the server runs on loopback with its own data folder and none of the caller SESAME settings', () => {
  const environment = serverEnvironment(
    { PATH: '/usr/bin', SESAME_PUBLIC_URL: 'https://example.invalid', SESAME_SMTP_PASSWORD: 'fictional', SESAME_SYNC_E2E_URL: 'x' },
    '/work/data',
    4321,
  )
  assert.equal(environment.PATH, '/usr/bin')
  assert.equal(environment.SESAME_DATA_DIR, '/work/data')
  assert.equal(environment.SESAME_ADDR, '127.0.0.1:4321')
  assert.equal(environment.SESAME_PUBLIC_URL, 'http://127.0.0.1:4321')
  assert.equal(environment.SESAME_BACKUP_INTERVAL, '0')
  assert.equal(environment.SESAME_SMTP_PASSWORD, undefined)
  assert.equal(environment.SESAME_SYNC_E2E_URL, undefined)
})

test('the capability key must be 32 bytes of base64url', () => {
  const key = Buffer.alloc(32, 7).toString('base64url')
  assert.equal(capabilityKeyOf({ capabilityPublicKey: key }), key)
  for (const bad of [undefined, null, '', 'not base64!', Buffer.alloc(31).toString('base64url'), Buffer.alloc(33).toString('base64url')]) {
    assert.throws(() => capabilityKeyOf({ capabilityPublicKey: bad }), /capability/, String(bad))
  }
  assert.throws(() => capabilityKeyOf(undefined), /capability/)
})

test('the credentials document holds one token per device for exactly the tests the real server runs', () => {
  const document = credentialsDocument({ url: 'http://127.0.0.1:1', key: 'k', devices: devicesFor(REAL_SERVER_TESTS) })
  assert.deepEqual(Object.keys(document), ['url', 'key', 'tests'])
  assert.deepEqual(Object.keys(document.tests).sort(), [...REAL_SERVER_TESTS].sort())
  for (const tokens of Object.values(document.tests)) assert.deepEqual(Object.keys(tokens).sort(), [...DEVICES_PER_TEST].sort())
})

test('the credentials document refuses a missing test, a missing device and a shared token', () => {
  const devices = devicesFor(REAL_SERVER_TESTS)
  assert.throws(() => credentialsDocument({ url: 'u', key: 'k', devices: devicesFor(REAL_SERVER_TESTS.slice(1)) }), /exactly the tests/)
  assert.throws(() => credentialsDocument({ url: 'u', key: 'k', devices: { ...devices, [REAL_SERVER_TESTS[0]]: { a: 'only' } } }), /one token per device/)
  assert.throws(() => credentialsDocument({ url: 'u', key: 'k', devices: { ...devices, [REAL_SERVER_TESTS[0]]: { a: 'same', b: 'same' } } }), /reuses a token/)
  const shared = { ...devices, [REAL_SERVER_TESTS[1]]: { ...devices[REAL_SERVER_TESTS[0]] } }
  assert.throws(() => credentialsDocument({ url: 'u', key: 'k', devices: shared }), /share a token/)
})

test('the credentials file holds the document and replaces a stale file', async () => {
  await withTemporaryDirectory((directory) => {
    const file = join(directory, 'nested', 'credentials.json')
    writeCredentials(file, { url: 'u', key: 'k', tests: {} })
    assert.deepEqual(JSON.parse(readFileSync(file, 'utf8')), { url: 'u', key: 'k', tests: {} })
    writeFileSync(file, 'stale')
    writeCredentials(file, { url: 'v', key: 'k', tests: {} })
    assert.deepEqual(JSON.parse(readFileSync(file, 'utf8')), { url: 'v', key: 'k', tests: {} })
  })
})

test('the credentials file is readable only by its owner', { skip: process.platform === 'win32' && 'Windows has no POSIX file modes to check' }, async () => {
  await withTemporaryDirectory((directory) => {
    const file = join(directory, 'nested', 'credentials.json')
    writeCredentials(file, { url: 'u', key: 'k', tests: {} })
    assert.equal(statSync(file).mode & 0o777, 0o600)
    assert.equal(statSync(join(directory, 'nested')).mode & 0o077, 0)
    writeFileSync(file, 'stale', { mode: 0o644 })
    const stale = join(directory, 'stale-link')
    linkSync(file, stale)
    writeCredentials(file, { url: 'u', key: 'k', tests: {} })
    assert.equal(statSync(file).mode & 0o777, 0o600)
    assert.equal(readFileSync(stale, 'utf8'), 'stale', 'a stale file is removed and never written into')
  })
})

test('a server log never shows the setup token or a pairing code', () => {
  const log = 'open http://127.0.0.1:1/setup#token=AbC_123-xyz now and pair?code=Zz9_8-q later'
  const redacted = redactServerLog(log)
  assert.ok(!redacted.includes('AbC_123-xyz'))
  assert.ok(!redacted.includes('Zz9_8-q'))
  assert.match(redacted, /setup#token=\[redacted\]/)
})

test('the script imports the server own client and says which piece a server lacks', async () => {
  await withTemporaryDirectory(async (directory) => {
    await assert.rejects(loadServerClient(directory), /not a sesame-server source tree/)
    const treeWith = (name, source) => {
      const tree = join(directory, name)
      mkdirSync(join(tree, 'scripts'), { recursive: true })
      writeFileSync(join(tree, 'scripts', 'selfhost-client.mjs'), source)
      return tree
    }
    const partial = treeWith('partial', 'export function connect() {}\nexport function request() {}\n')
    await assert.rejects(loadServerClient(partial), /no longer exports expectStatus, setupTokenFrom, runFirstSetup, createMember, pairDevice/)
    const complete = ['connect', 'request', 'expectStatus', 'setupTokenFrom', 'runFirstSetup', 'createMember', 'pairDevice']
    const client = await loadServerClient(treeWith('complete', complete.map((name) => `export function ${name}() {}`).join('\n')))
    assert.equal(typeof client.pairDevice, 'function')
  })
})

test('the script builds the self-host binary without cgo and removes everything it made', () => {
  const source = readFileSync('tools/start-real-sync-server.mjs', 'utf8')
  assert.match(source, /'build', '-o', output, '\.\/cmd\/sesame-server'/)
  assert.match(source, /CGO_ENABLED: '0'/)
  assert.match(source, /rmSync\(workDir, \{ recursive: true, force: true \}\)/)
  assert.match(source, /process\.once\('SIGTERM', finish\)/)
  assert.ok(!/console\.log\([^)]*token/i.test(source), 'the script must not log a token')
})

test('every test the real server runs exists as an ignored test and none of them needs the older server', () => {
  for (const name of REAL_SERVER_TESTS) {
    const start = e2e.indexOf(`fn ${name}(`)
    assert.notEqual(start, -1, `${name} is not in e2e_tests.rs`)
    const body = e2e.slice(start, e2e.indexOf('\n}\n', start))
    assert.ok(!body.includes('SESAME_SYNC_E2E_OLD_'), `${name} needs the older test server`)
    assert.ok(body.includes('SESAME_SYNC_E2E_URL'), `${name} does not read the server address`)
    assert.ok(body.includes('device_token("A"'), `${name} does not read its first device token`)
    assert.ok(body.includes('device_token("B"'), `${name} does not read its second device token`)
    assert.match(e2e.slice(e2e.lastIndexOf('#[test]', start), start), /#\[ignore/)
  }
  assert.equal(REAL_SERVER_TESTS.length, 3)
  assert.ok(!REAL_SERVER_TESTS.includes('a_hybrid_device_is_told_when_the_service_does_not_accept_its_key_yet'))
})

test('the fixed tokens stay as defaults and appear only where the environment is read', () => {
  assert.match(e2e, /fn device_token\(device: &str, fixed: &str\) -> String \{\s*std::env::var\(format!\("SESAME_SYNC_E2E_TOKEN_\{device\}"\)\)\.unwrap_or_else\(\|_\| fixed\.to_string\(\)\)/)
  assert.equal(e2e.match(/"token-[abc]"/g)?.length, 9)
  assert.equal(e2e.match(/device_token\("[ABC]", "token-[abc]"\)/g)?.length, 9)
})

test('the runner counts a test as passed only when exactly one test ran and passed', () => {
  assert.equal(exactlyOneTestPassed('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 882 filtered out; finished in 0.4s'), true)
  assert.equal(exactlyOneTestPassed('test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 883 filtered out'), false, 'a filtered out test is not a pass')
  assert.equal(exactlyOneTestPassed('test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 881 filtered out'), false)
  assert.equal(exactlyOneTestPassed('test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 882 filtered out'), false)
  assert.equal(exactlyOneTestPassed(''), false)
})

test('the runner hands each test its own tokens and drops stale settings from the caller', () => {
  const credentials = credentialsDocument({ url: 'http://127.0.0.1:9', key: 'fictional-key', devices: devicesFor(REAL_SERVER_TESTS) })
  const inherited = { PATH: '/usr/bin', SESAME_SYNC_E2E_TOKEN_C: 'stale', SESAME_SYNC_E2E_OLD_URL: 'http://stale.invalid' }
  const first = testEnvironment(inherited, credentials, REAL_SERVER_TESTS[0])
  const second = testEnvironment(inherited, credentials, REAL_SERVER_TESTS[1])
  assert.equal(first.PATH, '/usr/bin')
  assert.equal(first.SESAME_SYNC_E2E_URL, 'http://127.0.0.1:9')
  assert.equal(first.SESAME_SYNC_E2E_KEY, 'fictional-key')
  assert.equal(first.SESAME_SYNC_E2E_TOKEN_A, 'token-a-0')
  assert.equal(second.SESAME_SYNC_E2E_TOKEN_B, 'token-b-1')
  assert.notEqual(first.SESAME_SYNC_E2E_TOKEN_A, second.SESAME_SYNC_E2E_TOKEN_A)
  assert.equal(first.SESAME_SYNC_E2E_TOKEN_C, undefined)
  assert.equal(first.SESAME_SYNC_E2E_OLD_URL, undefined)
})

test('the runner runs one ignored test at a time against the locked app crate', () => {
  const args = cargoArguments(REAL_SERVER_TESTS[0])
  assert.ok(args.includes('--locked'))
  assert.ok(args.includes('sesame-app'))
  assert.equal(args.at(-1), '--ignored')
  assert.equal(args.at(-3), REAL_SERVER_TESTS[0])
  assert.deepEqual(parseRunnerArguments(['--server', '/srv/source']), { server: resolve('/srv/source') })
  assert.deepEqual(parseRunnerArguments(['--server', 'relative']), { server: resolve('relative') })
  assert.throws(() => parseRunnerArguments([]), /Usage/)
  assert.throws(() => parseRunnerArguments(['--server', '--other']), /Usage/)
})
