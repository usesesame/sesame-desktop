import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import process from 'node:process'

import { executableSuffix } from './browser-host.mjs'

const root = resolve('.')
const manifest = join(root, 'src-tauri', 'Cargo.toml')
const suffix = executableSuffix()
const desktopExe = join(root, 'src-tauri', 'target', 'debug', `sesame${suffix}`)
const hostExe = join(root, 'src-tauri', 'target', 'debug', `sesame-browser-host${suffix}`)
const pinnedOrigin = 'chrome-extension://idbkfhhjnniibleeanchljhakfhecnlg'
const hostName = 'app.usesesame.browser'
const firefoxExtensionId = 'sesame@usesesame.app'

function frame(value) {
  const json = Buffer.from(JSON.stringify(value), 'utf8')
  const header = Buffer.alloc(4)
  header.writeUInt32LE(json.length, 0)
  return Buffer.concat([header, json])
}

function run(command, args, environment) {
  const result = spawnSync(command, args, {
    cwd: root,
    stdio: 'inherit',
    env: environment,
    shell: process.platform === 'win32',
  })
  if (result.status !== 0) throw new Error(`${command} ${args.join(' ')} failed`)
}

function buildBinaries() {
  const environment = { ...process.env, TAURI_CONFIG: '{"bundle":{"externalBin":[]}}' }
  console.log('Building sesame and sesame-browser-host as true directory siblings...')
  run('cargo', ['build', '--manifest-path', manifest, '--bin', 'sesame'], environment)
  run('cargo', ['build', '--manifest-path', manifest, '--features', 'browser-helper-dev', '--bin', 'sesame-browser-host'], environment)
  if (!existsSync(desktopExe)) throw new Error(`Desktop binary not found at ${desktopExe}`)
  if (!existsSync(hostExe)) throw new Error(`Browser host binary not found at ${hostExe}`)
}

function scratchEnvironment(testRoot) {
  if (process.platform === 'win32') {
    return { ...process.env, LOCALAPPDATA: testRoot }
  }
  const directories = {
    HOME: join(testRoot, 'home'),
    XDG_CONFIG_HOME: join(testRoot, 'config'),
    XDG_DATA_HOME: join(testRoot, 'data'),
    XDG_CACHE_HOME: join(testRoot, 'cache'),
    XDG_RUNTIME_DIR: join(testRoot, 'runtime'),
  }
  for (const directory of Object.values(directories)) mkdirSync(directory, { recursive: true, mode: 0o700 })
  return { ...process.env, ...directories }
}

function manifestPaths(environment) {
  const file = `${hostName}.json`
  return {
    chromium: [
      join(environment.XDG_CONFIG_HOME, 'google-chrome', 'NativeMessagingHosts', file),
      join(environment.XDG_CONFIG_HOME, 'chromium', 'NativeMessagingHosts', file),
    ],
    edge: [join(environment.XDG_CONFIG_HOME, 'microsoft-edge', 'NativeMessagingHosts', file)],
    firefox: [join(environment.HOME, '.mozilla', 'native-messaging-hosts', file)],
  }
}

function sameFile(one, other) {
  try {
    return realpathSync(one) === realpathSync(other)
  } catch {
    return false
  }
}

function readManifest(location) {
  return JSON.parse(readFileSync(location, 'utf8'))
}

function verifyChromiumManifest(location) {
  const manifest = readManifest(location)
  if (manifest.name !== hostName || manifest.type !== 'stdio') {
    throw new Error(`${location} has the wrong identity: ${JSON.stringify(manifest)}`)
  }
  if (!sameFile(manifest.path, hostExe)) {
    throw new Error(`${location} points at ${manifest.path}, not ${hostExe}`)
  }
  if (
    !Array.isArray(manifest.allowed_origins)
    || manifest.allowed_origins.length !== 1
    || manifest.allowed_origins[0] !== `${pinnedOrigin}/`
  ) {
    throw new Error(`${location} allows ${JSON.stringify(manifest.allowed_origins)}`)
  }
}

function verifyFirefoxManifest(location) {
  const manifest = readManifest(location)
  if (manifest.name !== hostName || manifest.type !== 'stdio') {
    throw new Error(`${location} has the wrong identity: ${JSON.stringify(manifest)}`)
  }
  if (!sameFile(manifest.path, hostExe)) {
    throw new Error(`${location} points at ${manifest.path}, not ${hostExe}`)
  }
  if (
    !Array.isArray(manifest.allowed_extensions)
    || manifest.allowed_extensions.length !== 1
    || manifest.allowed_extensions[0] !== firefoxExtensionId
  ) {
    throw new Error(`${location} allows ${JSON.stringify(manifest.allowed_extensions)}`)
  }
  if ('allowed_origins' in manifest) {
    throw new Error(`${location} must not carry Chromium origins.`)
  }
}

function verifyRegistrationLifecycle(environment) {
  const paths = manifestPaths(environment)
  const all = [...paths.chromium, ...paths.edge, ...paths.firefox]
  run(hostExe, ['register'], environment)
  for (const location of all) {
    if (!existsSync(location)) throw new Error(`The browser host did not write ${location}`)
  }
  for (const location of [...paths.chromium, ...paths.edge]) verifyChromiumManifest(location)
  for (const location of paths.firefox) verifyFirefoxManifest(location)
  run(hostExe, ['unregister'], environment)
  for (const location of all) {
    if (existsSync(location)) throw new Error(`The browser host left ${location} behind`)
  }
  if (!existsSync(hostExe)) throw new Error('The unregister verb removed the host binary.')
}

const delay = (milliseconds) => new Promise((resolveWait) => setTimeout(resolveWait, milliseconds))

async function waitForBrokerSocket(environment) {
  const directory = join(environment.XDG_RUNTIME_DIR, 'sesame')
  const socket = join(directory, 'browser.sock')
  const deadline = Date.now() + 60_000
  let lastMode = ''
  while (Date.now() < deadline) {
    if (existsSync(socket)) {
      const directoryMode = statSync(directory).mode & 0o777
      const socketMode = statSync(socket).mode & 0o777
      if (directoryMode === 0o700 && socketMode === 0o600) return socket
      lastMode = `directory ${directoryMode.toString(8)}, socket ${socketMode.toString(8)}`
    }
    await delay(250)
  }
  if (lastMode) throw new Error(`The broker socket modes never became private (last saw ${lastMode}).`)
  throw new Error('The desktop broker did not create its socket within 60 seconds.')
}

async function probeDesktop(environment) {
  const host = spawn(hostExe, [pinnedOrigin], { stdio: ['pipe', 'pipe', 'pipe'], env: environment })
  let stderr = ''
  let timer
  host.stderr.on('data', (chunk) => { stderr += chunk.toString() })
  try {
    return await new Promise((settle, fail) => {
      let buffer = Buffer.alloc(0)
      timer = setTimeout(() => fail(new Error(`native host did not respond over the pipe in time (stderr: ${stderr || '(none)'})`)), 10_000)
      host.once('error', fail)
      host.stdout.on('data', (chunk) => {
        buffer = Buffer.concat([buffer, chunk])
        if (buffer.length < 4) return
        const size = buffer.readUInt32LE(0)
        if (buffer.length < 4 + size) return
        settle(JSON.parse(buffer.subarray(4, 4 + size).toString('utf8')))
      })
      host.once('exit', (code) => fail(new Error(`native host exited (code ${code}) before responding`)))
      host.stdin.write(frame({ version: 1, type: 'capabilities', requestId: 'pipe-check-1' }))
    })
  } finally {
    clearTimeout(timer)
    host.stdin.end()
    if (host.exitCode === null && !host.killed) host.kill()
  }
}

async function main() {
  if (!['win32', 'linux'].includes(process.platform)) {
    console.log(`The browser native-host pipe test does not support ${process.platform}.`)
    return
  }

  buildBinaries()

  const testRoot = mkdtempSync(join(tmpdir(), 'sesame-pipe-check-'))
  const environment = scratchEnvironment(testRoot)
  if (process.platform === 'linux') verifyRegistrationLifecycle(environment)
  const desktop = spawn(desktopExe, [], { env: environment, stdio: ['ignore', 'ignore', 'pipe'] })
  let desktopErrors = ''
  desktop.stderr.on('data', (chunk) => { desktopErrors += chunk.toString() })

  try {
    if (process.platform === 'linux') await waitForBrokerSocket(environment)
    let response
    for (let attempt = 0; attempt < 12; attempt += 1) {
      response = await probeDesktop(environment)
      if (response.type === 'capabilities' && response.desktopAvailable === true) break
      await delay(500)
    }

    if (response?.type !== 'capabilities' || response.desktopAvailable !== true) {
      const hint = process.platform === 'linux' && desktop.exitCode !== null
        ? ' Another Sesame instance may hold the session bus name; run under dbus-run-session.'
        : ''
      throw new Error(`unexpected response from the desktop broker: ${JSON.stringify(response)}${hint} (desktop stderr: ${desktopErrors || '(none)'})`)
    }
    if (process.platform === 'linux' && !existsSync(manifestPaths(environment).chromium[0])) {
      throw new Error('The desktop did not restore its browser registration at startup.')
    }
    console.log('The browser native host completed an authenticated exchange with the live desktop broker:', response)
  } finally {
    try { process.kill(desktop.pid) } catch { void 0 }
    rmSync(testRoot, { recursive: true, force: true })
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1 })
