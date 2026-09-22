import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import process from 'node:process'

import { executableSuffix } from './browser-host.mjs'

const root = resolve('.')
const manifest = join(root, 'src-tauri', 'Cargo.toml')
const suffix = executableSuffix()
const desktopExe = join(root, 'src-tauri', 'target', 'debug', `sesame${suffix}`)
const hostExe = join(root, 'src-tauri', 'target', 'debug', `sesame-browser-host${suffix}`)

function parseArguments(argv) {
  const options = {
    extensionDirectory: resolve(root, '..', 'sesame-browser-extension'),
    testNamePattern: 'registered native host',
  }
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    if (argument === '--extension-directory') options.extensionDirectory = resolve(argv[++index] ?? '')
    else if (argument === '--test-name-pattern') options.testNamePattern = argv[++index]
    else if (argument === '--keep') options.keep = true
    else throw new Error(`Unknown argument: ${argument}`)
  }
  return options
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

function readHostContract(extensionDirectory) {
  const contractPath = join(extensionDirectory, 'contracts', 'native-host.json')
  const contract = JSON.parse(readFileSync(contractPath, 'utf8'))
  if (contract.host_name !== 'app.usesesame.browser' || typeof contract.official_extension_id !== 'string') {
    throw new Error(`The extension native-host contract is incomplete: ${contractPath}`)
  }
  return contract
}

function scratchEnvironment(testRoot) {
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

function writeHostManifest(testRoot, contract) {
  const directory = join(testRoot, 'native-host')
  mkdirSync(directory, { recursive: true })
  const path = join(directory, 'app.usesesame.browser.json')
  writeFileSync(path, `${JSON.stringify({
    name: contract.host_name,
    description: 'Sesame Browser Helper native host',
    path: realpathSync(hostExe),
    type: 'stdio',
    allowed_origins: [`chrome-extension://${contract.official_extension_id}/`],
  }, null, 2)}\n`)
  return path
}

const delay = (milliseconds) => new Promise((resolveWait) => setTimeout(resolveWait, milliseconds))

async function waitForBrokerSocket(environment, desktop) {
  const socket = join(environment.XDG_RUNTIME_DIR, 'sesame', 'browser.sock')
  const deadline = Date.now() + 60_000
  while (Date.now() < deadline) {
    if (existsSync(socket)) return
    if (desktop.exitCode !== null) {
      throw new Error(`The desktop exited (code ${desktop.exitCode}) before creating its broker socket. Run under dbus-run-session to isolate the session bus.`)
    }
    await delay(250)
  }
  throw new Error('The desktop broker did not create its socket within 60 seconds.')
}

function runExtensionSuite(extensionDirectory, environment, testNamePattern) {
  if (!existsSync(join(extensionDirectory, 'node_modules'))) {
    throw new Error(`The extension checkout has no dependencies installed: run npm ci in ${extensionDirectory}.`)
  }
  const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm'
  const result = spawnSync(npm, ['--prefix', extensionDirectory, 'run', 'test:browser', '--', '--testNamePattern', testNamePattern], {
    cwd: root,
    stdio: 'inherit',
    env: environment,
  })
  if (result.status !== 0) throw new Error('The extension browser suite failed against the registered native host.')
}

async function main() {
  if (process.platform !== 'linux') {
    console.log('The Linux extension native-host harness runs only on Linux; use npm run desktop:host:test on Windows.')
    return
  }

  const options = parseArguments(process.argv.slice(2))
  if (!existsSync(options.extensionDirectory)) throw new Error(`The extension checkout is missing: ${options.extensionDirectory}`)
  const contract = readHostContract(options.extensionDirectory)
  buildBinaries()

  const testRoot = mkdtempSync(join(tmpdir(), 'sesame-extension-native-host-'))
  const environment = {
    ...scratchEnvironment(testRoot),
    SESAME_NATIVE_HOST_TEST: '1',
    SESAME_NATIVE_HOST_MANIFEST: writeHostManifest(testRoot, contract),
  }
  if (process.env.SESAME_MANUAL_NATIVE_FILL === '1') environment.SESAME_MANUAL_NATIVE_FILL = '1'
  if (process.env.SESAME_BROWSER_TEST_EXECUTABLE) environment.SESAME_BROWSER_TEST_EXECUTABLE = process.env.SESAME_BROWSER_TEST_EXECUTABLE

  const desktop = spawn(desktopExe, [], { env: environment, stdio: 'ignore' })
  try {
    await waitForBrokerSocket(environment, desktop)
    runExtensionSuite(options.extensionDirectory, environment, options.testNamePattern)
    console.log('The extension answered through the real native host and the live desktop broker on Linux.')
  } finally {
    try { process.kill(desktop.pid) } catch { void 0 }
    if (options.keep) console.log(`Kept the scratch environment at ${testRoot}`)
    else rmSync(testRoot, { recursive: true, force: true })
  }
}

main().catch((error) => {
  console.error(error)
  process.exitCode = 1
})
