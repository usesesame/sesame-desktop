import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import process from 'node:process'

import { UNSTAGED_TAURI_CONFIG, executableSuffix } from './browser-host.mjs'
import { launchApp, openBridge, recordStep, stopApp } from './desktop-e2e-bridge.mjs'
import { fictionalLogin, judgeApprovedFill, judgeRefusedFill, openJourney, promptCount, startFixtureServer, stationOriginPolicy } from './extension-journey.mjs'
import { brokerSocketFits, createApprover, createCallQueue, isLoopbackOrigin, judgeStation, stationTargetDirectory, stationTauriConfig } from './extension-station.mjs'

const root = resolve('.')
const manifest = join(root, 'src-tauri', 'Cargo.toml')
const suffix = executableSuffix()
const targetDirectory = stationTargetDirectory(root, process.env)
const desktopExe = join(targetDirectory, 'debug', `sesame${suffix}`)
const hostExe = join(targetDirectory, 'debug', `sesame-browser-host${suffix}`)
const masterPassword = 'fictional extension station vault'

function parseArguments(argv) {
  const options = {
    extensionDirectory: resolve(root, '..', 'sesame-browser-extension'),
    testNamePattern: 'registered native host',
  }
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    if (argument === '--extension-directory') options.extensionDirectory = resolve(argv[++index] ?? '')
    else if (argument === '--test-name-pattern') options.testNamePattern = argv[++index]
    else if (argument === '--evidence-directory') options.evidenceDirectory = resolve(argv[++index] ?? '')
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

function buildBinaries(testRoot) {
  const frontendDist = join(testRoot, 'dist')
  const wdioConfig = JSON.parse(readFileSync(join(root, 'src-tauri', 'tauri.wdio.conf.json'), 'utf8'))
  const config = stationTauriConfig({ wdioConfig, unstagedConfig: UNSTAGED_TAURI_CONFIG, frontendDist })
  const environment = { ...process.env, TAURI_CONFIG: JSON.stringify(config), VITE_SESAME_WDIO: 'true' }
  console.log('Building the test-featured desktop, its web interface and the browser host as directory siblings...')
  run('npm', ['run', 'desktop:build:wdio', '--', '--outDir', frontendDist, '--emptyOutDir'], environment)
  run('cargo', [
    'build', '--locked', '--manifest-path', manifest,
    '--features', 'wdio,browser-helper-dev,tauri/custom-protocol',
    '--bin', 'sesame', '--bin', 'sesame-browser-host',
  ], environment)
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

function appRegisteredOrigins(environment, contract) {
  const path = join(environment.XDG_CONFIG_HOME, 'google-chrome', 'NativeMessagingHosts', `${contract.host_name}.json`)
  try {
    const registered = JSON.parse(readFileSync(path, 'utf8'))
    const sameHost = realpathSync(registered.path) === realpathSync(hostExe)
    const sameOrigins = JSON.stringify(registered.allowed_origins) === JSON.stringify(contract.allowed_origins)
    return sameHost && sameOrigins
      ? { ok: true, value: registered.allowed_origins }
      : { ok: false, error: 'The desktop registered a native host that differs from the extension contract.' }
  } catch (error) {
    return { ok: false, error: `The desktop wrote no readable native-host registration: ${error.message}` }
  }
}

function failedTests(report) {
  if (!report) return 'no report was written.'
  const failed = report.testResults.flatMap((file) => file.assertionResults).filter((test) => test.status === 'failed')
  return failed.map((test) => `${test.title}: ${(test.failureMessages?.[0] ?? '').split('\n')[0].slice(0, 200)}`).join('; ') || 'no failing test was reported.'
}

function runExtensionSuite(extensionDirectory, environment, testNamePattern, evidenceDirectory) {
  if (!existsSync(join(extensionDirectory, 'node_modules'))) {
    throw new Error(`The extension checkout has no dependencies installed: run npm ci in ${extensionDirectory}.`)
  }
  const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm'
  const reportPath = join(evidenceDirectory, 'extension-suite-report.json')
  return new Promise((settle) => {
    const child = spawn(npm, [
      '--prefix', extensionDirectory, 'run', 'test:browser', '--',
      '--testNamePattern', testNamePattern,
      '--reporter=json',
      `--outputFile=${reportPath}`,
    ], { cwd: root, stdio: 'inherit', env: environment })
    child.once('exit', (status) => {
      let report = null
      try {
        report = JSON.parse(readFileSync(reportPath, 'utf8'))
      } catch {
        report = null
      }
      if (status !== 0) return settle({ ok: false, error: `The extension browser suite failed against the registered native host: ${failedTests(report)}` })
      if (!report || report.numFailedTests > 0) return settle({ ok: false, error: 'The extension browser run reported a failing native-host test.' })
      if (!(report.numPassedTests >= 1)) {
        return settle({ ok: false, error: 'The extension browser run matched no native-host test, so it proved nothing. Update the extension checkout or the test name pattern.' })
      }
      return settle({ ok: true, value: { passed: report.numPassedTests } })
    })
  })
}

async function waitForBrokerSocket(environment, desktop) {
  const socket = join(environment.XDG_RUNTIME_DIR, 'sesame', 'browser.sock')
  const deadline = Date.now() + 60_000
  while (Date.now() < deadline) {
    if (existsSync(socket)) return
    if (desktop.exitCode !== null) {
      throw new Error(`The desktop exited (code ${desktop.exitCode}) before creating its broker socket. Run under dbus-run-session to isolate the session bus.`)
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 250))
  }
  throw new Error('The desktop broker did not create its socket within 60 seconds.')
}

async function journey({ options, steps, call, approver, hostManifest, environment, testRoot, evidenceDirectory, fixtures }) {
  const [home, other] = fixtures
  const station = await openJourney({ extensionDirectory: options.extensionDirectory, scratch: testRoot, hostManifest, environment })
  try {
    const connection = await station.connect()
    const connected = connection?.diagnostic?.code === 'connected' && connection?.state === 'ready' && connection?.capabilities?.desktopAvailable === true
    recordStep(steps, 'extension.connect', {
      ok: connected,
      value: { state: connection?.state, code: connection?.diagnostic?.code },
      error: connected ? undefined : `The extension did not connect to a ready desktop: ${JSON.stringify({ state: connection?.state, code: connection?.diagnostic?.code })}`,
    })

    approver.allow(stationOriginPolicy([home.origin]))
    const approved = await station.attemptFill(`${home.origin}/login`)
    recordStep(steps, 'fill.approved', judgeApprovedFill(approved))
    if (!judgeApprovedFill(approved).ok) await station.capture(approved, join(evidenceDirectory, 'fill-approved.png'))
    await station.release(approved)

    const foreignBefore = promptCount(approver, other.origin)
    const foreign = await station.attemptFill(`${other.origin}/login`, { waitMs: 8_000 })
    const foreignJudgement = judgeRefusedFill(foreign, foreignBefore, approver, other.origin)
    recordStep(steps, 'fill.other-origin', foreignJudgement)
    if (!foreignJudgement.ok) await station.capture(foreign, join(evidenceDirectory, 'fill-other-origin.png'))
    await station.release(foreign)

    const locked = await call('lock_vault')
    if (!locked.ok) throw new Error(`The vault did not lock: ${locked.error}`)
    const lockedBefore = promptCount(approver, home.origin)
    const lockedAttempt = await station.attemptFill(`${home.origin}/login`, { waitMs: 8_000 })
    const lockedJudgement = judgeRefusedFill(lockedAttempt, lockedBefore, approver, home.origin)
    recordStep(steps, 'fill.locked', lockedJudgement)
    if (!lockedJudgement.ok) await station.capture(lockedAttempt, join(evidenceDirectory, 'fill-locked.png'))
    await station.release(lockedAttempt)
    await call('unlock_vault', { request: { masterPassword } })
  } finally {
    await station.close().catch(() => undefined)
  }
}

async function main() {
  if (process.platform !== 'linux') {
    console.log('The Linux extension native-host harness runs only on Linux; use npm run desktop:host:test on Windows.')
    return
  }

  const options = parseArguments(process.argv.slice(2))
  if (!existsSync(options.extensionDirectory)) throw new Error(`The extension checkout is missing: ${options.extensionDirectory}`)
  const contract = readHostContract(options.extensionDirectory)
  const testRoot = mkdtempSync(join(tmpdir(), 'sesame-extension-native-host-'))
  if (!brokerSocketFits(join(testRoot, 'runtime'))) {
    throw new Error(`The scratch folder ${testRoot} is too long for the desktop broker's Unix socket. Set TMPDIR to a shorter folder.`)
  }
  const evidenceDirectory = options.evidenceDirectory ?? join(testRoot, 'evidence')
  mkdirSync(evidenceDirectory, { recursive: true })
  buildBinaries(testRoot)

  const desktopEnvironment = scratchEnvironment(testRoot)
  const hostManifest = writeHostManifest(testRoot, contract)
  const browserEnvironment = {
    ...process.env,
    XDG_RUNTIME_DIR: desktopEnvironment.XDG_RUNTIME_DIR,
    SESAME_NATIVE_HOST_TEST: '1',
    SESAME_NATIVE_HOST_EXPECT_DESKTOP: '1',
    SESAME_NATIVE_HOST_MANIFEST: hostManifest,
  }
  if (process.env.SESAME_MANUAL_NATIVE_FILL === '1') browserEnvironment.SESAME_MANUAL_NATIVE_FILL = '1'
  if (process.env.SESAME_BROWSER_TEST_EXECUTABLE) browserEnvironment.SESAME_BROWSER_TEST_EXECUTABLE = process.env.SESAME_BROWSER_TEST_EXECUTABLE

  const steps = []
  const log = []
  const bridge = await openBridge(`extension-station-${Math.random().toString(16).slice(2)}${Date.now().toString(16)}`)
  const call = createCallQueue((command, args) => bridge.call(command, args))
  const fixtures = [await startFixtureServer(), await startFixtureServer()]
  const desktop = launchApp({ binary: desktopExe, root: testRoot, bridge, log, env: desktopEnvironment })
  const approver = createApprover({ call })
  let failure = null

  try {
    const connected = await bridge.waitForConnection()
    recordStep(steps, 'app.launch', { ok: connected, error: connected ? undefined : 'The desktop never connected to the test bridge.' })
    if (!connected) throw new Error('The desktop never connected to the test bridge.')
    await waitForBrokerSocket(desktopEnvironment, desktop)
    recordStep(steps, 'browser.registration', appRegisteredOrigins(desktopEnvironment, contract))

    const created = await call('create_vault', { request: { masterPassword } })
    recordStep(steps, 'vault.create', { ok: created.ok, error: created.error })
    const seeded = await call('save_login', {
      input: {
        title: fictionalLogin.title,
        url: `${fixtures[0].origin}/login`,
        username: fictionalLogin.username,
        password: fictionalLogin.password,
      },
    })
    recordStep(steps, 'vault.seed', { ok: seeded.ok, error: seeded.error })

    approver.allow((origin) => isLoopbackOrigin(origin))
    approver.start()
    recordStep(steps, 'extension.suite', await runExtensionSuite(options.extensionDirectory, browserEnvironment, options.testNamePattern, evidenceDirectory))
    await journey({ options, steps, call, approver, hostManifest, environment: browserEnvironment, testRoot, evidenceDirectory, fixtures })
    const clean = approver.failures.length === 0 && approver.refusals.length === 0
    recordStep(steps, 'approvals.expected', {
      ok: clean && approver.approvals.length > 0,
      value: { approved: approver.approvals.length },
      error: clean
        ? 'The desktop never asked for an approval.'
        : `Unexpected approvals: ${JSON.stringify([...approver.refusals, ...approver.failures])}`,
    })
  } catch (error) {
    failure = error
    steps.push({ name: 'station.error', ok: false, error: String(error.message ?? error) })
  } finally {
    await approver.stop()
    await stopApp(desktop)
    bridge.close()
    await Promise.all(fixtures.map((fixture) => fixture.close()))
    writeFileSync(join(evidenceDirectory, 'desktop.log'), log.join(''))
    const verdict = judgeStation(steps)
    writeFileSync(join(evidenceDirectory, 'report.json'), `${JSON.stringify({ verdict, steps, approvals: approver.approvals, refusals: approver.refusals, failures: approver.failures }, null, 2)}\n`)
    if (options.keep) console.log(`Kept the scratch environment at ${testRoot}`)
    else if (options.evidenceDirectory) rmSync(testRoot, { recursive: true, force: true })
    else if (verdict.ok) rmSync(testRoot, { recursive: true, force: true })
    else console.log(`Kept the evidence at ${evidenceDirectory}`)
  }

  const verdict = judgeStation(steps)
  for (const step of steps) console.log(`${step.ok ? 'ok  ' : 'FAIL'} ${step.name}${step.error ? `: ${step.error}` : ''}`)
  if (failure || !verdict.ok) {
    throw new Error(`The extension station failed. Missing steps: ${verdict.missing.join(', ') || 'none'}. Failed steps: ${verdict.failed.join(', ') || 'none'}.`)
  }
  console.log('The real extension answered through the real native host and the live desktop broker, and every refusal held.')
}

main().catch((error) => {
  console.error(error)
  process.exitCode = 1
})
