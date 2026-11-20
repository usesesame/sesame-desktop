import { execFile } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'

import { architectureName, chromeHostManifestMatches, evidenceStep, judgeAppStop, launchApp, linuxBrowserEnvironment, openBridge, platformName, readChromeHostManifest, recordStep, sha256, stopApp } from './desktop-e2e-bridge.mjs'
import { runVaultRestoreGate } from './run-vault-restore-gate.mjs'
import { repositoryRoot } from './vault-compatibility-gate.mjs'

const run = promisify(execFile)
const sha256Pattern = /^[0-9a-f]{64}$/

export const PACKAGE_RUN_SCHEMA = 'sesame.linux-installed-package-run/1'
export const requiredPackageSteps = [
  'package.metadata',
  'package.desktop_entry',
  'package.browser_host',
  'package.install',
  'app.launch',
  'browser.registration',
  'webview.features',
  'vault.create',
  'login.save',
  'vault.backup.verified',
  'vault.backup.entries',
  'vault.lock',
  'vault.unlock',
  'login.read_after_unlock',
  'app.stop',
  'app.restart',
  'restart.unlock',
  'restart.login.read',
  'login.edit',
  'login.read_after_edit',
  'login.delete',
  'login.gone',
  'login.gone_after_unlock',
  'restart.stop',
  'package.uninstall',
]

export const journeyMasterPassword = 'fictional package validation'
export const journeyLogin = {
  title: 'Northwind mail',
  url: 'https://northwind.example/sign-in',
  username: 'ada.lovelace.example',
  password: 'fictional-journey-password-one',
}
export const journeyEditedPassword = 'fictional-journey-password-two'

function parseArguments(argv) {
  const options = { installKind: 'dpkg' }
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    if (argument === '--package') options.package = argv[++index]
    else if (argument === '--out') options.out = argv[++index]
    else if (argument === '--install') options.installKind = argv[++index]
    else if (argument === '--skip-restore') options.skipRestore = true
    else if (argument === '--repo') options.repo = argv[++index]
    else if (argument === '--keep') options.keep = true
    else throw new Error(`Unknown argument: ${argument}`)
  }
  if (!options.package || !options.out) {
    throw new Error('Usage: node tools/linux-installed-package-gate.mjs --package <deb> --out <report-directory> [--install dpkg|extracted] [--skip-restore] [--repo <directory>] [--keep]')
  }
  if (!['dpkg', 'extracted'].includes(options.installKind)) throw new Error('The install kind must be dpkg or extracted.')
  return options
}

async function command(executable, args) {
  const { stdout } = await run(executable, args, { maxBuffer: 16 * 1024 * 1024 })
  return stdout.trim()
}

async function executableFile(path) {
  const info = await stat(path).catch(() => null)
  return info?.isFile() === true && (info.mode & 0o111) !== 0
}

function recordStop(steps, name, stop) {
  const judged = judgeAppStop(stop)
  return recordStep(steps, name, judged, { value: judged.value, evidence: true })
}

function browserRegistration(binary, environment) {
  const manifest = readChromeHostManifest(environment)
  const expectedHost = path.join(path.dirname(binary), 'sesame-browser-host')
  const ok = chromeHostManifestMatches(manifest, expectedHost)
  return {
    ok,
    value: { host: manifest.path ?? null, allowedOrigins: manifest.allowed_origins ?? [] },
    error: ok ? undefined : 'The installed app did not register a matching Chrome native-host manifest.',
  }
}

export const disabledWebviewFeatures = ['webgl', 'webgl2', 'audioContext', 'mediaDevices', 'mediaElements']

export function judgeWebviewFeatures(result) {
  if (!result?.ok) return { ok: false, error: result?.error ?? 'no result' }
  const offered = disabledWebviewFeatures.filter((feature) => result.value?.[feature] !== false)
  return offered.length === 0
    ? { ok: true, value: result.value }
    : { ok: false, error: `The running webview still offers ${offered.join(', ')}.` }
}

export function loginInput(login, id) {
  return {
    ...(id ? { id } : {}),
    title: login.title,
    url: login.url,
    urls: [],
    tags: [],
    username: login.username,
    email: '',
    password: login.password,
    folder: '',
    backupCodes: [],
    keepBackupCodes: false,
    recoveryEmail: '',
    recoveryPhone: '',
    recoveryNotApplicable: false,
    notes: '',
  }
}

export function judgeLoginReadBack(expected, card, password) {
  const differing = []
  if (card?.title !== expected.title) differing.push('title')
  if (card?.url !== expected.url) differing.push('url')
  if (card?.username !== expected.username) differing.push('username')
  if (card?.hasPassword !== true || password !== expected.password) differing.push('password')
  return differing.length === 0
    ? { ok: true }
    : { ok: false, error: `The saved login read back differently in these fields: ${differing.join(', ')}.` }
}

function noLoginSaved(action) {
  return { ok: false, error: `No login was saved, so there is nothing to ${action}.` }
}

function failure(result, fallback) {
  return String(result?.error ?? fallback)
}

export async function readLogin(bridge, id, expected) {
  if (!id) return { ok: false, error: 'No login was saved, so there is nothing to read back.' }
  const card = await bridge.call('get_login_card', { id })
  if (!card.ok) return { ok: false, error: failure(card, 'The saved login could not be opened.') }
  const granted = await bridge.call('grant_presence', { secret: journeyMasterPassword })
  if (!granted.ok) return { ok: false, error: failure(granted, 'The vault password was not accepted for revealing the login.') }
  const revealed = await bridge.call('reveal_login_secret', { id })
  if (!revealed.ok) return { ok: false, error: failure(revealed, 'The saved password could not be revealed.') }
  return judgeLoginReadBack(expected, card.value, revealed.value)
}

export function judgeLoginGone({ id, snapshot, card }) {
  if (!id) return { ok: false, error: 'No login was saved, so its removal cannot be checked.' }
  if (!Array.isArray(snapshot?.entries)) return { ok: false, error: 'The vault listing could not be read after the delete.' }
  if (snapshot.entries.some((entry) => entry.id === id)) return { ok: false, error: 'The deleted login is still listed in the vault.' }
  if (card?.ok === true) return { ok: false, error: 'The deleted login can still be opened.' }
  if (!/no longer exists/.test(String(card?.error ?? ''))) return { ok: false, error: `Opening the deleted login failed for another reason: ${failure(card, 'no result')}` }
  return { ok: true }
}

async function checkLoginGone(bridge, id, snapshotResult) {
  const snapshot = snapshotResult.ok ? snapshotResult.value : undefined
  return judgeLoginGone({ id, snapshot, card: id ? await bridge.call('get_login_card', { id }) : undefined })
}

async function relock(bridge, steps, lockName, unlockName) {
  recordStep(steps, lockName, await bridge.call('lock_vault', {}))
  return recordStep(steps, unlockName, await bridge.call('unlock_vault', { request: { masterPassword: journeyMasterPassword } }))
}

export async function driveFirstSession({ bridge, steps, journey, vaultRoot }) {
  recordStep(steps, 'vault.status.before', await bridge.call('get_vault_status', {}))
  recordStep(steps, 'vault.create', await bridge.call('create_vault', { request: { masterPassword: journeyMasterPassword } }))
  const created = await bridge.call('get_vault_status', {})
  recordStep(steps, 'vault.status.unlocked', { ok: created.ok && created.value?.exists === true && created.value?.unlocked === true, value: created.value, error: created.error })
  const before = await bridge.call('get_vault_snapshot', {})
  journey.baselineEntries = before.ok && Array.isArray(before.value?.entries) ? before.value.entries.length : null
  const saved = recordStep(steps, 'login.save', await bridge.call('save_login', { input: loginInput(journeyLogin) }))
  journey.loginId = saved.ok && typeof saved.value?.id === 'string' ? saved.value.id : null
  const backup = recordStep(steps, 'vault.backup.created', await bridge.call('create_backup', {}))
  if (backup.ok) {
    const verified = recordStep(steps, 'vault.backup.verified', await bridge.call('verify_backup', { request: { source: path.join(vaultRoot, 'backups', backup.value), secret: journeyMasterPassword } }))
    const expectedEntries = journey.baselineEntries === null ? null : journey.baselineEntries + 1
    recordStep(steps, 'vault.backup.entries', {
      ok: verified.ok && expectedEntries !== null && verified.value?.entryCount === expectedEntries,
      error: 'The verified backup does not hold the saved login.',
    })
  }
  await relock(bridge, steps, 'vault.lock', 'vault.unlock')
  recordStep(steps, 'login.read_after_unlock', await readLogin(bridge, journey.loginId, journeyLogin))
}

export async function driveRestartSession({ bridge, steps, journey }) {
  const status = recordStep(steps, 'restart.status', await bridge.call('get_vault_status', {}))
  recordStep(steps, 'restart.status.locked', { ok: status.value?.exists === true && status.value?.unlocked === false })
  recordStep(steps, 'restart.unlock', await bridge.call('unlock_vault', { request: { masterPassword: journeyMasterPassword } }))
  recordStep(steps, 'restart.login.read', await readLogin(bridge, journey.loginId, journeyLogin))

  const edited = { ...journeyLogin, password: journeyEditedPassword }
  const edit = journey.loginId ? await bridge.call('save_login', { input: loginInput(edited, journey.loginId) }) : noLoginSaved('edit')
  const updatedInPlace = edit.ok && edit.value?.id === journey.loginId
  recordStep(steps, 'login.edit', edit.ok && !updatedInPlace ? { ok: false, error: 'Editing the login saved a second login instead of updating it.' } : edit)
  await relock(bridge, steps, 'login.edit.lock', 'login.edit.unlock')
  recordStep(steps, 'login.read_after_edit', await readLogin(bridge, journey.loginId, edited))

  recordStep(steps, 'login.delete', journey.loginId ? await bridge.call('delete_login', { id: journey.loginId }) : noLoginSaved('delete'))
  recordStep(steps, 'login.gone', await checkLoginGone(bridge, journey.loginId, await bridge.call('get_vault_snapshot', {})))
  const unlocked = await relock(bridge, steps, 'login.delete.lock', 'login.delete.unlock')
  recordStep(steps, 'login.gone_after_unlock', await checkLoginGone(bridge, journey.loginId, { ok: unlocked.ok, value: unlocked.value }))
}

async function runAppLifecycle({ binary, vaultRoot, logPath, environment, journey }) {
  const steps = []
  const log = []
  const bridge = await openBridge(`linux-package-${randomBytes(16).toString('hex')}`)
  const child = launchApp({ binary, root: vaultRoot, bridge, log, env: environment })
  try {
    const connected = await bridge.waitForConnection()
    recordStep(steps, 'app.launch', { ok: connected, error: connected ? undefined : 'The installed app never connected to the test bridge.' })
    if (!connected) return steps
    recordStep(steps, 'browser.registration', browserRegistration(binary, environment))
    recordStep(steps, 'webview.features', judgeWebviewFeatures(await bridge.call('desktop_e2e_webview_features', {})))
    await driveFirstSession({ bridge, steps, journey, vaultRoot })
  } catch (error) {
    recordStep(steps, 'app.launch', { ok: false, error: String(error.message ?? error) })
  } finally {
    recordStop(steps, 'app.stop', await stopApp(child))
    bridge.close()
    await writeFile(logPath, log.join(''))
  }
  return steps
}

async function runRestartLifecycle({ binary, vaultRoot, logPath, environment, journey }) {
  const steps = []
  const log = []
  const bridge = await openBridge(`linux-package-${randomBytes(16).toString('hex')}`)
  const child = launchApp({ binary, root: vaultRoot, bridge, log, env: environment })
  try {
    const connected = await bridge.waitForConnection()
    recordStep(steps, 'app.restart', { ok: connected, error: connected ? undefined : 'The restarted app never connected to the test bridge.' })
    if (!connected) return steps
    await driveRestartSession({ bridge, steps, journey })
  } catch (error) {
    recordStep(steps, 'app.restart', { ok: false, error: String(error.message ?? error) })
  } finally {
    recordStop(steps, 'restart.stop', await stopApp(child))
    bridge.close()
    await writeFile(logPath, log.join(''))
  }
  return steps
}

export function validateLinuxPackageEvidence(evidence, { requireInstall = true } = {}) {
  if (evidence?.schema !== PACKAGE_RUN_SCHEMA) throw new Error('The installed-package record has the wrong schema.')
  if (evidence.result !== 'passed' || evidence.skipped === true) throw new Error('The installed-package run did not pass.')
  if (evidence.buildKind !== 'tauri-wdio-test-package') throw new Error('The release lane only counts an installed test-featured package.')
  if (requireInstall && evidence.installKind !== 'dpkg') throw new Error('The release lane only counts a real package installation, not an extracted tree.')
  if (!sha256Pattern.test(evidence.package?.sha256 ?? '') || !sha256Pattern.test(evidence.binarySha256 ?? '')) {
    throw new Error('The installed-package record does not bind the package and binary digests.')
  }
  for (const name of requiredPackageSteps) {
    const step = (evidence.steps ?? []).find((entry) => entry.name === name)
    if (!step || step.ok !== true) throw new Error(`The installed-package run did not pass ${name}.`)
  }
  if (!evidence.restore || evidence.restore.failed !== 0 || (evidence.restore.runs ?? []).length < 5) {
    throw new Error('The installed-package run carries no passing historical restore corpus.')
  }
  for (const fixture of evidence.restore.runs) {
    if (fixture.result !== 'passed') throw new Error(`The installed-package run failed fixture ${fixture.fixtureId}.`)
  }
  return evidence
}

async function main() {
  const options = parseArguments(process.argv.slice(2))
  const repo = options.repo ? path.resolve(options.repo) : repositoryRoot
  const out = path.resolve(options.out)
  await mkdir(out, { recursive: true })

  const packagePath = path.resolve(options.package)
  const packageInfo = await stat(packagePath).catch(() => null)
  if (!packageInfo?.isFile()) throw new Error(`The package is missing: ${packagePath}`)
  const packageBytes = await readFile(packagePath)
  const packageSha256 = sha256(packageBytes)
  const platform = platformName()
  if (platform !== 'linux') throw new Error('The installed-package gate only runs on Linux.')
  const architecture = architectureName()
  const version = JSON.parse(await readFile(path.join(repo, 'package.json'), 'utf8')).version
  const startedAt = new Date().toISOString()

  const [name, packageVersion, packageArchitecture] = await Promise.all([
    command('dpkg-deb', ['-f', packagePath, 'Package']),
    command('dpkg-deb', ['-f', packagePath, 'Version']),
    command('dpkg-deb', ['-f', packagePath, 'Architecture']),
  ])
  const expectedArchitecture = architecture === 'x86_64' ? 'amd64' : 'arm64'
  if (name !== 'sesame' || packageVersion !== version || packageArchitecture !== expectedArchitecture) {
    throw new Error(`The package identity does not match the release: ${name} ${packageVersion} ${packageArchitecture}.`)
  }

  const workRoot = options.keep ? path.join(out, 'work') : await mkdtemp(path.join(tmpdir(), 'sesame-linux-package-'))
  await rm(workRoot, { recursive: true, force: true })
  const staging = path.join(workRoot, 'staging')
  const vaultRoot = path.join(workRoot, 'vault')
  await mkdir(staging, { recursive: true })
  await mkdir(vaultRoot, { recursive: true })
  await command('dpkg-deb', ['-x', packagePath, staging])

  const desktopPath = path.join(staging, 'usr/share/applications/Sesame.desktop')
  const desktopEntry = await readFile(desktopPath, 'utf8').catch(() => '')
  const iconPath = path.join(staging, 'usr/share/icons/hicolor/512x512/apps/sesame.png')
  const binName = 'sesame'
  const hostName = 'sesame-browser-host'
  const steps = []
  recordStep(steps, 'package.metadata', { ok: true, value: { name, version: packageVersion, architecture: packageArchitecture } })
  recordStep(steps, 'package.desktop_entry', {
    ok: /^Exec=.*\bsesame\b/m.test(desktopEntry) && String(desktopEntry).includes('Icon=sesame') && (await stat(iconPath).catch(() => null))?.isFile() === true,
  })
  recordStep(steps, 'package.browser_host', {
    ok: await executableFile(path.join(staging, 'usr/bin', hostName)),
  })

  let installedBinary = path.join(staging, 'usr/bin', binName)
  if (options.installKind === 'dpkg') {
    try {
      await command('sudo', ['-n', 'dpkg', '-i', packagePath])
      const status = await command('dpkg-query', ['-W', '-f=${Status}', name])
      const listing = await command('dpkg-query', ['-L', name])
      const installedPath = listing.split('\n').find((line) => line.endsWith(`/bin/${binName}`))
      const installedHost = listing.split('\n').find((line) => line.endsWith(`/bin/${hostName}`))
      if (!status.includes('install ok installed') || !installedPath || !installedHost) throw new Error('dpkg did not install the package and its browser host into a bin directory.')
      installedBinary = installedPath
      recordStep(steps, 'package.install', { ok: true, value: { installKind: 'dpkg', binary: installedBinary } })
    } catch (error) {
      recordStep(steps, 'package.install', { ok: false, error: String(error.message ?? error) })
      throw new Error(`The package installation failed: ${error.message ?? error}`, { cause: error })
    }
  } else {
    recordStep(steps, 'package.install', { ok: true, value: { installKind: 'extracted', binary: installedBinary } })
  }

  const environment = linuxBrowserEnvironment(workRoot)
  const binarySha256 = sha256(await readFile(installedBinary))
  const journey = { loginId: null, baselineEntries: null }
  steps.push(...await runAppLifecycle({ binary: installedBinary, vaultRoot, logPath: path.join(out, 'linux-package-launch.log'), environment, journey }))
  steps.push(...await runRestartLifecycle({ binary: installedBinary, vaultRoot, logPath: path.join(out, 'linux-package-restart.log'), environment, journey }))

  let restore = null
  if (!options.skipRestore) {
    const result = await runVaultRestoreGate({ binary: installedBinary, out: path.join(out, 'restore'), repo })
    restore = { failed: result.failed, runs: result.runs.map((entry) => ({ fixtureId: entry.fixtureId, result: entry.result, reportSha256: entry.reportSha256 })) }
  }

  if (options.installKind === 'dpkg') {
    try {
      await command('sudo', ['-n', 'dpkg', '-r', name])
      let stillInstalled = true
      try {
        await command('dpkg-query', ['-W', name])
      } catch {
        stillInstalled = false
      }
      recordStep(steps, 'package.uninstall', { ok: !stillInstalled && (await stat(installedBinary).catch(() => null)) === null })
    } catch (error) {
      recordStep(steps, 'package.uninstall', { ok: false, error: String(error.message ?? error) })
    }
  } else {
    await rm(staging, { recursive: true, force: true })
    recordStep(steps, 'package.uninstall', { ok: (await stat(staging).catch(() => null)) === null })
  }

  const failed = steps.filter((step) => !step.ok).length + (restore?.failed ?? (options.skipRestore ? 0 : 1))
  const record = {
    schema: PACKAGE_RUN_SCHEMA,
    platform,
    architecture,
    version,
    buildKind: 'tauri-wdio-test-package',
    installKind: options.installKind,
    package: { filename: path.basename(packagePath), sha256: packageSha256, bytes: packageBytes.length, name, version: packageVersion, architecture: packageArchitecture },
    binarySha256,
    steps: steps.map(evidenceStep),
    restore,
    result: failed === 0 ? 'passed' : 'failed',
    skipped: options.skipRestore === true,
    startedAt,
    finishedAt: new Date().toISOString(),
  }
  await writeFile(path.join(out, 'linux-installed-package.json'), `${JSON.stringify(record, null, 2)}\n`)
  if (!options.keep) await rm(workRoot, { recursive: true, force: true })
  process.stdout.write(`Linux installed package: ${record.result}, ${steps.filter((step) => step.ok).length}/${steps.length} steps passed${restore ? `, ${restore.runs.filter((entry) => entry.result === 'passed').length}/${restore.runs.length} fixtures passed` : ''}.\n`)
  return record.result === 'passed' ? 0 : 1
}

const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
if (invokedDirectly) {
  main().then((code) => {
    process.exitCode = code
  }).catch((error) => {
    process.stderr.write(`${error.message ?? error}\n`)
    process.exitCode = 2
  })
}
