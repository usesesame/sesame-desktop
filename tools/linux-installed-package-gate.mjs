import { execFile } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'

import { architectureName, launchApp, openBridge, platformName, recordStep, sha256, stopApp } from './desktop-e2e-bridge.mjs'
import { runVaultRestoreGate } from './run-vault-restore-gate.mjs'
import { repositoryRoot } from './vault-compatibility-gate.mjs'

const run = promisify(execFile)
const sha256Pattern = /^[0-9a-f]{64}$/

export const PACKAGE_RUN_SCHEMA = 'sesame.linux-installed-package-run/1'
export const requiredPackageSteps = [
  'package.metadata',
  'package.desktop_entry',
  'package.install',
  'app.launch',
  'vault.create',
  'vault.backup.verified',
  'vault.lock',
  'vault.unlock',
  'app.restart',
  'restart.unlock',
  'package.uninstall',
]

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

async function runAppLifecycle({ binary, vaultRoot, logPath }) {
  const steps = []
  const log = []
  const bridge = await openBridge(`linux-package-${randomBytes(16).toString('hex')}`)
  const child = launchApp({ binary, root: vaultRoot, bridge, log })
  try {
    const connected = await bridge.waitForConnection()
    recordStep(steps, 'app.launch', { ok: connected, error: connected ? undefined : 'The installed app never connected to the test bridge.' })
    if (!connected) return steps
    recordStep(steps, 'vault.status.before', await bridge.call('get_vault_status', {}))
    recordStep(steps, 'vault.create', await bridge.call('create_vault', { request: { masterPassword: 'fictional package validation' } }))
    const created = await bridge.call('get_vault_status', {})
    recordStep(steps, 'vault.status.unlocked', { ok: created.ok && created.value?.exists === true && created.value?.unlocked === true, value: created.value, error: created.error })
    const backup = recordStep(steps, 'vault.backup.created', await bridge.call('create_backup', {}))
    if (backup.ok) {
      recordStep(steps, 'vault.backup.verified', await bridge.call('verify_backup', { request: { source: path.join(vaultRoot, 'backups', backup.value), secret: 'fictional package validation' } }))
    }
    recordStep(steps, 'vault.lock', await bridge.call('lock_vault', {}))
    recordStep(steps, 'vault.unlock', await bridge.call('unlock_vault', { request: { masterPassword: 'fictional package validation' } }))
  } catch (error) {
    recordStep(steps, 'app.launch', { ok: false, error: String(error.message ?? error) })
  } finally {
    await stopApp(child)
    bridge.close()
    await writeFile(logPath, log.join(''))
  }
  return steps
}

async function runRestartLifecycle({ binary, vaultRoot, logPath }) {
  const steps = []
  const log = []
  const bridge = await openBridge(`linux-package-${randomBytes(16).toString('hex')}`)
  const child = launchApp({ binary, root: vaultRoot, bridge, log })
  try {
    const connected = await bridge.waitForConnection()
    recordStep(steps, 'app.restart', { ok: connected, error: connected ? undefined : 'The restarted app never connected to the test bridge.' })
    if (!connected) return steps
    const status = recordStep(steps, 'restart.status', await bridge.call('get_vault_status', {}))
    recordStep(steps, 'restart.status.locked', { ok: status.value?.exists === true && status.value?.unlocked === false })
    recordStep(steps, 'restart.unlock', await bridge.call('unlock_vault', { request: { masterPassword: 'fictional package validation' } }))
  } catch (error) {
    recordStep(steps, 'app.restart', { ok: false, error: String(error.message ?? error) })
  } finally {
    await stopApp(child)
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
  const steps = []
  recordStep(steps, 'package.metadata', { ok: true, value: { name, version: packageVersion, architecture: packageArchitecture } })
  recordStep(steps, 'package.desktop_entry', {
    ok: /^Exec=.*\bsesame\b/m.test(desktopEntry) && String(desktopEntry).includes('Icon=sesame') && (await stat(iconPath).catch(() => null))?.isFile() === true,
  })

  let installedBinary = path.join(staging, 'usr/bin', binName)
  if (options.installKind === 'dpkg') {
    try {
      await command('sudo', ['-n', 'dpkg', '-i', packagePath])
      const status = await command('dpkg-query', ['-W', '-f=${Status}', name])
      const listing = await command('dpkg-query', ['-L', name])
      const installedPath = listing.split('\n').find((line) => line.endsWith(`/bin/${binName}`))
      if (!status.includes('install ok installed') || !installedPath) throw new Error('dpkg did not install the package into a bin directory.')
      installedBinary = installedPath
      recordStep(steps, 'package.install', { ok: true, value: { installKind: 'dpkg', binary: installedBinary } })
    } catch (error) {
      recordStep(steps, 'package.install', { ok: false, error: String(error.message ?? error) })
      throw new Error(`The package installation failed: ${error.message ?? error}`, { cause: error })
    }
  } else {
    recordStep(steps, 'package.install', { ok: true, value: { installKind: 'extracted', binary: installedBinary } })
  }

  const binarySha256 = sha256(await readFile(installedBinary))
  steps.push(...await runAppLifecycle({ binary: installedBinary, vaultRoot, logPath: path.join(out, 'linux-package-launch.log') }))
  steps.push(...await runRestartLifecycle({ binary: installedBinary, vaultRoot, logPath: path.join(out, 'linux-package-restart.log') }))

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
    steps: steps.map(({ name: stepName, ok, error }) => ({ name: stepName, ok, ...(error ? { error } : {}) })),
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
