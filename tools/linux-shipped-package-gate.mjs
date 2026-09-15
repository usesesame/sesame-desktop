import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'

import { architectureName, launchApp, platformName, sha256, stopApp } from './desktop-e2e-bridge.mjs'
import { repositoryRoot } from './vault-compatibility-gate.mjs'

const run = promisify(execFile)
const sha256Pattern = /^[0-9a-f]{64}$/

export const SHIPPED_RUN_SCHEMA = 'sesame.linux-shipped-package-run/1'
export const requiredShippedSteps = [
  'package.metadata',
  'package.desktop_entry',
  'package.install',
  'app.launch',
  'app.stop',
  'package.uninstall',
]
export const requiredUpgradeSteps = ['upgrade.previous_launch', 'upgrade.candidate_launch']

function parseArguments(argv) {
  const options = { installKind: 'dpkg', launchSeconds: 8 }
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    if (argument === '--package') options.package = argv[++index]
    else if (argument === '--previous') options.previous = argv[++index]
    else if (argument === '--out') options.out = argv[++index]
    else if (argument === '--install') options.installKind = argv[++index]
    else if (argument === '--launch-seconds') options.launchSeconds = Number(argv[++index])
    else if (argument === '--repo') options.repo = argv[++index]
    else if (argument === '--keep') options.keep = true
    else throw new Error(`Unknown argument: ${argument}`)
  }
  if (!options.package || !options.out) {
    throw new Error('Usage: node tools/linux-shipped-package-gate.mjs --package <deb> --out <report-directory> [--previous <deb>] [--install dpkg|extracted] [--launch-seconds 8] [--repo <directory>] [--keep]')
  }
  if (!['dpkg', 'extracted'].includes(options.installKind)) throw new Error('The install kind must be dpkg or extracted.')
  if (options.previous && options.installKind !== 'dpkg') throw new Error('The upgrade check only runs against a real install.')
  if (!Number.isFinite(options.launchSeconds) || options.launchSeconds < 3) throw new Error('The launch window must be at least 3 seconds.')
  return options
}

async function command(executable, args) {
  const { stdout } = await run(executable, args, { maxBuffer: 16 * 1024 * 1024 })
  return stdout.trim()
}

function record(steps, name, ok, value, error) {
  const step = { name, ok: Boolean(ok) }
  if (value !== undefined) step.value = value
  if (error) step.error = String(error)
  steps.push(step)
  return step
}

async function packageMetadata(packagePath, expectedArchitecture) {
  const [name, version, architecture] = await Promise.all([
    command('dpkg-deb', ['-f', packagePath, 'Package']),
    command('dpkg-deb', ['-f', packagePath, 'Version']),
    command('dpkg-deb', ['-f', packagePath, 'Architecture']),
  ])
  if (name !== 'sesame' || architecture !== expectedArchitecture) {
    throw new Error(`The package identity is wrong: ${name} ${version} ${architecture}.`)
  }
  return { name, version, architecture }
}

async function inspectContents(staging) {
  const desktopPath = path.join(staging, 'usr/share/applications/Sesame.desktop')
  const desktopEntry = await readFile(desktopPath, 'utf8').catch(() => '')
  const iconPath = path.join(staging, 'usr/share/icons/hicolor/512x512/apps/sesame.png')
  return {
    desktopEntry: /^Exec=.*\bsesame\b/m.test(desktopEntry) && desktopEntry.includes('Icon=sesame'),
    icon: (await stat(iconPath).catch(() => null))?.isFile() === true,
  }
}

async function launchAndStop(binary, { launchSeconds, logPath }) {
  const log = []
  const child = launchApp({ binary, root: path.dirname(logPath), bridge: { port: 0, token: 'shipped-package-gate' }, log })
  await new Promise((resolve) => setTimeout(resolve, launchSeconds * 1000))
  const alive = child.exitCode === null
  await stopApp(child)
  await writeFile(logPath, log.join(''))
  return alive
}

async function installPackage(packagePath) {
  await command('sudo', ['-n', 'dpkg', '-i', packagePath])
  const status = await command('dpkg-query', ['-W', '-f=${Status}', 'sesame'])
  const listing = await command('dpkg-query', ['-L', 'sesame'])
  const binary = listing.split('\n').find((line) => line.endsWith('/bin/sesame'))
  if (!status.includes('install ok installed') || !binary) throw new Error('dpkg did not install the package into a bin directory.')
  return binary
}

export function validateLinuxShippedEvidence(evidence, { requireInstall = true } = {}) {
  if (evidence?.schema !== SHIPPED_RUN_SCHEMA) throw new Error('The shipped-package record has the wrong schema.')
  if (evidence.result !== 'passed' || evidence.skipped === true) throw new Error('The shipped-package run did not pass.')
  if (requireInstall && evidence.installKind !== 'dpkg') throw new Error('The release lane only counts a real package installation, not an extracted tree.')
  if (!sha256Pattern.test(evidence.package?.sha256 ?? '') || !sha256Pattern.test(evidence.binarySha256 ?? '')) {
    throw new Error('The shipped-package record does not bind the package and binary digests.')
  }
  const required = evidence.previousPackage ? [...requiredShippedSteps, ...requiredUpgradeSteps] : requiredShippedSteps
  for (const name of required) {
    const step = (evidence.steps ?? []).find((entry) => entry.name === name)
    if (!step || step.ok !== true) throw new Error(`The shipped-package run did not pass ${name}.`)
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
  if (platform !== 'linux') throw new Error('The shipped-package gate only runs on Linux.')
  const architecture = architectureName()
  const version = JSON.parse(await readFile(path.join(repo, 'package.json'), 'utf8')).version
  const expectedArchitecture = architecture === 'x86_64' ? 'amd64' : 'arm64'
  const startedAt = new Date().toISOString()
  const steps = []

  const workRoot = await mkdtemp(path.join(tmpdir(), 'sesame-shipped-package-'))
  const staging = path.join(workRoot, 'staging')
  await mkdir(staging, { recursive: true })
  await command('dpkg-deb', ['-x', packagePath, staging])

  try {
    const metadata = await packageMetadata(packagePath, expectedArchitecture)
    if (metadata.version !== version) throw new Error(`The package version ${metadata.version} does not match package.json ${version}.`)
    record(steps, 'package.metadata', true, metadata)
    const contents = await inspectContents(staging)
    record(steps, 'package.desktop_entry', contents.desktopEntry && contents.icon, contents)

    let binary
    if (options.installKind === 'dpkg') {
      binary = await installPackage(packagePath)
      record(steps, 'package.install', true, { installKind: 'dpkg', binary })
    } else {
      binary = path.join(staging, 'usr/bin/sesame')
      record(steps, 'package.install', true, { installKind: 'extracted', binary })
    }
    const binarySha256 = sha256(await readFile(binary))

    let previousPackage = null
    if (options.previous) {
      const previousPath = path.resolve(options.previous)
      const previousBytes = await readFile(previousPath)
      const previousMetadata = await packageMetadata(previousPath, expectedArchitecture)
      previousPackage = { filename: path.basename(previousPath), sha256: sha256(previousBytes), bytes: previousBytes.length, ...previousMetadata }
      const previousBinary = await installPackage(previousPath)
      const previousAlive = await launchAndStop(previousBinary, { launchSeconds: options.launchSeconds, logPath: path.join(out, 'linux-previous-launch.log') })
      record(steps, 'upgrade.previous_launch', previousAlive, undefined, previousAlive ? undefined : 'The previous package exited before the launch window closed.')
      binary = await installPackage(packagePath)
      const candidateAlive = await launchAndStop(binary, { launchSeconds: options.launchSeconds, logPath: path.join(out, 'linux-upgrade-launch.log') })
      record(steps, 'upgrade.candidate_launch', candidateAlive, undefined, candidateAlive ? undefined : 'The candidate exited before the launch window closed.')
    }

    const alive = await launchAndStop(binary, { launchSeconds: options.launchSeconds, logPath: path.join(out, 'linux-launch.log') })
    record(steps, 'app.launch', alive, undefined, alive ? undefined : 'The installed app exited before the launch window closed.')
    record(steps, 'app.stop', true)

    if (options.installKind === 'dpkg') {
      await command('sudo', ['-n', 'dpkg', '-r', 'sesame'])
      let stillInstalled = true
      try {
        await command('dpkg-query', ['-W', 'sesame'])
      } catch {
        stillInstalled = false
      }
      const desktopGone = (await stat('/usr/share/applications/Sesame.desktop').catch(() => null)) === null
      record(steps, 'package.uninstall', !stillInstalled && desktopGone && (await stat(binary).catch(() => null)) === null)
    } else {
      await rm(staging, { recursive: true, force: true })
      record(steps, 'package.uninstall', (await stat(staging).catch(() => null)) === null)
    }

    const failed = steps.filter((step) => !step.ok).length
    const result = {
      schema: SHIPPED_RUN_SCHEMA,
      platform,
      architecture,
      version,
      installKind: options.installKind,
      package: { filename: path.basename(packagePath), sha256: packageSha256, bytes: packageBytes.length, ...metadata },
      previousPackage,
      binarySha256,
      steps: steps.map(({ name, ok, error }) => ({ name, ok, ...(error ? { error } : {}) })),
      result: failed === 0 ? 'passed' : 'failed',
      skipped: false,
      startedAt,
      finishedAt: new Date().toISOString(),
    }
    await writeFile(path.join(out, 'linux-shipped-package.json'), `${JSON.stringify(result, null, 2)}\n`)
    process.stdout.write(`Linux shipped package: ${result.result}, ${steps.filter((step) => step.ok).length}/${steps.length} steps passed.\n`)
    return result.result === 'passed' ? 0 : 1
  } finally {
    if (!options.keep) await rm(workRoot, { recursive: true, force: true })
  }
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
