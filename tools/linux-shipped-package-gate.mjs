import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'

import { architectureName, browserHostName, chromeHostManifestMatches, launchApp, linuxBrowserEnvironment, platformName, readChromeHostManifest, sha256, stopApp } from './desktop-e2e-bridge.mjs'
import { repositoryRoot } from './vault-compatibility-gate.mjs'

const run = promisify(execFile)
const sha256Pattern = /^[0-9a-f]{64}$/
const elMachines = { x86_64: 0x3e, aarch64: 0xb7 }

export const SHIPPED_RUN_SCHEMA = 'sesame.linux-shipped-package-run/1'
export const RPM_RUN_SCHEMA = 'sesame.linux-rpm-shipped-package-run/1'
export const APPIMAGE_RUN_SCHEMA = 'sesame.linux-appimage-shipped-package-run/1'

export const requiredShippedSteps = [
  'package.metadata',
  'package.desktop_entry',
  'package.browser_host',
  'package.install',
  'app.launch',
  'app.stop',
  'browser.registration',
  'package.uninstall',
  'browser.registration_removed',
]
export const requiredUpgradeSteps = ['upgrade.previous_launch', 'upgrade.candidate_launch']
export const requiredRpmSteps = [
  'package.metadata',
  'package.install',
  'package.desktop_entry',
  'package.browser_host',
  'app.launch',
  'app.stop',
  'browser.registration',
  'package.uninstall',
  'browser.registration_removed',
]
export const requiredAppImageSteps = [
  'package.metadata',
  'package.install',
  'package.desktop_entry',
  'package.browser_host',
  'app.launch',
  'app.stop',
  'browser.registration_refused',
  'package.uninstall',
]

export const evidenceFilenameByFormat = {
  deb: 'linux-shipped-package.json',
  rpm: 'linux-rpm-shipped-package.json',
  appimage: 'linux-appimage-shipped-package.json',
}

export function formatForPackage(packagePath) {
  const name = path.basename(packagePath)
  if (name.endsWith('.deb')) return 'deb'
  if (name.endsWith('.rpm')) return 'rpm'
  if (name.endsWith('.AppImage')) return 'appimage'
  throw new Error(`Unsupported Linux package: ${name}`)
}

function parseArguments(argv) {
  const options = { installKind: 'dpkg', launchSeconds: 8 }
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    if (argument === '--package') options.package = argv[++index]
    else if (argument === '--format') options.format = argv[++index]
    else if (argument === '--previous') options.previous = argv[++index]
    else if (argument === '--out') options.out = argv[++index]
    else if (argument === '--install') options.installKind = argv[++index]
    else if (argument === '--launch-seconds') options.launchSeconds = Number(argv[++index])
    else if (argument === '--repo') options.repo = argv[++index]
    else if (argument === '--keep') options.keep = true
    else throw new Error(`Unknown argument: ${argument}`)
  }
  if (!options.package || !options.out) {
    throw new Error('Usage: node tools/linux-shipped-package-gate.mjs --package <deb|rpm|AppImage> --out <report-directory> [--format deb|rpm|appimage] [--previous <deb>] [--install dpkg|extracted] [--launch-seconds 8] [--repo <directory>] [--keep]')
  }
  options.format = options.format ?? formatForPackage(options.package)
  if (!Object.hasOwn(evidenceFilenameByFormat, options.format)) throw new Error(`Unknown Linux package format: ${options.format}`)
  if (!['dpkg', 'extracted'].includes(options.installKind)) throw new Error('The install kind must be dpkg or extracted.')
  if (options.format !== 'deb' && options.installKind !== 'dpkg') throw new Error('Only deb packages support the extracted install kind.')
  if (options.previous && options.format !== 'deb') throw new Error('The upgrade check only runs against deb packages.')
  if (options.previous && options.installKind !== 'dpkg') throw new Error('The upgrade check only runs against a real install.')
  if (!Number.isFinite(options.launchSeconds) || options.launchSeconds < 3) throw new Error('The launch window must be at least 3 seconds.')
  return options
}

async function command(executable, args, options = {}) {
  const { stdout } = await run(executable, args, { maxBuffer: 16 * 1024 * 1024, ...options })
  return stdout.trim()
}

function record(steps, name, ok, value, error) {
  const step = { name, ok: Boolean(ok) }
  if (value !== undefined) step.value = value
  if (error) step.error = String(error)
  steps.push(step)
  return step
}

async function executableFile(file) {
  const info = await stat(file).catch(() => null)
  return info?.isFile() === true && (info.mode & 0o111) !== 0
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
  const hostPath = path.join(staging, 'usr/bin/sesame-browser-host')
  const hostInfo = await stat(hostPath).catch(() => null)
  return {
    desktopEntry: /^Exec=.*\bsesame\b/m.test(desktopEntry) && desktopEntry.includes('Icon=sesame'),
    icon: (await stat(iconPath).catch(() => null))?.isFile() === true,
    browserHost: hostInfo?.isFile() === true && (hostInfo.mode & 0o111) !== 0,
  }
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

async function removeBrowserRegistration(environment) {
  await rm(path.join(environment.XDG_CONFIG_HOME, 'google-chrome', 'NativeMessagingHosts'), { recursive: true, force: true })
}

function registrationPaths(environment) {
  const manifest = `${browserHostName}.json`
  return [
    path.join(environment.XDG_CONFIG_HOME, 'google-chrome', 'NativeMessagingHosts', manifest),
    path.join(environment.XDG_CONFIG_HOME, 'chromium', 'NativeMessagingHosts', manifest),
    path.join(environment.XDG_CONFIG_HOME, 'microsoft-edge', 'NativeMessagingHosts', manifest),
    path.join(environment.HOME, '.mozilla', 'native-messaging-hosts', manifest),
  ]
}

async function registrationRemoved(environment) {
  for (const file of registrationPaths(environment)) {
    if ((await stat(file).catch(() => null)) !== null) return false
  }
  return true
}

const registrationEnvironment = (environment) => [`HOME=${environment.HOME}`, `XDG_CONFIG_HOME=${environment.XDG_CONFIG_HOME}`]

function elfMachine(bytes) {
  if (bytes.length < 20 || bytes[0] !== 0x7f || bytes.toString('latin1', 1, 4) !== 'ELF') {
    throw new Error('The AppImage payload does not carry an ELF application binary.')
  }
  return bytes[5] === 1 ? bytes.readUInt16LE(18) : bytes.readUInt16BE(18)
}

async function launchAndStop(binary, { launchSeconds, logPath, environment, extraEnv = {} }) {
  const log = []
  const child = launchApp({ binary, root: path.dirname(logPath), bridge: { port: 0, token: 'shipped-package-gate' }, log, env: { ...environment, ...extraEnv } })
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
  const host = listing.split('\n').find((line) => line.endsWith('/bin/sesame-browser-host'))
  if (!status.includes('install ok installed') || !binary || !host) throw new Error('dpkg did not install the package and its browser host into a bin directory.')
  return binary
}

function buildRecord({ schema, format, installKind, platform, architecture, version, package: packageRecord, previousPackage, binarySha256, steps, startedAt }) {
  const failed = steps.filter((step) => !step.ok).length
  return {
    schema,
    format,
    platform,
    architecture,
    version,
    installKind,
    package: packageRecord,
    previousPackage,
    binarySha256,
    steps: steps.map(({ name, ok, error }) => ({ name, ok, ...(error ? { error } : {}) })),
    result: failed === 0 ? 'passed' : 'failed',
    skipped: false,
    startedAt,
    finishedAt: new Date().toISOString(),
  }
}

async function runDebGate(context) {
  const { options, out, staging, environment, platform, architecture, version, expectedArchitecture, packagePath, packageBytes, packageSha256, steps, startedAt } = context
  await command('dpkg-deb', ['-x', packagePath, staging])
  const metadata = await packageMetadata(packagePath, expectedArchitecture)
  if (metadata.version !== version) throw new Error(`The package version ${metadata.version} does not match package.json ${version}.`)
  record(steps, 'package.metadata', true, metadata)
  const contents = await inspectContents(staging)
  record(steps, 'package.desktop_entry', contents.desktopEntry && contents.icon, contents)
  record(steps, 'package.browser_host', contents.browserHost)

  let binary
  let previousPackage = null
  if (options.installKind === 'dpkg') {
    binary = await installPackage(packagePath)
    record(steps, 'package.install', true, { installKind: 'dpkg', binary })
  } else {
    binary = path.join(staging, 'usr/bin/sesame')
    record(steps, 'package.install', true, { installKind: 'extracted', binary })
  }
  const binarySha256 = sha256(await readFile(binary))

  if (options.previous) {
    const previousPath = path.resolve(options.previous)
    const previousBytes = await readFile(previousPath)
    const previousMetadata = await packageMetadata(previousPath, expectedArchitecture)
    previousPackage = { filename: path.basename(previousPath), sha256: sha256(previousBytes), bytes: previousBytes.length, ...previousMetadata }
    const previousBinary = await installPackage(previousPath)
    const previousAlive = await launchAndStop(previousBinary, { launchSeconds: options.launchSeconds, logPath: path.join(out, 'linux-previous-launch.log'), environment })
    record(steps, 'upgrade.previous_launch', previousAlive, undefined, previousAlive ? undefined : 'The previous package exited before the launch window closed.')
    await removeBrowserRegistration(environment)
    binary = await installPackage(packagePath)
    const candidateAlive = await launchAndStop(binary, { launchSeconds: options.launchSeconds, logPath: path.join(out, 'linux-upgrade-launch.log'), environment })
    record(steps, 'upgrade.candidate_launch', candidateAlive, undefined, candidateAlive ? undefined : 'The candidate exited before the launch window closed.')
  }

  const alive = await launchAndStop(binary, { launchSeconds: options.launchSeconds, logPath: path.join(out, 'linux-launch.log'), environment })
  record(steps, 'app.launch', alive, undefined, alive ? undefined : 'The installed app exited before the launch window closed.')
  record(steps, 'app.stop', true)
  const registration = browserRegistration(binary, environment)
  record(steps, 'browser.registration', registration.ok, registration.value, registration.error)

  if (options.installKind === 'dpkg') {
    await command('sudo', ['-n', 'env', ...registrationEnvironment(environment), 'dpkg', '-r', metadata.name])
    let stillInstalled = true
    try {
      await command('dpkg-query', ['-W', metadata.name])
    } catch {
      stillInstalled = false
    }
    const desktopGone = (await stat('/usr/share/applications/Sesame.desktop').catch(() => null)) === null
    record(steps, 'package.uninstall', !stillInstalled && desktopGone && (await stat(binary).catch(() => null)) === null)
  } else {
    await command(path.join(staging, 'usr/bin/sesame-browser-host'), ['unregister'], { env: { ...process.env, ...environment } }).catch(() => null)
    await rm(staging, { recursive: true, force: true })
    record(steps, 'package.uninstall', (await stat(staging).catch(() => null)) === null)
  }
  const removed = await registrationRemoved(environment)
  record(steps, 'browser.registration_removed', removed, undefined, removed ? undefined : 'The uninstall left a native-host manifest behind.')

  return buildRecord({
    schema: SHIPPED_RUN_SCHEMA,
    format: 'deb',
    installKind: options.installKind,
    platform,
    architecture,
    version,
    package: { filename: path.basename(packagePath), sha256: packageSha256, bytes: packageBytes.length, ...metadata },
    previousPackage,
    binarySha256,
    steps,
    startedAt,
  })
}

async function runRpmGate(context) {
  const { out, environment, platform, architecture, version, expectedRpmArchitecture, rpmDatabase, packagePath, packageBytes, packageSha256, steps, startedAt } = context
  const rpm = (...args) => command('rpm', ['--dbpath', rpmDatabase, ...args])
  const [name, rpmVersion, release, rpmArchitecture] = await Promise.all([
    rpm('-qp', '--qf', '%{NAME}', packagePath),
    rpm('-qp', '--qf', '%{VERSION}', packagePath),
    rpm('-qp', '--qf', '%{RELEASE}', packagePath),
    rpm('-qp', '--qf', '%{ARCH}', packagePath),
  ])
  if (name !== 'sesame' || rpmVersion !== version || rpmArchitecture !== expectedRpmArchitecture) {
    throw new Error(`The package identity is wrong: ${name} ${rpmVersion} ${rpmArchitecture}.`)
  }
  record(steps, 'package.metadata', true, { name, version: rpmVersion, release, architecture: rpmArchitecture })

  await command('sudo', ['-n', 'rpm', '--dbpath', rpmDatabase, '-i', '--nodeps', '--force', packagePath])
  const installedName = await rpm('-q', '--qf', '%{NAME}', name)
  const listing = await rpm('-ql', name)
  const binary = listing.split('\n').find((line) => line.endsWith('/bin/sesame'))
  const host = listing.split('\n').find((line) => line.endsWith('/bin/sesame-browser-host'))
  if (installedName !== name || !binary || !host) throw new Error('rpm did not install the package and its browser host into a bin directory.')
  record(steps, 'package.install', true, { installKind: 'rpm', binary })

  const desktopPath = '/usr/share/applications/Sesame.desktop'
  const desktopEntry = await readFile(desktopPath, 'utf8').catch(() => '')
  const icon = await stat('/usr/share/icons/hicolor/512x512/apps/sesame.png').catch(() => null)
  record(steps, 'package.desktop_entry', /^Exec=.*\bsesame\b/m.test(desktopEntry) && desktopEntry.includes('Icon=sesame') && icon?.isFile() === true)
  record(steps, 'package.browser_host', await executableFile(host))
  const binarySha256 = sha256(await readFile(binary))

  const alive = await launchAndStop(binary, { launchSeconds: context.options.launchSeconds, logPath: path.join(out, 'linux-rpm-launch.log'), environment })
  record(steps, 'app.launch', alive, undefined, alive ? undefined : 'The installed app exited before the launch window closed.')
  record(steps, 'app.stop', true)
  const registration = browserRegistration(binary, environment)
  record(steps, 'browser.registration', registration.ok, registration.value, registration.error)

  await command('sudo', ['-n', 'env', ...registrationEnvironment(environment), 'rpm', '--dbpath', rpmDatabase, '-e', '--nodeps', name])
  let stillInstalled = true
  try {
    await rpm('-q', name)
  } catch {
    stillInstalled = false
  }
  const desktopGone = (await stat(desktopPath).catch(() => null)) === null
  record(steps, 'package.uninstall', !stillInstalled && desktopGone && (await stat(binary).catch(() => null)) === null)
  const removed = await registrationRemoved(environment)
  record(steps, 'browser.registration_removed', removed, undefined, removed ? undefined : 'The rpm removal left a native-host manifest behind.')

  return buildRecord({
    schema: RPM_RUN_SCHEMA,
    format: 'rpm',
    installKind: 'rpm',
    platform,
    architecture,
    version,
    package: { filename: path.basename(packagePath), sha256: packageSha256, bytes: packageBytes.length, name, version: rpmVersion, release, architecture: rpmArchitecture },
    previousPackage: null,
    binarySha256,
    steps,
    startedAt,
  })
}

async function runAppImageGate(context) {
  const { staging, environment, platform, architecture, version, expectedElfMachine, packagePath, packageBytes, packageSha256, steps, startedAt } = context
  const filename = path.basename(packagePath)
  if (!filename.includes(`_${version}_`)) throw new Error(`The AppImage name ${filename} does not carry version ${version}.`)
  await command(packagePath, ['--appimage-extract'], { cwd: staging })
  const appDir = path.join(staging, 'squashfs-root')
  const binary = path.join(appDir, 'usr/bin/sesame')
  const host = path.join(appDir, 'usr/bin/sesame-browser-host')
  const binaryBytes = await readFile(binary)
  if (elfMachine(binaryBytes) !== expectedElfMachine) throw new Error(`The AppImage payload architecture does not match ${architecture}.`)
  record(steps, 'package.metadata', true, { filename, version, architecture })
  record(steps, 'package.install', true, { installKind: 'appimage-extract', binary })

  const desktopPath = path.join(appDir, 'usr/share/applications/Sesame.desktop')
  const desktopEntry = await readFile(desktopPath, 'utf8').catch(() => '')
  const icon = await stat(path.join(appDir, 'usr/share/icons/hicolor/512x512/apps/sesame.png')).catch(() => null)
  record(steps, 'package.desktop_entry', /^Exec=.*\bsesame\b/m.test(desktopEntry) && desktopEntry.includes('Icon=sesame') && icon?.isFile() === true)
  record(steps, 'package.browser_host', await executableFile(host))
  const binarySha256 = sha256(binaryBytes)

  await removeBrowserRegistration(environment)
  const alive = await launchAndStop(packagePath, { launchSeconds: context.options.launchSeconds, logPath: path.join(context.out, 'linux-appimage-launch.log'), environment, extraEnv: { APPIMAGE_EXTRACT_AND_RUN: '1' } })
  record(steps, 'app.launch', alive, undefined, alive ? undefined : 'The AppImage exited before the launch window closed.')
  record(steps, 'app.stop', true)
  const refused = await registrationRemoved(environment)
  record(steps, 'browser.registration_refused', refused, undefined, refused ? undefined : 'The AppImage registered a persistent native-host manifest.')

  await rm(staging, { recursive: true, force: true })
  record(steps, 'package.uninstall', (await stat(staging).catch(() => null)) === null)

  return buildRecord({
    schema: APPIMAGE_RUN_SCHEMA,
    format: 'appimage',
    installKind: 'appimage-extract',
    platform,
    architecture,
    version,
    package: { filename, sha256: packageSha256, bytes: packageBytes.length, version, architecture },
    previousPackage: null,
    binarySha256,
    steps,
    startedAt,
  })
}

function validateGateRecord(evidence, { schema, format, installKind, steps: requiredSteps, label, installError }) {
  if (evidence?.schema !== schema) throw new Error(`The ${label} record has the wrong schema.`)
  if (evidence.format !== format) throw new Error(`The ${label} record has the wrong format.`)
  if (evidence.result !== 'passed' || evidence.skipped === true) throw new Error(`The ${label} run did not pass.`)
  if (installKind && evidence.installKind !== installKind) throw new Error(installError)
  if (!sha256Pattern.test(evidence.package?.sha256 ?? '') || !sha256Pattern.test(evidence.binarySha256 ?? '')) {
    throw new Error(`The ${label} record does not bind the package and binary digests.`)
  }
  const required = evidence.previousPackage ? [...requiredSteps, ...requiredUpgradeSteps] : requiredSteps
  for (const name of required) {
    const step = (evidence.steps ?? []).find((entry) => entry.name === name)
    if (!step || step.ok !== true) throw new Error(`The ${label} run did not pass ${name}.`)
  }
  return evidence
}

export function validateLinuxShippedEvidence(evidence, { requireInstall = true } = {}) {
  return validateGateRecord(evidence, {
    schema: SHIPPED_RUN_SCHEMA,
    format: 'deb',
    installKind: requireInstall ? 'dpkg' : null,
    steps: requiredShippedSteps,
    label: 'shipped-package',
    installError: 'The release lane only counts a real package installation, not an extracted tree.',
  })
}

export function validateLinuxRpmShippedEvidence(evidence, { requireInstall = true } = {}) {
  return validateGateRecord(evidence, {
    schema: RPM_RUN_SCHEMA,
    format: 'rpm',
    installKind: requireInstall ? 'rpm' : null,
    steps: requiredRpmSteps,
    label: 'rpm shipped-package',
    installError: 'The release lane only counts a real rpm installation.',
  })
}

export function validateLinuxAppImageShippedEvidence(evidence, { requireInstall = true } = {}) {
  return validateGateRecord(evidence, {
    schema: APPIMAGE_RUN_SCHEMA,
    format: 'appimage',
    installKind: requireInstall ? 'appimage-extract' : null,
    steps: requiredAppImageSteps,
    label: 'AppImage shipped-package',
    installError: 'The release lane only counts an extracted AppImage payload.',
  })
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
  const startedAt = new Date().toISOString()

  const workRoot = await mkdtemp(path.join(tmpdir(), 'sesame-shipped-package-'))
  const staging = path.join(workRoot, 'staging')
  const rpmDatabase = path.join(workRoot, 'rpmdb')
  const environment = linuxBrowserEnvironment(workRoot)
  await mkdir(staging, { recursive: true })
  await mkdir(rpmDatabase, { recursive: true })

  const context = {
    options,
    out,
    staging,
    rpmDatabase,
    environment,
    version,
    architecture,
    platform,
    expectedArchitecture: architecture === 'x86_64' ? 'amd64' : 'arm64',
    expectedRpmArchitecture: architecture,
    expectedElfMachine: elMachines[architecture],
    packagePath,
    packageBytes,
    packageSha256,
    startedAt,
    steps: [],
  }
  const runners = { deb: runDebGate, rpm: runRpmGate, appimage: runAppImageGate }

  try {
    const evidence = await runners[options.format](context)
    await writeFile(path.join(out, evidenceFilenameByFormat[options.format]), `${JSON.stringify(evidence, null, 2)}\n`)
    process.stdout.write(`Linux shipped ${options.format}: ${evidence.result}, ${context.steps.filter((step) => step.ok).length}/${context.steps.length} steps passed.\n`)
    return evidence.result === 'passed' ? 0 : 1
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
