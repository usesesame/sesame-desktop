import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { PACKAGE_RUN_SCHEMA, requiredPackageSteps, validateLinuxPackageEvidence } from './linux-installed-package-gate.mjs'
import { APPIMAGE_RUN_SCHEMA, RPM_RUN_SCHEMA, SHIPPED_RUN_SCHEMA, apprunHooksForceX11, evidenceFilenameByFormat, formatForPackage, requiredAppImageSteps, requiredRpmSteps, requiredShippedSteps, shippedPackageRuntimeRootBase, shippedPackageWorkRootBase, validateLinuxAppImageShippedEvidence, validateLinuxRpmShippedEvidence, validateLinuxShippedEvidence } from './linux-shipped-package-gate.mjs'
import { fetchTool, installPinnedTool, pinnedBundleTools, verifiedCliVersion } from './prepare-linux-bundle-tools.mjs'
import { appProcessAlive, chromeHostManifestMatches, linuxBrowserEnvironment, pinnedChromeOrigin, storeChromeOrigin, trustedChromeOrigins } from './desktop-e2e-bridge.mjs'

const repository = process.cwd()

function workflowJob(workflow, name) {
  const job = workflow.split(/\r?\n {2}(?=[\w-]+:)/).find((entry) => entry.startsWith(`${name}:`))
  assert.ok(job, `the workflow has no ${name} job`)
  return job
}

function workflowRunSteps(job) {
  return job.split(/\r?\n {6}- /).slice(1).map((step) => {
    const lines = step.split(/\r?\n/)
    const start = lines.findIndex((line) => /^(?: {8})?run:/.test(line))
    if (start === -1) return ''
    const first = lines[start].trim().slice('run:'.length).trim()
    const body = ['|', '|-', '>', '>-'].includes(first) ? [] : [first]
    for (const line of lines.slice(start + 1)) {
      if (line.trim() && !/^ {10}/.test(line)) break
      body.push(line.trimStart())
    }
    return body.filter((line) => !line.startsWith('#')).join('\n').replace(/\\\r?\n/g, ' ')
  })
}

const bundlerFetchedToolNames = [
  'AppRun-x86_64',
  'linuxdeploy-07333c6-x86_64.AppImage',
  'linuxdeploy-plugin-appimage.AppImage',
]

function shippedRecord(overrides = {}) {
  return {
    schema: SHIPPED_RUN_SCHEMA,
    format: 'deb',
    platform: 'linux',
    architecture: 'x86_64',
    version: '1.2.3',
    installKind: 'dpkg',
    package: { filename: 'Sesame_1.2.3_amd64.deb', sha256: 'a'.repeat(64), bytes: 1024, name: 'sesame', version: '1.2.3', architecture: 'amd64' },
    previousPackage: null,
    binarySha256: 'b'.repeat(64),
    steps: requiredShippedSteps.map((name) => ({ name, ok: true })),
    result: 'passed',
    skipped: false,
    startedAt: '2026-09-13T00:00:00.000Z',
    finishedAt: '2026-09-13T00:05:00.000Z',
    ...overrides,
  }
}

function rpmRecord(overrides = {}) {
  return {
    schema: RPM_RUN_SCHEMA,
    format: 'rpm',
    platform: 'linux',
    architecture: 'x86_64',
    version: '1.2.3',
    installKind: 'rpm',
    package: { filename: 'Sesame-1.2.3-1.x86_64.rpm', sha256: 'd'.repeat(64), bytes: 2048, name: 'sesame', version: '1.2.3', release: '1', architecture: 'x86_64' },
    previousPackage: null,
    binarySha256: 'e'.repeat(64),
    steps: requiredRpmSteps.map((name) => ({ name, ok: true })),
    result: 'passed',
    skipped: false,
    startedAt: '2026-09-13T00:00:00.000Z',
    finishedAt: '2026-09-13T00:05:00.000Z',
    ...overrides,
  }
}

function appimageRecord(overrides = {}) {
  return {
    schema: APPIMAGE_RUN_SCHEMA,
    format: 'appimage',
    platform: 'linux',
    architecture: 'x86_64',
    version: '1.2.3',
    installKind: 'appimage-extract',
    package: { filename: 'Sesame_1.2.3_amd64.AppImage', sha256: 'f'.repeat(64), bytes: 4096, version: '1.2.3', architecture: 'x86_64' },
    previousPackage: null,
    binarySha256: 'a'.repeat(64),
    steps: requiredAppImageSteps.map((name) => ({ name, ok: true })),
    result: 'passed',
    skipped: false,
    startedAt: '2026-09-13T00:00:00.000Z',
    finishedAt: '2026-09-13T00:05:00.000Z',
    ...overrides,
  }
}

function packageRecord(overrides = {}) {
  return {
    schema: PACKAGE_RUN_SCHEMA,
    platform: 'linux',
    architecture: 'x86_64',
    version: '1.2.3',
    buildKind: 'tauri-wdio-test-package',
    installKind: 'dpkg',
    package: { filename: 'Sesame_1.2.3_amd64.deb', sha256: 'a'.repeat(64), bytes: 1024, name: 'sesame', version: '1.2.3', architecture: 'amd64' },
    binarySha256: 'b'.repeat(64),
    steps: requiredPackageSteps.map((name) => ({ name, ok: true })),
    restore: {
      failed: 0,
      runs: ['v0.1.0', 'v0.1.1', 'v0.2.0', 'v0.2.1', 'v0.2.2'].map((fixtureId) => ({ fixtureId, result: 'passed', reportSha256: 'c'.repeat(64) })),
    },
    result: 'passed',
    skipped: false,
    startedAt: '2026-09-13T00:00:00.000Z',
    finishedAt: '2026-09-13T00:30:00.000Z',
    ...overrides,
  }
}

test('a real install with the full restore corpus satisfies the release lane', () => {
  const evidence = packageRecord()
  assert.equal(validateLinuxPackageEvidence(evidence), evidence)
})

test('an extracted tree cannot stand in for an installed package', () => {
  assert.throws(() => validateLinuxPackageEvidence(packageRecord({ installKind: 'extracted' })), /real package installation/)
  assert.equal(validateLinuxPackageEvidence(packageRecord({ installKind: 'extracted' }), { requireInstall: false }).installKind, 'extracted')
})

test('a skipped, failed, or incomplete package run is not evidence', () => {
  assert.throws(() => validateLinuxPackageEvidence(packageRecord({ skipped: true })), /did not pass/)
  assert.throws(() => validateLinuxPackageEvidence(packageRecord({ result: 'failed' })), /did not pass/)
  const missingStep = packageRecord()
  missingStep.steps = missingStep.steps.filter((step) => step.name !== 'package.uninstall')
  assert.throws(() => validateLinuxPackageEvidence(missingStep), /did not pass package.uninstall/)
  const failedStep = packageRecord()
  failedStep.steps = failedStep.steps.map((step) => step.name === 'restart.unlock' ? { ...step, ok: false } : step)
  assert.throws(() => validateLinuxPackageEvidence(failedStep), /did not pass restart.unlock/)
})

test('a package run without the historical fixtures is not evidence', () => {
  assert.throws(() => validateLinuxPackageEvidence(packageRecord({ restore: null })), /historical restore corpus/)
  assert.throws(() => validateLinuxPackageEvidence(packageRecord({ restore: { failed: 1, runs: [] } })), /historical restore corpus/)
  const failedFixture = packageRecord()
  failedFixture.restore = structuredClone(failedFixture.restore)
  failedFixture.restore.runs[2].result = 'failed'
  assert.throws(() => validateLinuxPackageEvidence(failedFixture), /failed fixture v0.2.0/)
})

test('a package run must bind both digests and carry the test-package identity', () => {
  assert.throws(() => validateLinuxPackageEvidence(packageRecord({ package: { filename: 'Sesame.deb', sha256: 'nope', bytes: 1 } })), /package and binary digests/)
  assert.throws(() => validateLinuxPackageEvidence(packageRecord({ binarySha256: undefined })), /package and binary digests/)
  assert.throws(() => validateLinuxPackageEvidence(packageRecord({ buildKind: 'release' })), /test-featured package/)
})

test('Linux CI installs a package and runs the gate before the build finishes', async () => {
  const workflow = await readFile(path.join(repository, '.github', 'workflows', 'ci.yml'), 'utf8')
  assert.match(workflow, /linux-installed-package-gate\.mjs/, 'the Linux job does not run the installed-package gate')
  assert.match(workflow, /xvfb-run -a node tools\/linux-installed-package-gate\.mjs/, 'the installed-package gate is not run under a display server')
  const job = workflow.slice(workflow.indexOf('  linux-installed:'), workflow.indexOf('  desktop-linux:'))
  assert.match(job, /--bundles deb/, 'the Linux job does not build the deb the gate installs')
  assert.match(job, /--features wdio/, 'the Linux job does not build the test-featured package the gate drives')
})

test('the gate refuses non-Linux and non-deb inputs', async () => {
  const source = await readFile(path.join(repository, 'tools', 'linux-installed-package-gate.mjs'), 'utf8')
  assert.match(source, /if \(platform !== 'linux'\) throw new Error/)
  assert.match(source, /dpkg-deb/)
  assert.match(source, /sudo', \['-n', 'dpkg', '-i'/)
})

test('the shipped manifest check pins the host path, type, and the two trusted origins', () => {
  const manifest = {
    name: 'app.usesesame.browser',
    type: 'stdio',
    path: '/usr/bin/sesame-browser-host',
    allowed_origins: trustedChromeOrigins,
  }
  assert.equal(chromeHostManifestMatches(manifest, '/usr/bin/sesame-browser-host'), true)
  assert.equal(chromeHostManifestMatches({ ...manifest, path: '/tmp/sesame-browser-host' }, '/usr/bin/sesame-browser-host'), false)
  assert.equal(chromeHostManifestMatches({ ...manifest, type: 'ws' }, '/usr/bin/sesame-browser-host'), false)
  assert.equal(chromeHostManifestMatches({ ...manifest, allowed_origins: ['chrome-extension://other/'] }, '/usr/bin/sesame-browser-host'), false)
  assert.equal(chromeHostManifestMatches({ ...manifest, allowed_origins: [pinnedChromeOrigin, pinnedChromeOrigin] }, '/usr/bin/sesame-browser-host'), false)
  assert.equal(chromeHostManifestMatches({ ...manifest, allowed_origins: [pinnedChromeOrigin] }, '/usr/bin/sesame-browser-host'), false)
  assert.equal(chromeHostManifestMatches({ ...manifest, allowed_origins: [storeChromeOrigin] }, '/usr/bin/sesame-browser-host'), false)
  assert.equal(chromeHostManifestMatches({ ...manifest, allowed_origins: [...trustedChromeOrigins, 'chrome-extension://other/'] }, '/usr/bin/sesame-browser-host'), false)
  assert.equal(chromeHostManifestMatches({ ...manifest, allowed_origins: ['chrome-extension://*/'] }, '/usr/bin/sesame-browser-host'), false)
  assert.equal(chromeHostManifestMatches({ ...manifest, name: 'app.other.browser' }, '/usr/bin/sesame-browser-host'), false)
  assert.equal(chromeHostManifestMatches({}, '/usr/bin/sesame-browser-host'), false)
})

test('both package gates require the shipped host and its startup registration', () => {
  assert.ok(requiredPackageSteps.includes('package.browser_host'))
  assert.ok(requiredPackageSteps.includes('browser.registration'))
  assert.ok(requiredShippedSteps.includes('package.browser_host'))
  assert.ok(requiredShippedSteps.includes('browser.registration'))
})

test('Linux CI proves host registration and the live broker exchange', async () => {
  const workflow = await readFile(path.join(repository, '.github', 'workflows', 'ci.yml'), 'utf8')
  assert.match(workflow, /dbus-run-session -- node tools\/test-browser-host-pipe\.mjs/, 'the Linux job does not run the native-host pipe test')
  const harness = await readFile(path.join(repository, 'tools', 'test-browser-host-pipe.mjs'), 'utf8')
  assert.match(harness, /\['register'\]/, 'the harness does not exercise the register verb')
  assert.match(harness, /\['unregister'\]/, 'the harness does not exercise the unregister verb')
  assert.match(harness, /verifyChromiumManifest\(location\)/, 'the harness does not validate every Chromium manifest')
  assert.match(harness, /verifyFirefoxManifest\(location\)/, 'the harness does not validate the Firefox manifest')
  assert.doesNotMatch(harness, /Windows-only/, 'the harness still skips the Linux path')
})

test('both package gates require an executable browser host', async () => {
  for (const file of ['linux-installed-package-gate.mjs', 'linux-shipped-package-gate.mjs']) {
    const source = await readFile(path.join(repository, 'tools', file), 'utf8')
    assert.match(source, /0o111/, `${file} does not require the host to be executable`)
  }
})

test('the shipped deb record still satisfies the release lane', () => {
  const evidence = shippedRecord()
  assert.equal(validateLinuxShippedEvidence(evidence), evidence)
  assert.throws(() => validateLinuxShippedEvidence(shippedRecord({ installKind: 'extracted' })), /real package installation/)
  assert.equal(validateLinuxShippedEvidence(shippedRecord({ installKind: 'extracted' }), { requireInstall: false }).installKind, 'extracted')
})

test('a shipped deb run without native-host cleanup is not evidence', () => {
  const missing = shippedRecord()
  missing.steps = missing.steps.filter((step) => step.name !== 'browser.registration_removed')
  assert.throws(() => validateLinuxShippedEvidence(missing), /did not pass browser\.registration_removed/)
})

test('the rpm shipped record requires a real install and native-host cleanup', () => {
  const evidence = rpmRecord()
  assert.equal(validateLinuxRpmShippedEvidence(evidence), evidence)
  const missing = rpmRecord()
  missing.steps = missing.steps.filter((step) => step.name !== 'browser.registration_removed')
  assert.throws(() => validateLinuxRpmShippedEvidence(missing), /did not pass browser\.registration_removed/)
  assert.throws(() => validateLinuxRpmShippedEvidence(rpmRecord({ installKind: 'extracted' })), /real rpm installation/)
  assert.throws(() => validateLinuxRpmShippedEvidence(rpmRecord({ skipped: true })), /did not pass/)
  assert.throws(() => validateLinuxRpmShippedEvidence({ ...rpmRecord(), schema: SHIPPED_RUN_SCHEMA }), /wrong schema/)
})

test('the AppImage shipped record requires an extracted payload and a staged registration', () => {
  const evidence = appimageRecord()
  assert.equal(validateLinuxAppImageShippedEvidence(evidence), evidence)
  const missing = appimageRecord()
  missing.steps = missing.steps.filter((step) => step.name !== 'browser.registration_staged')
  assert.throws(() => validateLinuxAppImageShippedEvidence(missing), /did not pass browser\.registration_staged/)
  assert.throws(() => validateLinuxAppImageShippedEvidence(appimageRecord({ schema: RPM_RUN_SCHEMA })), /wrong schema/)
  assert.throws(() => validateLinuxAppImageShippedEvidence(appimageRecord({ binarySha256: 'nope' })), /package and binary digests/)
  assert.ok(!requiredAppImageSteps.includes('package.uninstall'), 'the AppImage gate must not require an uninstall step that only deletes its own staging directory')
})

test('the AppImage gate keeps the documented display backend trade', async () => {
  assert.equal(apprunHooksForceX11(['export GDK_BACKEND=x11\n']), true)
  assert.equal(apprunHooksForceX11(['export GTK_THEME=dark\n', 'export GDK_BACKEND=x11\n']), true)
  assert.equal(apprunHooksForceX11(['export GDK_BACKEND=wayland\n']), false)
  assert.equal(apprunHooksForceX11([]), false)
  assert.ok(requiredAppImageSteps.includes('package.display_backend'))
  const missing = appimageRecord()
  missing.steps = missing.steps.filter((step) => step.name !== 'package.display_backend')
  assert.throws(() => validateLinuxAppImageShippedEvidence(missing), /did not pass package\.display_backend/)
  const source = await readFile(path.join(repository, 'tools', 'linux-shipped-package-gate.mjs'), 'utf8')
  assert.match(source, /apprun-hooks/, 'the AppImage gate does not read the apprun hooks')
  assert.match(source, /apprunHooksForceX11/, 'the AppImage gate does not assert the x11 hook')
})

test('the shipped evidence filenames and format inference stay stable', () => {
  assert.deepEqual(evidenceFilenameByFormat, {
    deb: 'linux-shipped-package.json',
    rpm: 'linux-rpm-shipped-package.json',
    appimage: 'linux-appimage-shipped-package.json',
  })
  assert.equal(formatForPackage('/tmp/Sesame_1.2.3_amd64.deb'), 'deb')
  assert.equal(formatForPackage('/tmp/Sesame-1.2.3-1.x86_64.rpm'), 'rpm')
  assert.equal(formatForPackage('/tmp/Sesame_1.2.3_amd64.AppImage'), 'appimage')
  assert.throws(() => formatForPackage('/tmp/Sesame-1.2.3.dmg'), /Unsupported Linux package/)
})

test('the gate exercises rpm installs, AppImage extraction, and both cleanup paths', async () => {
  const source = await readFile(path.join(repository, 'tools', 'linux-shipped-package-gate.mjs'), 'utf8')
  assert.match(source, /const rpm = \(\.\.\.args\) => command\('rpm', \['--dbpath', rpmDatabase, \.\.\.args\]\)/)
  assert.match(source, /'rpm', '--dbpath', rpmDatabase, '-i', '--nodeps', '--force'/)
  assert.match(source, /'rpm', '--dbpath', rpmDatabase, '-e', '--nodeps'/)
  assert.match(source, /'dpkg', '-r'/)
  assert.match(source, /--appimage-extract/)
  assert.match(source, /APPIMAGE_EXTRACT_AND_RUN/)
  assert.ok(requiredRpmSteps.includes('browser.registration_removed'))
  assert.ok(requiredAppImageSteps.includes('browser.registration_staged'))
  for (const steps of [requiredShippedSteps, requiredRpmSteps, requiredAppImageSteps]) {
    assert.ok(steps.includes('browser.host_reaches_app'), 'a shipped format does not prove its browser helper reaches the running app')
  }
  assert.match(source, /hostReachesApp\(environment, context\.capabilitiesRequest\)/)
})

test('the shipped package work root stays outside the RPM scriptlet private mounts', async () => {
  assert.equal(shippedPackageWorkRootBase('/tmp'), '/var/tmp')
  assert.equal(shippedPackageWorkRootBase('/tmp/sesame-run'), '/var/tmp')
  assert.equal(shippedPackageWorkRootBase('/home/runner'), '/var/tmp')
  assert.equal(shippedPackageWorkRootBase('/home'), '/var/tmp')
  assert.equal(shippedPackageWorkRootBase('/tmp-other'), '/tmp-other')
  assert.equal(shippedPackageWorkRootBase('/home-other'), '/home-other')
  assert.equal(shippedPackageWorkRootBase('/var/tmp/sesame-run'), '/var/tmp/sesame-run')
  const source = await readFile(path.join(repository, 'tools', 'linux-shipped-package-gate.mjs'), 'utf8')
  assert.match(source, /mkdtemp\(path\.join\(shippedPackageWorkRootBase\(\), 'sesame-shipped-package-'\)\)/)
})

test('the shipped package runtime stays outside the WebKit symlink target', async () => {
  assert.equal(shippedPackageRuntimeRootBase('/tmp'), '/tmp')
  assert.equal(shippedPackageRuntimeRootBase('/home/runner'), '/home/runner')
  assert.equal(shippedPackageRuntimeRootBase('/var/tmp'), '/tmp')
  assert.equal(shippedPackageRuntimeRootBase('/var/tmp/sesame-run'), '/tmp')
  assert.equal(shippedPackageRuntimeRootBase('/var/tmp-other'), '/var/tmp-other')
  const source = await readFile(path.join(repository, 'tools', 'linux-shipped-package-gate.mjs'), 'utf8')
  assert.match(source, /mkdtemp\(path\.join\(shippedPackageRuntimeRootBase\(\), 'sesame-shipped-runtime-'\)\)/)
  assert.match(source, /linuxBrowserEnvironment\(workRoot, runtimeRoot\)/)
  assert.match(source, /rm\(runtimeRoot, \{ recursive: true, force: true \}\)/)
})

test('the browser environment can keep its runtime outside the fixture root', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'sesame-environment-root-'))
  const runtimeRoot = await mkdtemp(path.join(tmpdir(), 'sesame-environment-runtime-'))
  try {
    const environment = linuxBrowserEnvironment(root, runtimeRoot)
    assert.equal(environment.HOME, path.join(root, 'browser-home'))
    assert.equal(environment.XDG_CONFIG_HOME, path.join(root, 'browser-config'))
    assert.equal(environment.XDG_DATA_HOME, path.join(root, 'browser-data'))
    assert.equal(environment.XDG_CACHE_HOME, path.join(root, 'browser-cache'))
    assert.equal(environment.XDG_RUNTIME_DIR, path.join(runtimeRoot, 'browser-runtime'))
    assert.equal(linuxBrowserEnvironment(root).XDG_RUNTIME_DIR, path.join(root, 'browser-runtime'))
    if (process.platform !== 'win32') {
      for (const directory of Object.values(environment)) {
        assert.equal((await stat(directory)).mode & 0o777, 0o700, `${directory} is not private`)
      }
    }
  } finally {
    await rm(root, { recursive: true, force: true })
    await rm(runtimeRoot, { recursive: true, force: true })
  }
})

test('a signal-terminated app is not counted as alive', async () => {
  assert.equal(appProcessAlive({ exitCode: null, signalCode: 'SIGABRT' }), false)
  assert.equal(appProcessAlive({ exitCode: null, signalCode: null }), true)
  assert.equal(appProcessAlive({ exitCode: 0, signalCode: null }), false)
  assert.equal(appProcessAlive(null), false)
  if (process.platform === 'win32') return
  const terminated = spawn(process.execPath, ['-e', 'setTimeout(() => process.kill(process.pid, "SIGTERM"), 50)'], { stdio: 'ignore' })
  const terminatedExit = new Promise((resolve) => terminated.once('exit', resolve))
  await terminatedExit
  assert.equal(terminated.exitCode, null)
  assert.equal(terminated.signalCode, 'SIGTERM')
  assert.equal(appProcessAlive(terminated), false)
  const running = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 5000)'], { stdio: 'ignore' })
  const runningExit = new Promise((resolve) => running.once('exit', resolve))
  try {
    assert.equal(appProcessAlive(running), true)
  } finally {
    running.kill('SIGKILL')
    await runningExit
  }
  assert.equal(appProcessAlive(running), false)
})

test('the release lane gates every shipped format before freezing evidence', async () => {
  const workflow = await readFile(path.join(repository, '.github', 'workflows', 'release-linux-early-access.yml'), 'utf8')
  assert.equal((workflow.match(/linux-shipped-package-gate\.mjs/g) ?? []).length, 3, 'the lane does not gate each shipped format')
  assert.equal((workflow.match(/xvfb-run -a node tools\/linux-shipped-package-gate\.mjs/g) ?? []).length, 3, 'the lane does not run each shipped-format gate under a display server')
  for (const format of ['deb', 'rpm', 'appimage']) {
    assert.match(workflow, new RegExp(`--format ${format}\\b`), `the lane does not gate the shipped ${format}`)
  }
  assert.match(workflow, /SESAME_RPM_PACKAGE_EVIDENCE=linux-rpm-shipped-evidence\/linux-rpm-shipped-package\.json/)
  assert.match(workflow, /SESAME_APPIMAGE_PACKAGE_EVIDENCE=linux-appimage-shipped-evidence\/linux-appimage-shipped-package\.json/)
  assert.ok(workflow.indexOf('linux-shipped-package-gate.mjs') < workflow.indexOf('prepare-linux-release-evidence.mjs'), 'the gates must run before the evidence freeze')
})

test('every tool the Tauri bundler can fetch is pinned by version and hash', async () => {
  const pins = pinnedBundleTools.x86_64
  assert.deepEqual(pins.map((pin) => pin.name).sort(), [...bundlerFetchedToolNames].sort(), 'the pin table does not cover exactly the tools the bundler fetches')
  for (const pin of pins) {
    assert.match(pin.name, /^[A-Za-z0-9._-]+$/)
    assert.match(pin.url, /^https:\/\/(github\.com|raw\.githubusercontent\.com)\//)
    assert.match(pin.sha256, /^[0-9a-f]{64}$/)
  }
  const apprun = pins.find((pin) => pin.name === 'AppRun-x86_64')
  assert.equal(apprun.url, 'https://github.com/tauri-apps/binary-releases/releases/download/apprun-old/AppRun-x86_64')
  const linuxdeploy = pins.find((pin) => pin.name.startsWith('linuxdeploy-') && pin.name.endsWith('.AppImage'))
  assert.equal(linuxdeploy.name, 'linuxdeploy-07333c6-x86_64.AppImage')
  assert.equal(linuxdeploy.url, 'https://github.com/tauri-apps/binary-releases/releases/download/linuxdeploy-07333c6/linuxdeploy-x86_64.AppImage')
  const plugin = pins.find((pin) => pin.name === 'linuxdeploy-plugin-appimage.AppImage')
  assert.equal(plugin.url, 'https://github.com/linuxdeploy/linuxdeploy-plugin-appimage/releases/download/1-alpha-20250213-1/linuxdeploy-plugin-appimage-x86_64.AppImage')
  for (const pin of pins) {
    assert.doesNotMatch(pin.url, /\/releases\/download\/continuous\//, `${pin.name} comes from a rolling release whose bytes change under the pin`)
  }
  assert.match(linuxdeploy.url, /\/releases\/download\/linuxdeploy-[0-9a-f]{7}\//, 'linuxdeploy is not pinned to a commit release')
  const lock = JSON.parse(await readFile(path.join(repository, 'package-lock.json'), 'utf8'))
  assert.equal(lock.packages['node_modules/@tauri-apps/cli'].version, verifiedCliVersion, 'the pinned Linux bundling tools target a different Tauri CLI; re-verify every bundler tool name and hash')
})

test('a download that does not match its pinned hash is refused before it is written', async () => {
  const tool = pinnedBundleTools.x86_64.find((pin) => pin.name === 'linuxdeploy-plugin-appimage.AppImage')
  const toolsDir = await mkdtemp(path.join(tmpdir(), 'sesame-bundle-tools-'))
  const originalFetch = globalThis.fetch
  globalThis.fetch = async () => new Response('fictional tampered tool', { status: 200 })
  try {
    await assert.rejects(installPinnedTool(tool, toolsDir), /does not match its pinned SHA-256/)
    assert.equal(await readFile(path.join(toolsDir, tool.name)).catch(() => null), null, 'the rejected tool was written')
    assert.equal(await readFile(path.join(toolsDir, `${tool.name}.download`)).catch(() => null), null, 'the rejected tool was staged for rename')
  } finally {
    globalThis.fetch = originalFetch
    await rm(toolsDir, { recursive: true, force: true })
  }
})

test('Linux CI exercises the shipped rpm and AppImage gates before tagging', async () => {
  const workflow = await readFile(path.join(repository, '.github', 'workflows', 'ci.yml'), 'utf8')
  const job = workflow.slice(workflow.indexOf('  linux-bundles:'), workflow.indexOf('  linux-installed:'))
  for (const format of ['rpm', 'appimage']) {
    assert.match(job, new RegExp(`--format ${format}\\b`), `the Linux CI job does not gate the shipped ${format}`)
  }
  assert.equal((job.match(/xvfb-run -a node tools\/linux-shipped-package-gate\.mjs/g) ?? []).length, 2, 'each CI shipped-format gate must run under a display server')
})

test('Linux package validation uses the pinned release build image', async () => {
  const ci = await readFile(path.join(repository, '.github', 'workflows', 'ci.yml'), 'utf8')
  const release = await readFile(path.join(repository, '.github', 'workflows', 'release-linux-early-access.yml'), 'utf8')
  const image = workflowJob(release, 'build-and-test').match(/^ {4}runs-on: (\S+)/m)?.[1]
  assert.match(image ?? '', /^ubuntu-\d{2}\.\d{2}$/)
  for (const name of ['linux-bundles', 'linux-installed']) {
    const job = workflowJob(ci, name)
    assert.equal(job.match(/^ {4}runs-on: (\S+)/m)?.[1], image, `${name} must validate the release build image`)
    assert.equal(job.match(/^ {10}key: (\S+)/m)?.[1], `${name}-${image}`, `${name} must separate build caches by release image`)
  }
})

test('Linux bundle builders upgrade the existing PCRE2 runtime from vendor updates', async () => {
  for (const [filename, name] of [['ci.yml', 'linux-bundles'], ['release-linux-early-access.yml', 'build-and-test']]) {
    const workflow = await readFile(path.join(repository, '.github', 'workflows', filename), 'utf8')
    const steps = workflowRunSteps(workflowJob(workflow, name))
    const upgrade = steps.findIndex((script) => /^sudo apt-get install --only-upgrade[^\r\n]*\blibpcre2-8-0\b/m.test(script))
    const build = steps.findIndex((script) => /^(?:npm run tauri -- build|npx tauri build) --bundles\b/m.test(script))
    assert.ok(upgrade >= 0, `${filename} must run the vendor's PCRE2 upgrade command`)
    assert.ok(build >= 0, `${filename} must run the bundle build command`)
    assert.ok(upgrade < build, `${filename} must upgrade PCRE2 before building the bundle`)
  }
})

test('Linux CI prints the RPM and AppImage evidence when a shipped gate fails', async () => {
  const workflow = await readFile(path.join(repository, '.github', 'workflows', 'ci.yml'), 'utf8')
  const job = workflow.slice(workflow.indexOf('  linux-bundles:'), workflow.indexOf('  linux-installed:'))
  for (const [format, log] of [['rpm', 'linux-rpm-launch.log'], ['appimage', 'linux-appimage-launch.log']]) {
    const directory = `linux-${format}-shipped-evidence`
    const step = job.split('\n      - name:').find((entry) => entry.includes(`--format ${format}`))
    assert.ok(step, `the Linux CI job does not run the ${format} gate`)
    assert.match(step, /if ! xvfb-run -a node tools\/linux-shipped-package-gate\.mjs[\s\S]*; then/, `the ${format} evidence must be printed only when the gate fails`)
    assert.match(step, new RegExp(`cat ${directory}/${log.replaceAll('.', '\\.')} 2>/dev/null \\|\\| true`), `the Linux CI job does not print the ${format} launch log when its gate fails`)
    assert.match(step, new RegExp(`cat ${directory}/\\*\\.json 2>/dev/null \\|\\| true`), `the Linux CI job does not print the ${format} record when its gate fails`)
    assert.match(step, /\n {12}exit 1\n {10}fi/, `the ${format} failure reporting must preserve a failing exit status`)
  }
})

test('the bundling tools are verified before the bundler can download its own', async () => {
  const source = await readFile(path.join(repository, 'tools', 'prepare-linux-bundle-tools.mjs'), 'utf8')
  assert.match(source, /createHash\('sha256'\)/)
  assert.match(source, /does not match its pinned SHA-256/)
  assert.match(source, /cargo metadata/)
  for (const workflow of ['ci.yml', 'release-linux-early-access.yml']) {
    const body = await readFile(path.join(repository, '.github', 'workflows', workflow), 'utf8')
    const prepare = body.indexOf('prepare-linux-bundle-tools.mjs')
    const build = body.indexOf('--bundles deb,rpm,appimage')
    assert.ok(prepare >= 0, `${workflow} does not run the pinned tool preparation`)
    assert.ok(prepare < build, `${workflow} must verify the bundling tools before the bundle build`)
    assert.match(body, /useLocalToolsDir":true/, `${workflow} does not keep bundling tools in the project target directory`)
  }
})

function scriptedFetch(outcomes) {
  const calls = []
  const fetchImpl = async (url) => {
    calls.push(url)
    const outcome = outcomes.shift()
    if (outcome instanceof Error) throw outcome
    return { ok: outcome === 200, status: outcome, arrayBuffer: async () => new TextEncoder().encode('fictional tool').buffer }
  }
  return { fetchImpl, calls }
}

const fictionalTool = { name: 'fictional-tool', url: 'https://downloads.example.test/fictional-tool' }

test('bundle tool downloads retry gateway errors and dropped connections', async () => {
  const waits = []
  const { fetchImpl, calls } = scriptedFetch([504, new Error('socket hang up'), 503, 200])
  const bytes = await fetchTool(fictionalTool, { fetchImpl, wait: async (ms) => waits.push(ms) })
  assert.equal(bytes.toString(), 'fictional tool')
  assert.equal(calls.length, 4)
  assert.deepEqual(waits, [2000, 5000, 15000])
})

test('bundle tool downloads stop after the last retry and report the final status', async () => {
  const { fetchImpl, calls } = scriptedFetch([504, 504, 504, 504, 200])
  await assert.rejects(fetchTool(fictionalTool, { fetchImpl, wait: async () => {} }), /fictional-tool: HTTP 504/)
  assert.equal(calls.length, 4)
})

test('bundle tool downloads do not retry a missing or forbidden file', async () => {
  for (const status of [403, 404]) {
    const { fetchImpl, calls } = scriptedFetch([status, 200])
    await assert.rejects(fetchTool(fictionalTool, { fetchImpl, wait: async () => {} }), new RegExp(`HTTP ${status}`))
    assert.equal(calls.length, 1)
  }
})

