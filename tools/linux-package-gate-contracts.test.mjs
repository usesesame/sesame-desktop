import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import test from 'node:test'

import { PACKAGE_RUN_SCHEMA, requiredPackageSteps, validateLinuxPackageEvidence } from './linux-installed-package-gate.mjs'
import { APPIMAGE_RUN_SCHEMA, RPM_RUN_SCHEMA, SHIPPED_RUN_SCHEMA, evidenceFilenameByFormat, formatForPackage, requiredAppImageSteps, requiredRpmSteps, requiredShippedSteps, validateLinuxAppImageShippedEvidence, validateLinuxRpmShippedEvidence, validateLinuxShippedEvidence } from './linux-shipped-package-gate.mjs'
import { pinnedBundleTools, verifiedCliVersion } from './prepare-linux-bundle-tools.mjs'
import { chromeHostManifestMatches, pinnedChromeOrigin } from './desktop-e2e-bridge.mjs'

const repository = process.cwd()

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
  const job = workflow.slice(workflow.indexOf('desktop-linux:'))
  assert.match(job, /--bundles deb/, 'the Linux job does not build the deb the gate installs')
  assert.match(job, /--features wdio/, 'the Linux job does not build the test-featured package the gate drives')
})

test('the gate refuses non-Linux and non-deb inputs', async () => {
  const source = await readFile(path.join(repository, 'tools', 'linux-installed-package-gate.mjs'), 'utf8')
  assert.match(source, /if \(platform !== 'linux'\) throw new Error/)
  assert.match(source, /dpkg-deb/)
  assert.match(source, /sudo', \['-n', 'dpkg', '-i'/)
})

test('the shipped manifest check pins the host path, type, and single origin', () => {
  const manifest = {
    name: 'app.usesesame.browser',
    type: 'stdio',
    path: '/usr/bin/sesame-browser-host',
    allowed_origins: [pinnedChromeOrigin],
  }
  assert.equal(chromeHostManifestMatches(manifest, '/usr/bin/sesame-browser-host'), true)
  assert.equal(chromeHostManifestMatches({ ...manifest, path: '/tmp/sesame-browser-host' }, '/usr/bin/sesame-browser-host'), false)
  assert.equal(chromeHostManifestMatches({ ...manifest, type: 'ws' }, '/usr/bin/sesame-browser-host'), false)
  assert.equal(chromeHostManifestMatches({ ...manifest, allowed_origins: ['chrome-extension://other/'] }, '/usr/bin/sesame-browser-host'), false)
  assert.equal(chromeHostManifestMatches({ ...manifest, allowed_origins: [pinnedChromeOrigin, pinnedChromeOrigin] }, '/usr/bin/sesame-browser-host'), false)
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

test('the AppImage shipped record requires an extracted payload and no registration', () => {
  const evidence = appimageRecord()
  assert.equal(validateLinuxAppImageShippedEvidence(evidence), evidence)
  const missing = appimageRecord()
  missing.steps = missing.steps.filter((step) => step.name !== 'browser.registration_refused')
  assert.throws(() => validateLinuxAppImageShippedEvidence(missing), /did not pass browser\.registration_refused/)
  assert.throws(() => validateLinuxAppImageShippedEvidence(appimageRecord({ schema: RPM_RUN_SCHEMA })), /wrong schema/)
  assert.throws(() => validateLinuxAppImageShippedEvidence(appimageRecord({ binarySha256: 'nope' })), /package and binary digests/)
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
  assert.ok(requiredAppImageSteps.includes('browser.registration_refused'))
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

test('every repository-managed AppImage bundling tool is pinned by version and hash', async () => {
  const pins = pinnedBundleTools.x86_64
  assert.equal(pins.length, 3)
  for (const pin of pins) {
    assert.match(pin.name, /^[A-Za-z0-9._-]+$/)
    assert.match(pin.url, /^https:\/\/github\.com\//)
    assert.match(pin.sha256, /^[0-9a-f]{64}$/)
  }
  const apprun = pins.find((pin) => pin.name === 'AppRun-x86_64')
  assert.equal(apprun.url, 'https://github.com/tauri-apps/binary-releases/releases/download/apprun-old/AppRun-x86_64')
  const linuxdeploy = pins.find((pin) => pin.name.startsWith('linuxdeploy-') && pin.name.endsWith('.AppImage'))
  assert.equal(linuxdeploy.name, 'linuxdeploy-x86_64.AppImage')
  assert.equal(linuxdeploy.url, 'https://github.com/tauri-apps/binary-releases/releases/download/linuxdeploy/linuxdeploy-x86_64.AppImage')
  const plugin = pins.find((pin) => pin.name === 'linuxdeploy-plugin-appimage.AppImage')
  assert.equal(plugin.url, 'https://github.com/linuxdeploy/linuxdeploy-plugin-appimage/releases/download/continuous/linuxdeploy-plugin-appimage-x86_64.AppImage')
  const lock = JSON.parse(await readFile(path.join(repository, 'package-lock.json'), 'utf8'))
  assert.equal(lock.packages['node_modules/@tauri-apps/cli'].version, verifiedCliVersion, 'the pinned Linux bundling tools target a different Tauri CLI; re-verify every bundler tool name and hash')
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
