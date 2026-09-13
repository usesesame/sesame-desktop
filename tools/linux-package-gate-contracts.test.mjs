import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import test from 'node:test'

import { PACKAGE_RUN_SCHEMA, requiredPackageSteps, validateLinuxPackageEvidence } from './linux-installed-package-gate.mjs'

const repository = process.cwd()

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
