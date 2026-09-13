import assert from 'node:assert/strict'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import test from 'node:test'

import {
  assertCompatibilityPolicy, assertRepositoryCompatibility, assertRetainedReaderLabels, buildCompatibilityMatrix,
  loadCompatibilityPolicy, mergeInstalledEvidence, RUN_SCHEMA, validateCompatibilityEvidence,
} from './vault-compatibility-gate.mjs'

const repository = process.cwd()
const coreSourceTemplate = `pub const VAULT_FORMAT_VERSION: u8 = 10;
pub const LEGACY_PAYLOAD_AAD: &[u8] = b"sesame:vault-payload:v1";
pub const FORMAT_9_PAYLOAD_AAD: &[u8] = b"sesame:vault-payload:format:9";
pub const PENDING_SETUP_PAYLOAD_AAD: &[u8] = b"sesame:vault-payload:format:10:setup:pending";
pub const PAYLOAD_AAD: &[u8] = b"sesame:vault-payload:format:10:setup:complete";
pub fn payload_aad_for_file(format_version: u8, setup_complete: bool) -> Result<&'static [u8], String> {
    match (format_version, setup_complete) {
        (2..=8, true) => Ok(LEGACY_PAYLOAD_AAD),
        (9, true) => Ok(FORMAT_9_PAYLOAD_AAD),
        (VAULT_FORMAT_VERSION, false) => Ok(PENDING_SETUP_PAYLOAD_AAD),
        (VAULT_FORMAT_VERSION, true) => Ok(PAYLOAD_AAD),
        _ => Err("unsupported".into()),
    }
}
`

function fictionalManifest({ fixtures = true } = {}) {
  return {
    corpusSchema: 'sesame.compatibility-corpus/1',
    digestAlgorithm: 'sha256',
    publishedVersions: [{ tag: 'v1.0.0', commit: 'a'.repeat(40) }],
    provenFormats: [{ format: 10, fixtures: ['v1.0.0'] }],
    unprovenFormats: [{
      formats: [2, 3, 4, 5, 6, 7, 8, 9],
      decision: { status: 'excludedFromCompatibilityPromise', readersRetained: true },
      recoveryPath: { status: 'approvedUnprovenRecovery' },
    }],
    fixtures: fixtures ? [{ id: 'v1.0.0', writerTag: 'v1.0.0', fileName: 'v1.0.0.sesame', digestSha256: 'd'.repeat(64), formatVersion: 10 }] : [],
  }
}

function fictionalPolicy({ minimumSupportedFormat = 2 } = {}) {
  return {
    schema: 'sesame.vault-compatibility-policy/1',
    platforms: ['linux', 'windows'],
    minimumSupportedFormat,
    rollback: 'Fictional rollback rule for the contract tests.',
    minimumFormatDecision: { status: 'recorded', recordedBy: 'owner', date: '2026-09-05', note: 'Fictional decision for the contract tests.' },
  }
}

async function fictionalRepository({ minimumSupportedFormat = 2, manifest = fictionalManifest(), policy = fictionalPolicy(), coreSource = coreSourceTemplate } = {}) {
  const root = await mkdtemp(path.join(tmpdir(), 'sesame-vault-gate-'))
  const source = path.join(root, 'src-tauri', 'sesame-core', 'src')
  const corpus = path.join(root, 'src-tauri', 'sesame-core', 'tests', 'fixtures', 'compatibility')
  await mkdir(source, { recursive: true })
  await mkdir(corpus, { recursive: true })
  await mkdir(path.join(root, 'tools'), { recursive: true })
  await writeFile(path.join(source, 'migration.rs'), `pub const MIN_SUPPORTED_VAULT_FORMAT: u8 = ${minimumSupportedFormat};\n`)
  await writeFile(path.join(source, 'lib.rs'), coreSource)
  await writeFile(path.join(corpus, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`)
  await writeFile(path.join(root, 'tools', 'vault-compatibility-policy.json'), `${JSON.stringify(policy, null, 2)}\n`)
  return root
}

function fictionalRun({ matrix, matrixDigest, platform, fixtureId, overrides = {} }) {
  const version = matrix.publishedVersions.find((entry) => entry.fixtureId === fixtureId)
  return {
    schema: RUN_SCHEMA,
    platform,
    architecture: 'x86_64',
    version: '9.9.9',
    buildKind: 'tauri-wdio-test-build',
    matrixDigest,
    fixtureManifestSha256: matrix.fixtureManifestSha256,
    fixtureId,
    fixtureSha256: version.fixtureDigestSha256,
    binarySha256: 'e'.repeat(64),
    result: 'passed',
    skipped: false,
    startedAt: '2026-09-13T00:00:00.000Z',
    finishedAt: '2026-09-13T00:10:00.000Z',
    phases: {
      restore: { passed: 14, failed: 0, steps: ['create_vault', 'restore_backup', 'unlock.password', 'backup.restored', 'verify.restored_backup'].map((name) => ({ name, ok: true })) },
      restart: { passed: 6, failed: 0, steps: ['restart.unlock.password', 'restart.unlock.recovery_kit'].map((name) => ({ name, ok: true })) },
    },
    ...overrides,
  }
}

test('the repository matrix covers every published release and both platforms', async () => {
  const { matrix, matrixDigest } = await assertRepositoryCompatibility(repository)
  assert.equal(matrix.schema, 'sesame.vault-compatibility-matrix/1')
  assert.deepEqual(matrix.publishedVersions.map((entry) => entry.tag), ['v0.1.0', 'v0.1.1', 'v0.2.0', 'v0.2.1', 'v0.2.2'])
  assert.deepEqual(matrix.platforms, ['linux', 'windows'])
  assert.equal(matrix.minimumSupportedFormat, 2)
  assert.equal(matrix.currentFormat, 10)
  assert.match(matrix.rollback, /binary rollback/)
  assert.match(matrix.fixtureManifestSha256, /^[0-9a-f]{64}$/)
  const manifestBytes = await readFile(path.join(repository, 'src-tauri', 'sesame-core', 'tests', 'fixtures', 'compatibility', 'manifest.json'))
  const { createHash } = await import('node:crypto')
  assert.equal(matrix.fixtureManifestSha256, createHash('sha256').update(manifestBytes).digest('hex'))
  assert.match(matrixDigest, /^[0-9a-f]{64}$/)
})

test('a published release without a genuine writer fixture fails the gate', async () => {
  const root = await fictionalRepository({ manifest: fictionalManifest({ fixtures: false }) })
  try {
    await assert.rejects(buildCompatibilityMatrix(root), /has no genuine writer fixture/)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('raising the minimum supported format needs a recorded decision', async () => {
  const root = await fictionalRepository({ minimumSupportedFormat: 3, policy: fictionalPolicy({ minimumSupportedFormat: 2 }) })
  try {
    await assert.rejects(buildCompatibilityMatrix(root), /Record the compatibility decision in tools\/vault-compatibility-policy.json/)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('a format inside the supported range needs a fixture or a recorded recovery path', async () => {
  const manifest = fictionalManifest()
  manifest.provenFormats = []
  manifest.unprovenFormats = []
  const root = await fictionalRepository({ manifest })
  try {
    await assert.rejects(buildCompatibilityMatrix(root), /Format 2 is inside the supported range/)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('removing a retained reader label fails the gate while the format stays supported', async () => {
  const coreSource = coreSourceTemplate.replace('        (2..=8, true) => Ok(LEGACY_PAYLOAD_AAD),\n', '')
  const { matrix } = await assertRepositoryCompatibility(repository)
  assert.throws(() => assertRetainedReaderLabels({ coreSource, matrix }), /exact authentication label is gone/)
  assertRetainedReaderLabels({ coreSource: coreSourceTemplate, matrix })
})

test('installed-app evidence must pass on every platform for every fixture', async () => {
  const { matrix, policy, matrixDigest } = await assertRepositoryCompatibility(repository)
  const linuxRuns = matrix.publishedVersions.map((entry) => fictionalRun({ matrix, matrixDigest, platform: 'linux', fixtureId: entry.fixtureId }))
  assert.throws(
    () => mergeInstalledEvidence({ runs: linuxRuns, matrix, policy, matrixDigest }),
    /no installed-app evidence for windows/,
  )
  const complete = [
    ...linuxRuns,
    ...matrix.publishedVersions.map((entry) => fictionalRun({ matrix, matrixDigest, platform: 'windows', fixtureId: entry.fixtureId })),
  ]
  const evidence = mergeInstalledEvidence({ runs: complete, matrix, policy, matrixDigest })
  validateCompatibilityEvidence(evidence, { matrix, policy, matrixDigest })
  assert.deepEqual(evidence.platforms.map((entry) => entry.platform), ['linux', 'windows'])
  assert.equal(evidence.platforms[0].fixtures.length, matrix.publishedVersions.length)
})

test('a skipped, failed, or digest-mismatched installed run cannot merge', async () => {
  const { matrix, policy, matrixDigest } = await assertRepositoryCompatibility(repository)
  const runs = ['linux', 'windows'].flatMap((platform) => matrix.publishedVersions.map((entry) => fictionalRun({ matrix, matrixDigest, platform, fixtureId: entry.fixtureId })))
  const skipped = structuredClone(runs)
  skipped[0].skipped = true
  skipped[0].result = 'failed'
  assert.throws(() => mergeInstalledEvidence({ runs: skipped, matrix, policy, matrixDigest }), /did not pass/)
  const mismatched = structuredClone(runs)
  mismatched[0].fixtureSha256 = 'f'.repeat(64)
  assert.throws(() => mergeInstalledEvidence({ runs: mismatched, matrix, policy, matrixDigest }), /recorded fixture bytes/)
  const partialPhase = structuredClone(runs)
  partialPhase[0].phases.restore.steps = partialPhase[0].phases.restore.steps.filter((step) => step.name !== 'restore_backup')
  assert.throws(() => mergeInstalledEvidence({ runs: partialPhase, matrix, policy, matrixDigest }), /did not pass restore_backup/)
})

test('the release workflow gates publication on installed-app compatibility evidence', async () => {
  const workflow = await readFile(path.join(repository, '.github', 'workflows', 'release-early-access.yml'), 'utf8')
  assert.match(workflow, /vault-compatibility:/, 'the release workflow has no installed-app compatibility job')
  assert.match(workflow, /node tools\/run-vault-restore-gate\.mjs/, 'the compatibility job does not run the restore gate')
  assert.match(workflow, /vault-compatibility-gate\.mjs merge/, 'the compatibility job does not merge platform evidence')
  assert.match(workflow, /SESAME_VAULT_COMPATIBILITY_FILE/, 'release evidence does not take the compatibility evidence')
  const publish = workflow.slice(workflow.indexOf('publish-candidate:'))
  assert.match(publish, /needs: \[build-and-attest, verify-fresh\]/, 'publication does not wait for the evidence jobs')
  const build = workflow.slice(workflow.indexOf('build-and-attest:'), workflow.indexOf('verify-fresh:'))
  assert.match(build, /needs: \[vault-compatibility\]/, 'the release build does not wait for installed-app compatibility')
})

test('the policy file records the format decision the gate enforces', async () => {
  const policy = await loadCompatibilityPolicy(repository)
  assert.equal(policy.minimumSupportedFormat, 2)
  assert.equal(policy.minimumFormatDecision.status, 'recorded')
  assert.deepEqual(policy.platforms, ['linux', 'windows'])
  const { matrix } = await assertRepositoryCompatibility(repository)
  assertCompatibilityPolicy(matrix, policy)
})
