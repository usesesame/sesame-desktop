import assert from 'node:assert/strict'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import test from 'node:test'

import {
  assertCompatibilityPolicy, assertRepositoryCompatibility, assertRetainedReaderLabels, buildCompatibilityMatrix,
  computeTestBuildConfigurationDigest, describeTestBuildIdentity, loadCompatibilityPolicy, loadReleaseCandidate,
  mergeInstalledEvidence, RUN_SCHEMA, TEST_BUILD_CONFIGURATION_FILES, validateCompatibilityEvidence,
} from './vault-compatibility-gate.mjs'

const repository = process.cwd()
const candidate = {
  version: '9.9.9',
  commit: 'c'.repeat(40),
  configurationSha256: 'b'.repeat(64),
  workflowIdentity: 'https://github.com/example-org/example-repo/.github/workflows/release.yml@refs/tags/v9.9.9',
  workflowRunId: '1234567890',
}
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
    version: candidate.version,
    commit: candidate.commit,
    configurationSha256: candidate.configurationSha256,
    workflowIdentity: candidate.workflowIdentity,
    workflowRunId: candidate.workflowRunId,
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
      restore: { passed: 14, failed: 0, steps: ['create_vault', 'restore_backup.locked', 'active_vault.unchanged_after_locked_refusal', 'restore_backup.without_presence', 'active_vault.unchanged_after_presence_refusal', 'restore_backup.different_vault', 'active_vault.unchanged_after_refusal', 'delete_local_vault', 'restore_backup.fresh', 'unlock.password', 'backup.restored', 'verify.restored_backup', 'restore_backup.same_vault', 'safety_backup.same_vault'].map((name) => ({ name, ok: true })) },
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
    () => mergeInstalledEvidence({ runs: linuxRuns, matrix, policy, matrixDigest, candidate }),
    /no installed-app evidence for windows/,
  )
  const complete = [
    ...linuxRuns,
    ...matrix.publishedVersions.map((entry) => fictionalRun({ matrix, matrixDigest, platform: 'windows', fixtureId: entry.fixtureId })),
  ]
  const evidence = mergeInstalledEvidence({ runs: complete, matrix, policy, matrixDigest, candidate })
  validateCompatibilityEvidence(evidence, { matrix, policy, matrixDigest, candidate })
  assert.deepEqual(evidence.platforms.map((entry) => entry.platform), ['linux', 'windows'])
  assert.equal(evidence.platforms[0].fixtures.length, matrix.publishedVersions.length)
})

test('a skipped, failed, or digest-mismatched installed run cannot merge', async () => {
  const { matrix, policy, matrixDigest } = await assertRepositoryCompatibility(repository)
  const runs = ['linux', 'windows'].flatMap((platform) => matrix.publishedVersions.map((entry) => fictionalRun({ matrix, matrixDigest, platform, fixtureId: entry.fixtureId })))
  const skipped = structuredClone(runs)
  skipped[0].skipped = true
  skipped[0].result = 'failed'
  assert.throws(() => mergeInstalledEvidence({ runs: skipped, matrix, policy, matrixDigest, candidate }), /did not pass/)
  const mismatched = structuredClone(runs)
  mismatched[0].fixtureSha256 = 'f'.repeat(64)
  assert.throws(() => mergeInstalledEvidence({ runs: mismatched, matrix, policy, matrixDigest, candidate }), /recorded fixture bytes/)
  const partialPhase = structuredClone(runs)
  partialPhase[0].phases.restore.steps = partialPhase[0].phases.restore.steps.filter((step) => step.name !== 'restore_backup.same_vault')
  assert.throws(() => mergeInstalledEvidence({ runs: partialPhase, matrix, policy, matrixDigest, candidate }), /did not pass restore_backup\.same_vault/)
})

test('a restore run missing a refusal step cannot merge', async () => {
  const { matrix, policy, matrixDigest } = await assertRepositoryCompatibility(repository)
  const runs = ['linux', 'windows'].flatMap((platform) => matrix.publishedVersions.map((entry) => fictionalRun({ matrix, matrixDigest, platform, fixtureId: entry.fixtureId })))
  for (const omitted of ['restore_backup.locked', 'active_vault.unchanged_after_locked_refusal', 'restore_backup.without_presence', 'active_vault.unchanged_after_presence_refusal']) {
    const partial = structuredClone(runs)
    partial[0].phases.restore.steps = partial[0].phases.restore.steps.filter((step) => step.name !== omitted)
    assert.throws(
      () => mergeInstalledEvidence({ runs: partial, matrix, policy, matrixDigest, candidate }),
      new RegExp(`did not pass ${omitted.replace(/\./g, '\\.')}`),
    )
  }
})

async function completeRuns() {
  const { matrix, policy, matrixDigest } = await assertRepositoryCompatibility(repository)
  const runs = ['linux', 'windows'].flatMap((platform) => matrix.publishedVersions.map((entry) => fictionalRun({ matrix, matrixDigest, platform, fixtureId: entry.fixtureId })))
  return { matrix, policy, matrixDigest, runs }
}

const runMutations = [
  { name: 'version', change: { version: '9.9.8' }, message: /different version than the release candidate/ },
  { name: 'commit', change: { commit: 'd'.repeat(40) }, message: /different commit than the release candidate/ },
  { name: 'build configuration', change: { configurationSha256: 'a'.repeat(64) }, message: /different build configuration than the release candidate/ },
  { name: 'workflow', change: { workflowIdentity: 'https://github.com/example-org/example-repo/.github/workflows/other.yml@refs/tags/v9.9.9' }, message: /different workflow than the release candidate/ },
  { name: 'workflow run', change: { workflowRunId: '1234567891' }, message: /different workflow run than the release candidate/ },
  { name: 'architecture', change: { architecture: 'aarch64' }, message: /mix architecture values/ },
  { name: 'binary digest', change: { binarySha256: 'f'.repeat(64) }, message: /mix binary digest values/ },
  { name: 'build kind', change: { buildKind: 'shipped-build' }, message: /full app build with the test bridge/ },
]

for (const mutation of runMutations) {
  for (const position of ['first', 'last']) {
    test(`${position} installed-app run cannot merge when its ${mutation.name} differs`, async () => {
      const { matrix, policy, matrixDigest, runs } = await completeRuns()
      const mutated = structuredClone(runs)
      const target = position === 'first' ? mutated.find((run) => run.platform === 'linux') : mutated.findLast((run) => run.platform === 'linux')
      Object.assign(target, mutation.change)
      assert.throws(() => mergeInstalledEvidence({ runs: mutated, matrix, policy, matrixDigest, candidate }), mutation.message)
    })
  }
}

test('a platform where every run uniformly drifts from the candidate cannot merge', async () => {
  const { matrix, policy, matrixDigest, runs } = await completeRuns()
  for (const mutation of runMutations.filter((entry) => ['version', 'commit', 'build configuration', 'workflow', 'workflow run'].includes(entry.name))) {
    const mutated = structuredClone(runs).map((run) => (run.platform === 'windows' ? { ...run, ...mutation.change } : run))
    assert.throws(() => mergeInstalledEvidence({ runs: mutated, matrix, policy, matrixDigest, candidate }), mutation.message)
  }
})

test('merging needs a complete candidate identity', async () => {
  const { matrix, policy, matrixDigest, runs } = await completeRuns()
  assert.throws(() => mergeInstalledEvidence({ runs, matrix, policy, matrixDigest }), /release candidate has no version/)
  for (const [field, message] of [
    ['commit', /no source commit/],
    ['configurationSha256', /no build configuration digest/],
    ['workflowIdentity', /no workflow identity/],
    ['workflowRunId', /no workflow run/],
  ]) {
    assert.throws(() => mergeInstalledEvidence({ runs, matrix, policy, matrixDigest, candidate: { ...candidate, [field]: null } }), message)
  }
})

test('runs on different platforms may use different test binaries and architectures', async () => {
  const { matrix, policy, matrixDigest, runs } = await completeRuns()
  const varied = runs.map((run) => (run.platform === 'windows' ? { ...run, binarySha256: '1'.repeat(64), architecture: 'aarch64' } : run))
  const evidence = mergeInstalledEvidence({ runs: varied, matrix, policy, matrixDigest, candidate })
  validateCompatibilityEvidence(evidence, { matrix, policy, matrixDigest, candidate })
  assert.deepEqual(evidence.platforms.map((entry) => entry.architecture), ['x86_64', 'aarch64'])
  assert.notEqual(evidence.platforms[0].binarySha256, evidence.platforms[1].binarySha256)
  assert.deepEqual(evidence.candidate, candidate)
})

async function mergedEvidence() {
  const { matrix, policy, matrixDigest, runs } = await completeRuns()
  const evidence = mergeInstalledEvidence({ runs, matrix, policy, matrixDigest, candidate })
  return { matrix, policy, matrixDigest, evidence }
}

const evidenceMutations = [
  { name: 'version', message: /different version than the release candidate/, apply: (evidence) => { evidence.candidate.version = '9.9.8' } },
  { name: 'commit', message: /different commit than the release candidate/, apply: (evidence) => { evidence.candidate.commit = 'd'.repeat(40) } },
  { name: 'build configuration', message: /different build configuration than the release candidate/, apply: (evidence) => { evidence.candidate.configurationSha256 = 'a'.repeat(64) } },
  { name: 'workflow', message: /different workflow than the release candidate/, apply: (evidence) => { evidence.candidate.workflowIdentity = 'https://github.com/example-org/example-repo/.github/workflows/other.yml@refs/tags/v9.9.9' } },
  { name: 'workflow run', message: /different workflow run than the release candidate/, apply: (evidence) => { evidence.candidate.workflowRunId = '1234567891' } },
  { name: 'platform version', message: /linux evidence records a different version/, apply: (evidence) => { evidence.platforms[0].version = '9.9.8' } },
  { name: 'fixture version', message: /different version than the rest of the linux build/, apply: (evidence) => { evidence.platforms[0].fixtures[1].build.version = '9.9.8' } },
  { name: 'fixture commit', message: /different commit than the rest of the linux build/, apply: (evidence) => { evidence.platforms[0].fixtures[1].build.commit = 'd'.repeat(40) } },
  { name: 'fixture configuration', message: /different build configuration than the rest of the linux build/, apply: (evidence) => { evidence.platforms[0].fixtures[1].build.configurationSha256 = 'a'.repeat(64) } },
  { name: 'fixture workflow', message: /different workflow than the rest of the linux build/, apply: (evidence) => { evidence.platforms[0].fixtures[1].build.workflowIdentity = 'https://example.invalid/other' } },
  { name: 'fixture workflow run', message: /different workflow run than the rest of the linux build/, apply: (evidence) => { evidence.platforms[0].fixtures[1].build.workflowRunId = '1234567891' } },
  { name: 'fixture architecture', message: /different architecture than the rest of the linux build/, apply: (evidence) => { evidence.platforms[0].fixtures[1].build.architecture = 'aarch64' } },
  { name: 'fixture binary digest', message: /different binary digest than the rest of the linux build/, apply: (evidence) => { evidence.platforms[0].fixtures[1].build.binarySha256 = 'f'.repeat(64) } },
  { name: 'fixture build record', message: /different version than the rest of the linux build/, apply: (evidence) => { delete evidence.platforms[0].fixtures[1].build } },
  { name: 'platform architecture', message: /unknown architecture/, apply: (evidence) => { evidence.platforms[0].architecture = 'riscv64' } },
  { name: 'platform build kind', message: /full app build with the test bridge/, apply: (evidence) => { evidence.platforms[0].buildKind = 'shipped-build' } },
  { name: 'platform list repeats a platform', message: /lists a platform more than once/, apply: (evidence) => { evidence.platforms.push(structuredClone(evidence.platforms[0])) } },
]

for (const mutation of evidenceMutations) {
  test(`merged evidence fails validation when its ${mutation.name} differs`, async () => {
    const { matrix, policy, matrixDigest, evidence } = await mergedEvidence()
    validateCompatibilityEvidence(evidence, { matrix, policy, matrixDigest, candidate })
    const mutated = structuredClone(evidence)
    mutation.apply(mutated)
    assert.throws(() => validateCompatibilityEvidence(mutated, { matrix, policy, matrixDigest, candidate }), mutation.message)
  })
}

test('evidence for one candidate does not validate against another', async () => {
  const { matrix, policy, matrixDigest, evidence } = await mergedEvidence()
  assert.throws(
    () => validateCompatibilityEvidence(evidence, { matrix, policy, matrixDigest, candidate: { ...candidate, commit: 'e'.repeat(40) } }),
    /different commit than the release candidate/,
  )
  assert.throws(() => validateCompatibilityEvidence(evidence, { matrix, policy, matrixDigest }), /release candidate has no version/)
})

async function fictionalBuildRoot(version = '9.9.9') {
  const root = await mkdtemp(path.join(tmpdir(), 'sesame-vault-build-'))
  await mkdir(path.join(root, 'src-tauri'), { recursive: true })
  await writeFile(path.join(root, 'package.json'), `${JSON.stringify({ name: 'fictional', version })}\n`)
  for (const file of TEST_BUILD_CONFIGURATION_FILES) await writeFile(path.join(root, file), `fictional ${file}\n`)
  return root
}

const ciEnvironment = {
  GITHUB_REPOSITORY: 'example-org/example-repo',
  GITHUB_REF: 'refs/tags/v9.9.9',
  GITHUB_SHA: 'c'.repeat(40),
  GITHUB_RUN_ID: '1234567890',
}

test('the test-build configuration digest changes with each configuration file', async () => {
  const root = await fictionalBuildRoot()
  try {
    const baseline = await computeTestBuildConfigurationDigest(root)
    assert.match(baseline, /^[0-9a-f]{64}$/)
    for (const file of TEST_BUILD_CONFIGURATION_FILES) {
      await writeFile(path.join(root, file), 'changed\n')
      assert.notEqual(await computeTestBuildConfigurationDigest(root), baseline, `${file} does not change the digest`)
      await writeFile(path.join(root, file), `fictional ${file}\n`)
    }
    assert.equal(await computeTestBuildConfigurationDigest(root), baseline)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('the release candidate comes from the tagged workflow run and the checked-out configuration', async () => {
  const root = await fictionalBuildRoot()
  try {
    const loaded = await loadReleaseCandidate(root, ciEnvironment)
    assert.equal(loaded.version, '9.9.9')
    assert.equal(loaded.commit, ciEnvironment.GITHUB_SHA)
    assert.equal(loaded.workflowRunId, '1234567890')
    assert.equal(loaded.workflowIdentity, 'https://github.com/example-org/example-repo/.github/workflows/release-early-access.yml@refs/tags/v9.9.9')
    assert.equal(loaded.configurationSha256, await computeTestBuildConfigurationDigest(root))
    for (const name of Object.keys(ciEnvironment)) {
      await assert.rejects(loadReleaseCandidate(root, { ...ciEnvironment, [name]: '' }), new RegExp(`${name} is required`))
    }
    await assert.rejects(loadReleaseCandidate(root, { ...ciEnvironment, GITHUB_REF: 'refs/tags/v9.9.8' }), /is not the tag for version 9\.9\.9/)
    await assert.rejects(loadReleaseCandidate(root, { ...ciEnvironment, GITHUB_REF: 'refs/heads/main' }), /is not the tag for version 9\.9\.9/)
    await assert.rejects(loadReleaseCandidate(root, { ...ciEnvironment, GITHUB_SHA: 'not-a-commit' }), /no source commit/)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('a run record carries the identity the merge step binds', async () => {
  const root = await fictionalBuildRoot()
  try {
    const identity = await describeTestBuildIdentity(root, { GITHUB_SHA: 'c'.repeat(40), GITHUB_RUN_ID: '1234567890', GITHUB_WORKFLOW_REF: 'example-org/example-repo/.github/workflows/release-early-access.yml@refs/tags/v9.9.9' })
    assert.deepEqual(identity, {
      version: '9.9.9',
      commit: 'c'.repeat(40),
      configurationSha256: await computeTestBuildConfigurationDigest(root),
      workflowIdentity: 'https://github.com/example-org/example-repo/.github/workflows/release-early-access.yml@refs/tags/v9.9.9',
      workflowRunId: '1234567890',
    })
    const local = await describeTestBuildIdentity(root, {})
    assert.equal(local.commit, null)
    assert.equal(local.workflowIdentity, null)
    assert.equal(local.workflowRunId, null)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('release evidence preparation binds the compatibility evidence to the candidate', async () => {
  const source = await readFile(path.join(repository, 'tools', 'prepare-release-evidence.mjs'), 'utf8')
  assert.match(source, /validateCompatibilityEvidence\(compatibilityEvidence, \{[^}]*candidate: await loadReleaseCandidate\(\)/)
})

test('the release workflow gates publication on installed-app compatibility evidence', async () => {
  const workflow = await readFile(path.join(repository, '.github', 'workflows', 'release-early-access.yml'), 'utf8')
  assert.match(workflow, /vault-compatibility:/, 'the release workflow has no installed-app compatibility job')
  assert.match(workflow, /node tools\/run-vault-restore-gate\.mjs/, 'the compatibility job does not run the restore gate')
  assert.match(workflow, /vault-compatibility-gate\.mjs merge/, 'the compatibility job does not merge platform evidence')
  assert.match(workflow, /SESAME_VAULT_COMPATIBILITY_FILE/, 'release evidence does not take the compatibility evidence')
  const publish = workflow.slice(workflow.indexOf('publish-candidate:'))
  assert.match(publish, /needs: \[sign-and-attest, verify-fresh, candidate-receipt\]/, 'publication does not wait for the evidence jobs')
  const build = workflow.slice(workflow.indexOf('\n  build:\n'), workflow.indexOf('\n  sign-and-attest:\n'))
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
