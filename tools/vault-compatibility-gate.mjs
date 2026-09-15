import { createHash } from 'node:crypto'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { stableJSON } from './release-evidence-lib.mjs'

export const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
export const POLICY_PATH = 'tools/vault-compatibility-policy.json'
export const FIXTURE_MANIFEST_PATH = 'src-tauri/sesame-core/tests/fixtures/compatibility/manifest.json'
export const MATRIX_SCHEMA = 'sesame.vault-compatibility-matrix/1'
export const RUN_SCHEMA = 'sesame.vault-compatibility-installed-run/1'
export const EVIDENCE_SCHEMA = 'sesame.vault-compatibility-evidence/1'
export const SUPPORTED_PLATFORMS = ['linux', 'windows']

const sha256Pattern = /^[0-9a-f]{64}$/
const requiredRestoreSteps = ['create_vault', 'restore_backup', 'unlock.password', 'backup.restored', 'verify.restored_backup']
const requiredRestartSteps = ['restart.unlock.password', 'restart.unlock.recovery_kit']

const requireCondition = (condition, message) => {
  if (!condition) throw new Error(message)
}

export const sha256 = (value) => createHash('sha256').update(value).digest('hex')

const readRepositoryFile = (root, relativePath) => readFile(path.join(root, relativePath), 'utf8')

export function parseFormatConstants({ migrationSource, coreSource }) {
  const minimum = migrationSource.match(/pub const MIN_SUPPORTED_VAULT_FORMAT: u8 = (\d+);/)
  const current = coreSource.match(/pub const VAULT_FORMAT_VERSION: u8 = (\d+);/)
  requireCondition(minimum, 'MIN_SUPPORTED_VAULT_FORMAT is not declared in migration.rs.')
  requireCondition(current, 'VAULT_FORMAT_VERSION is not declared in lib.rs.')
  return { minimumSupportedFormat: Number(minimum[1]), currentFormat: Number(current[1]) }
}

export async function loadCompatibilityPolicy(root = repositoryRoot) {
  const policy = JSON.parse(await readRepositoryFile(root, POLICY_PATH))
  requireCondition(policy?.schema === 'sesame.vault-compatibility-policy/1', 'The vault compatibility policy has the wrong schema.')
  requireCondition(Array.isArray(policy.platforms) && policy.platforms.length > 0, 'The vault compatibility policy must name at least one platform.')
  for (const platform of policy.platforms) {
    requireCondition(SUPPORTED_PLATFORMS.includes(platform), `The vault compatibility policy names an unknown platform: ${platform}.`)
  }
  const decision = policy.minimumFormatDecision
  requireCondition(decision?.status === 'recorded', 'The minimum supported vault format needs a recorded owner decision.')
  requireCondition(typeof decision.recordedBy === 'string' && decision.recordedBy.length > 0, 'The compatibility decision must name who recorded it.')
  requireCondition(typeof decision.date === 'string' && !Number.isNaN(Date.parse(decision.date)), 'The compatibility decision must carry a date.')
  requireCondition(typeof decision.note === 'string' && decision.note.length > 0, 'The compatibility decision must carry a note.')
  requireCondition(typeof policy.rollback === 'string' && policy.rollback.length > 0, 'The compatibility policy must carry the rollback rule for a vault this release upgraded.')
  return policy
}

export async function loadFixtureManifest(root = repositoryRoot) {
  const bytes = await readFile(path.join(root, FIXTURE_MANIFEST_PATH))
  const manifest = JSON.parse(bytes.toString('utf8'))
  requireCondition(manifest.corpusSchema === 'sesame.compatibility-corpus/1', 'The fixture manifest is not a Sesame compatibility corpus.')
  return { manifest, bytes, sha256: sha256(bytes) }
}

export async function buildCompatibilityMatrix(root = repositoryRoot) {
  const [{ manifest, sha256: fixtureManifestSha256 }, policy, migrationSource, coreSource] = await Promise.all([
    loadFixtureManifest(root),
    loadCompatibilityPolicy(root),
    readRepositoryFile(root, 'src-tauri/sesame-core/src/migration.rs'),
    readRepositoryFile(root, 'src-tauri/sesame-core/src/lib.rs'),
  ])
  const { minimumSupportedFormat, currentFormat } = parseFormatConstants({ migrationSource, coreSource })
  const fixturesById = new Map(manifest.fixtures.map((fixture) => [fixture.id, fixture]))
  const fixtureByWriterTag = new Map(manifest.fixtures.map((fixture) => [fixture.writerTag, fixture]))

  const publishedVersions = []
  for (const version of manifest.publishedVersions) {
    const fixture = fixtureByWriterTag.get(version.tag)
    requireCondition(fixture, `Published release ${version.tag} has no genuine writer fixture.`)
    publishedVersions.push({
      tag: version.tag,
      commit: version.commit,
      fixtureId: fixture.id,
      fixtureFileName: fixture.fileName,
      fixtureDigestSha256: fixture.digestSha256,
      formatVersion: fixture.formatVersion,
    })
  }

  const provenFormats = []
  for (const record of manifest.provenFormats) {
    requireCondition(Array.isArray(record.fixtures) && record.fixtures.length > 0, `Proven format ${record.format} names no fixtures.`)
    for (const fixtureId of record.fixtures) {
      requireCondition(fixturesById.has(fixtureId), `Proven format ${record.format} names missing fixture ${fixtureId}.`)
    }
    provenFormats.push({ formats: [record.format], status: 'proven', fixtureIds: [...record.fixtures] })
  }

  const unprovenFormats = []
  for (const record of manifest.unprovenFormats) {
    requireCondition(Array.isArray(record.formats) && record.formats.length > 0, 'An unproven format record names no formats.')
    requireCondition(record.decision?.readersRetained === true, `Formats ${record.formats.join(', ')} do not retain their readers.`)
    requireCondition(record.recoveryPath?.status === 'approvedUnprovenRecovery', `Formats ${record.formats.join(', ')} need an approved recovery path.`)
    unprovenFormats.push({
      formats: [...record.formats].sort((left, right) => left - right),
      status: 'unprovenRecovery',
      readersRetained: true,
      recoveryPathStatus: record.recoveryPath.status,
    })
  }

  const matrix = {
    schema: MATRIX_SCHEMA,
    product: 'Sesame',
    fixtureManifest: FIXTURE_MANIFEST_PATH,
    fixtureManifestSha256,
    minimumSupportedFormat,
    currentFormat,
    platforms: [...policy.platforms],
    rollback: policy.rollback,
    publishedVersions,
    formats: [...provenFormats, ...unprovenFormats].sort((left, right) => left.formats[0] - right.formats[0]),
  }
  assertCompatibilityPolicy(matrix, policy)
  return { matrix, matrixDigest: matrixDigest(matrix), policy }
}

export function matrixDigest(matrix) {
  return sha256(stableJSON(matrix))
}

export function assertCompatibilityPolicy(matrix, policy) {
  requireCondition(matrix.schema === MATRIX_SCHEMA, 'The compatibility matrix has the wrong schema.')
  requireCondition(Number.isInteger(matrix.minimumSupportedFormat) && matrix.minimumSupportedFormat >= 1, 'The compatibility matrix has no valid minimum supported format.')
  requireCondition(Number.isInteger(matrix.currentFormat) && matrix.currentFormat >= matrix.minimumSupportedFormat, 'The compatibility matrix has no valid current format.')
  requireCondition(
    matrix.minimumSupportedFormat === policy.minimumSupportedFormat,
    `The minimum supported vault format is ${matrix.minimumSupportedFormat}, but the recorded decision covers ${policy.minimumSupportedFormat}. Record the compatibility decision in ${POLICY_PATH} before raising the minimum supported format.`,
  )
  requireCondition(matrix.fixtureManifestSha256 && sha256Pattern.test(matrix.fixtureManifestSha256), 'The compatibility matrix has no fixture manifest digest.')
  requireCondition(typeof matrix.rollback === 'string' && matrix.rollback.length > 0, 'The compatibility matrix must carry the rollback rule for a vault this release upgraded.')
  requireCondition(matrix.publishedVersions.length > 0, 'The compatibility matrix has no published releases.')

  const proven = new Map()
  const unproven = new Map()
  for (const record of matrix.formats) {
    requireCondition(Array.isArray(record.formats) && record.formats.length > 0, 'A compatibility format record names no formats.')
    for (const format of record.formats) {
      requireCondition(Number.isInteger(format) && format >= 1, 'A compatibility format record contains an invalid format number.')
      if (record.status === 'proven') {
        requireCondition(Array.isArray(record.fixtureIds) && record.fixtureIds.length > 0, `Format ${format} is marked proven without a fixture.`)
        proven.set(format, record.fixtureIds)
      } else if (record.status === 'unprovenRecovery') {
        requireCondition(record.readersRetained === true, `Format ${format} has no retained reader and no fixture.`)
        unproven.set(format, record)
      } else {
        throw new Error(`A compatibility format record uses an unknown status: ${record.status}.`)
      }
    }
  }
  const fixtureIds = new Set(matrix.publishedVersions.map((version) => version.fixtureId))
  for (const [format, ids] of proven) {
    for (const id of ids) requireCondition(fixtureIds.has(id), `Format ${format} names fixture ${id}, which is not a published release fixture.`)
  }
  for (let format = matrix.minimumSupportedFormat; format <= matrix.currentFormat; format += 1) {
    requireCondition(
      proven.has(format) || unproven.has(format),
      `Format ${format} is inside the supported range but has no genuine writer fixture and no recorded recovery path.`,
    )
  }
  requireCondition(proven.has(matrix.currentFormat), `The current format ${matrix.currentFormat} has no genuine writer fixture.`)
  return matrix
}

export function assertRetainedReaderLabels({ coreSource, matrix }) {
  const hasLegacyLabel = /pub const LEGACY_PAYLOAD_AAD: &\[u8\] = b"[^"]+";/.test(coreSource)
  const hasLegacyArm = /\(2\.\.=8, true\)\s*=>\s*Ok\(LEGACY_PAYLOAD_AAD\)/.test(coreSource)
  const hasFormat9Label = /pub const FORMAT_9_PAYLOAD_AAD: &\[u8\] = b"[^"]+";/.test(coreSource)
  const hasFormat9Arm = /\(9, true\)\s*=>\s*Ok\(FORMAT_9_PAYLOAD_AAD\)/.test(coreSource)
  if (matrix.minimumSupportedFormat <= 8) {
    requireCondition(hasLegacyLabel && hasLegacyArm, 'Formats 2 through 8 stay inside the supported range, but their exact authentication label is gone from payload_aad_for_file.')
  }
  if (matrix.minimumSupportedFormat <= 9) {
    requireCondition(hasFormat9Label && hasFormat9Arm, 'Format 9 stays inside the supported range, but its exact authentication label is gone from payload_aad_for_file.')
  }
  return coreSource
}

export function assertInstalledRun(run, { matrix, policy, matrixDigest: expectedMatrixDigest }) {
  requireCondition(run?.schema === RUN_SCHEMA, 'An installed-app run record has the wrong schema.')
  requireCondition(policy.platforms.includes(run.platform), `An installed-app run names an unapproved platform: ${run.platform}.`)
  requireCondition(['x86_64', 'aarch64'].includes(run.architecture), `An installed-app run names an unknown architecture: ${run.architecture}.`)
  requireCondition(run.matrixDigest === expectedMatrixDigest, 'An installed-app run does not match the current compatibility matrix.')
  requireCondition(run.fixtureManifestSha256 === matrix.fixtureManifestSha256, 'An installed-app run does not match the current fixture manifest.')
  requireCondition(sha256Pattern.test(run.binarySha256 ?? ''), 'An installed-app run does not record the tested binary digest.')
  requireCondition(run.buildKind === 'tauri-wdio-test-build', 'The installed-app gate only counts a full app build with the test bridge.')
  requireCondition(run.result === 'passed' && run.skipped !== true, `The ${run.platform} ${run.fixtureId} installed-app run did not pass.`)
  const version = matrix.publishedVersions.find((entry) => entry.fixtureId === run.fixtureId)
  requireCondition(version, `An installed-app run names an unknown fixture: ${run.fixtureId}.`)
  requireCondition(run.fixtureSha256 === version.fixtureDigestSha256, `The ${run.fixtureId} run did not test the recorded fixture bytes.`)
  for (const [phase, requiredSteps] of [['restore', requiredRestoreSteps], ['restart', requiredRestartSteps]]) {
    const report = run.phases?.[phase]
    requireCondition(report && report.failed === 0 && report.passed > 0, `The ${run.fixtureId} ${phase} phase has no passing result.`)
    for (const step of requiredSteps) {
      const recorded = (report.steps ?? []).find((entry) => entry.name === step)
      requireCondition(recorded?.ok === true, `The ${run.fixtureId} ${phase} phase did not pass ${step}.`)
    }
  }
  return run
}

export function mergeInstalledEvidence({ runs, reportDigests = {}, matrix, policy, matrixDigest: expectedMatrixDigest }) {
  const verified = runs.map((run) => assertInstalledRun(run, { matrix, policy, matrixDigest: expectedMatrixDigest }))
  const seen = new Set()
  for (const run of verified) {
    const key = `${run.platform}:${run.fixtureId}`
    requireCondition(!seen.has(key), `The vault compatibility gate received two installed-app runs for ${key}.`)
    seen.add(key)
  }
  const platforms = []
  for (const platform of policy.platforms) {
    const platformRuns = verified.filter((run) => run.platform === platform)
    requireCondition(platformRuns.length > 0, `The vault compatibility gate has no installed-app evidence for ${platform}.`)
    const fixtures = matrix.publishedVersions.map((version) => {
      const run = platformRuns.find((entry) => entry.fixtureId === version.fixtureId)
      requireCondition(run, `The ${platform} installed-app evidence is missing fixture ${version.fixtureId}.`)
      return {
        id: run.fixtureId,
        digestSha256: run.fixtureSha256,
        restoreSteps: run.phases.restore.passed,
        restartSteps: run.phases.restart.passed,
        reportSha256: reportDigests[`${platform}:${run.fixtureId}`] ?? sha256(stableJSON(run)),
        startedAt: run.startedAt,
        finishedAt: run.finishedAt,
      }
    })
    platforms.push({
      platform,
      architecture: platformRuns[0].architecture,
      version: platformRuns[0].version,
      buildKind: platformRuns[0].buildKind,
      binarySha256: platformRuns[0].binarySha256,
      result: 'passed',
      fixtures,
    })
  }
  return {
    schema: EVIDENCE_SCHEMA,
    matrixDigest: expectedMatrixDigest,
    fixtureManifestSha256: matrix.fixtureManifestSha256,
    minimumSupportedFormat: matrix.minimumSupportedFormat,
    currentFormat: matrix.currentFormat,
    platforms,
    result: 'passed',
    generatedAt: new Date().toISOString(),
  }
}

export function validateCompatibilityEvidence(evidence, { matrix, policy, matrixDigest: expectedMatrixDigest }) {
  requireCondition(evidence?.schema === EVIDENCE_SCHEMA, 'The vault compatibility evidence has the wrong schema.')
  requireCondition(evidence.result === 'passed', 'The vault compatibility evidence did not pass.')
  requireCondition(evidence.matrixDigest === expectedMatrixDigest, 'The vault compatibility evidence does not match the current matrix.')
  requireCondition(evidence.fixtureManifestSha256 === matrix.fixtureManifestSha256, 'The vault compatibility evidence does not match the current fixture manifest.')
  requireCondition(evidence.minimumSupportedFormat === policy.minimumSupportedFormat, 'The vault compatibility evidence does not match the recorded format decision.')
  const platforms = new Set((evidence.platforms ?? []).map((entry) => entry.platform))
  for (const platform of policy.platforms) {
    requireCondition(platforms.has(platform), `The vault compatibility evidence is missing ${platform}.`)
  }
  for (const entry of evidence.platforms ?? []) {
    requireCondition(entry.result === 'passed', `The ${entry.platform} vault compatibility evidence did not pass.`)
    requireCondition(sha256Pattern.test(entry.binarySha256 ?? ''), `The ${entry.platform} evidence does not record the tested binary digest.`)
    for (const version of matrix.publishedVersions) {
      const fixture = (entry.fixtures ?? []).find((item) => item.id === version.fixtureId)
      requireCondition(fixture, `The ${entry.platform} evidence is missing fixture ${version.fixtureId}.`)
      requireCondition(fixture.digestSha256 === version.fixtureDigestSha256, `The ${entry.platform} ${version.fixtureId} evidence does not match the fixture bytes.`)
      requireCondition(fixture.restoreSteps > 0 && fixture.restartSteps > 0, `The ${entry.platform} ${version.fixtureId} evidence records no passing phases.`)
    }
  }
  return evidence
}

export async function assertRepositoryCompatibility(root = repositoryRoot) {
  const { matrix, policy, matrixDigest: digest } = await buildCompatibilityMatrix(root)
  const coreSource = await readRepositoryFile(root, 'src-tauri/sesame-core/src/lib.rs')
  assertRetainedReaderLabels({ coreSource, matrix })
  return { matrix, policy, matrixDigest: digest }
}

async function writeJSON(file, value) {
  await mkdir(path.dirname(path.resolve(file)), { recursive: true })
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`)
}

async function main(argv) {
  const [command, ...rest] = argv
  const repo = path.resolve(process.env.SESAME_VAULT_REPO?.trim() || repositoryRoot)
  if (command === 'verify') {
    const { matrix, matrixDigest: digest } = await assertRepositoryCompatibility(repo)
    process.stdout.write(`Vault compatibility matrix ${digest} verified across ${matrix.publishedVersions.length} published releases and ${matrix.platforms.length} platforms.\n`)
    return 0
  }
  if (command === 'matrix') {
    const file = rest[0]
    if (!file) throw new Error('Usage: node tools/vault-compatibility-gate.mjs matrix <output-file>')
    const { matrix, matrixDigest: digest } = await assertRepositoryCompatibility(repo)
    await writeJSON(file, { ...matrix, matrixDigest: digest })
    process.stdout.write(`${digest} ${file}\n`)
    return 0
  }
  if (command === 'merge') {
    const file = rest[0]
    const runFiles = rest.slice(1)
    if (!file || runFiles.length === 0) throw new Error('Usage: node tools/vault-compatibility-gate.mjs merge <output-file> <run-file...>')
    const { matrix, policy, matrixDigest: digest } = await buildCompatibilityMatrix(repo)
    const runs = []
    const reportDigests = {}
    for (const runFile of runFiles) {
      const bytes = await readFile(runFile)
      const run = JSON.parse(bytes.toString('utf8'))
      runs.push(run)
      reportDigests[`${run.platform}:${run.fixtureId}`] = sha256(bytes)
    }
    const evidence = mergeInstalledEvidence({ runs, reportDigests, matrix, policy, matrixDigest: digest })
    validateCompatibilityEvidence(evidence, { matrix, policy, matrixDigest: digest })
    await writeJSON(file, evidence)
    process.stdout.write(`Vault compatibility evidence passed for ${evidence.platforms.map((entry) => entry.platform).join(', ')}.\n`)
    return 0
  }
  throw new Error(`Unknown command: ${command ?? '(none)'}. Use verify, matrix, or merge.`)
}

const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
if (invokedDirectly) {
  main(process.argv.slice(2)).then((code) => {
    process.exitCode = code
  }).catch((error) => {
    process.stderr.write(`${error.message}\n`)
    process.exitCode = 1
  })
}
