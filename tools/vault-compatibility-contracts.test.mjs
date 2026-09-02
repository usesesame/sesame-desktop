import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const corpus = join(root, 'src-tauri', 'sesame-core', 'tests', 'fixtures', 'compatibility')
const read = (...parts) => readFileSync(join(...parts), 'utf8')

const loadManifest = () => JSON.parse(read(corpus, 'manifest.json'))

const publishedTags = ['v0.1.0', 'v0.1.1', 'v0.2.0', 'v0.2.1', 'v0.2.2']
const countKeys = [
  'entries',
  'identities',
  'secureNotes',
  'cards',
  'wifiNetworks',
  'sshKeys',
  'softwareLicenses',
  'documents',
  'customRecords',
  'folders',
  'trash',
  'history',
]
const envelopeKeys = [
  'formatVersion',
  'kdf',
  'keyWrap',
  'deviceWrap',
  'recoveryKdf',
  'recoveryWrap',
  'pinWrap',
  'helloWrap',
  'setupComplete',
  'payload',
]

test('the corpus records every published desktop release', () => {
  const manifest = loadManifest()
  assert.equal(manifest.corpusSchema, 'sesame.compatibility-corpus/1')
  assert.equal(manifest.digestAlgorithm, 'sha256')
  assert.deepEqual(
    manifest.fixtures.map((fixture) => fixture.id),
    publishedTags,
  )
  assert.deepEqual(
    manifest.publishedVersions.map((version) => version.tag),
    publishedTags,
  )
  for (const version of manifest.publishedVersions) {
    assert.match(version.commit, /^[0-9a-f]{40}$/)
  }
})

test('each fixture entry is complete and inside recorded limits', () => {
  for (const fixture of loadManifest().fixtures) {
    const label = fixture.id
    assert.match(fixture.writerCommit, /^[0-9a-f]{40}$/, label)
    assert.match(fixture.digestSha256, /^[0-9a-f]{64}$/, label)
    assert.equal(fixture.formatVersion, 10, label)
    assert.equal(fixture.setupComplete, true, label)
    assert.equal(fixture.kdf.algorithm, 'argon2id', label)
    assert.ok(fixture.kdf.memoryKib > 0 && fixture.kdf.memoryKib <= 1_048_576, label)
    assert.ok(fixture.kdf.iterations > 0 && fixture.kdf.iterations <= 20, label)
    assert.ok(fixture.kdf.parallelism > 0 && fixture.kdf.parallelism <= 16, label)
    assert.ok(fixture.secrets.masterPassword.length >= 12, label)
    assert.ok(fixture.secrets.recoveryKit.length >= 10, label)
    assert.ok(fixture.vault.name.length > 0, label)
    assert.ok(fixture.vault.vaultId.length > 0, label)
    assert.ok(fixture.vault.revision >= 1, label)
    for (const key of countKeys) {
      assert.ok(fixture.counts[key] >= 1, `${label} ${key}`)
    }
    assert.ok(fixture.stableIds.includes('login-empty'), label)
    assert.equal(typeof fixture.payloadShape.identityHasFavourite, 'boolean', label)
    assert.equal(typeof fixture.payloadShape.identityHasTags, 'boolean', label)
    assert.equal(fixture.expectedMigration.fileChanged, false, label)
    assert.equal(fixture.expectedMigration.payloadChanged, true, label)
    assert.deepEqual(fixture.expectedMigration.afterOpenCounts, fixture.counts, label)
    assert.ok(
      fixture.expectedMigration.preservedTimestamps['login-alpha'].createdAt > 0,
      label,
    )
    assert.ok(fixture.expectedMigration.backfilled['login-empty'].length >= 4, label)
  }
})

test('every fixture matches its recorded digest and is a genuine sealed envelope', () => {
  for (const fixture of loadManifest().fixtures) {
    const raw = readFileSync(join(corpus, fixture.fileName))
    assert.equal(
      createHash('sha256').update(raw).digest('hex'),
      fixture.digestSha256,
      fixture.fileName,
    )
    const envelope = JSON.parse(raw.toString('utf8'))
    for (const key of Object.keys(envelope)) {
      assert.ok(envelopeKeys.includes(key), `${fixture.fileName} unexpected envelope key ${key}`)
    }
    assert.equal(envelope.formatVersion, fixture.formatVersion, fixture.fileName)
    assert.equal(envelope.setupComplete, fixture.setupComplete, fixture.fileName)
    const nonce = Buffer.from(envelope.keyWrap.nonce, 'base64url')
    const ciphertext = Buffer.from(envelope.keyWrap.ciphertext, 'base64url')
    assert.equal(nonce.length, 24, fixture.fileName)
    assert.ok(ciphertext.length >= 16, fixture.fileName)
    const payloadNonce = Buffer.from(envelope.payload.nonce, 'base64url')
    const payloadCipher = Buffer.from(envelope.payload.ciphertext, 'base64url')
    assert.equal(payloadNonce.length, 24, fixture.fileName)
    assert.ok(payloadCipher.length >= 16, fixture.fileName)
  }
})

test('formats without a recoverable writer stay recorded as unproven', () => {
  const recorded = loadManifest()
  assert.deepEqual(
    recorded.provenFormats.map((format) => format.format),
    [10],
  )
  assert.equal(recorded.unprovenFormats.length, 1)
  const unproven = recorded.unprovenFormats[0]
  assert.deepEqual(unproven.formats, [2, 3, 4, 5, 6, 7, 8, 9])
  assert.ok(unproven.reason.length > 0)
  assert.ok(unproven.evidence.length > 0)
  assert.equal(unproven.decision.status, 'supportRetained')
  assert.ok(unproven.decision.note.length > 0)
})

test('each declared writer generation ships its generator driver', () => {
  const recorded = loadManifest()
  for (const generation of recorded.writerGenerations) {
    const driver = read(corpus, generation.generator)
    assert.match(driver, /create_vault\(/, generation.id)
    assert.match(driver, /complete_recovery_setup_for_session\(/, generation.id)
    assert.match(driver, /fn generate_fixture_with_this_releases_writer/, generation.id)
    const versions = JSON.stringify(generation.versions)
    for (const tag of generation.versions) {
      assert.ok(versions.includes(tag), generation.id)
    }
  }
  const fixtureGenerations = new Set(recorded.fixtures.map((fixture) => fixture.writerGeneration))
  for (const id of fixtureGenerations) {
    assert.ok(
      recorded.writerGenerations.some((generation) => generation.id === id),
      `fixture names undeclared generation ${id}`,
    )
  }
})

test('the corpus holds no secret outside the recorded fictional ones', () => {
  const recorded = loadManifest()
  const secrets = recorded.fixtures.flatMap((fixture) => [
    fixture.secrets.masterPassword,
    fixture.secrets.recoveryKit,
  ])
  const scanTargets = ['manifest.json']
  for (const fixture of recorded.fixtures) scanTargets.push(fixture.fileName)
  for (const name of scanTargets) {
    const raw = readFileSync(join(corpus, name)).toString('utf8')
    assert.doesNotMatch(raw, /-----BEGIN [A-Z ]*PRIVATE KEY/, name)
    assert.doesNotMatch(raw, /AKIA[0-9A-Z]{16}/, name)
    if (name.endsWith('.sesame')) {
      for (const secret of secrets) {
        assert.ok(!raw.includes(secret), `${name} carries a plaintext recorded secret`)
      }
    }
  }
  const driverText = ['generate_fixtures_legacy.rs', 'generate_fixtures_current.rs']
    .map((name) => read(corpus, 'generator', name))
    .join('\n')
  for (const kit of recorded.fixtures.map((fixture) => fixture.secrets.recoveryKit)) {
    assert.ok(!driverText.includes(kit), 'a generator driver hardcodes a recorded recovery kit')
  }
})
