import assert from 'node:assert/strict'
import test from 'node:test'

import { RELEASE_REPOSITORY, RELEASE_WORKFLOW, SIGSTORE_ISSUER, releaseIdentity, validateReleaseManifest } from './release-evidence-lib.mjs'

const version = '1.2.3'
const tag = `v${version}`
const identity = releaseIdentity(RELEASE_REPOSITORY, RELEASE_WORKFLOW, `refs/tags/${tag}`)

function manifestFixture() {
  return {
    schemaVersion: 1,
    product: 'Sesame',
    releaseKind: 'unsigned-windows-early-access',
    version,
    channel: 'beta',
    platform: 'windows',
    architecture: 'x86_64',
    source: { repository: RELEASE_REPOSITORY, workflow: RELEASE_WORKFLOW, ref: `refs/tags/${tag}`, commit: 'a'.repeat(40) },
    artifact: { filename: 'Sesame_1.2.3_x64-setup.exe', sha256: 'b'.repeat(64), bytes: 48213 },
    updaterSignature: { filename: 'Sesame_1.2.3_x64-setup.exe.sig', sha256: 'c'.repeat(64), bytes: 128, signingKeyId: 'updater-1' },
    sbom: { filename: 'sesame-1.2.3.cdx.json', sha256: 'd'.repeat(64), bytes: 2048 },
    sigstore: { issuer: SIGSTORE_ISSUER, certificateIdentity: identity, transparencyLogRequired: true },
    windowsTrust: { authenticodeVerified: false, smartScreenReputationPromised: false, label: 'Unsigned Windows early-access build' },
    supportedWindows: 'Windows 10,Windows 11',
    releaseNotesUrl: 'https://usesesame.app/releases/1.2.3',
  }
}

function mulberry32(seed) {
  let state = seed | 0
  return () => {
    state = (state + 0x6d2b79f5) | 0
    let mixed = Math.imul(state ^ (state >>> 15), 1 | state)
    mixed = (mixed + Math.imul(mixed ^ (mixed >>> 7), 61 | mixed)) ^ mixed
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4294967296
  }
}

function mutate(manifest, random) {
  const candidate = structuredClone(manifest)
  const paths = [
    ['schemaVersion'], ['product'], ['releaseKind'], ['version'], ['channel'], ['platform'], ['architecture'],
    ['source', 'repository'], ['source', 'workflow'], ['source', 'ref'], ['source', 'commit'],
    ['artifact', 'filename'], ['artifact', 'sha256'], ['artifact', 'bytes'],
    ['updaterSignature', 'filename'], ['updaterSignature', 'sha256'], ['updaterSignature', 'bytes'], ['updaterSignature', 'signingKeyId'],
    ['sbom', 'sha256'], ['sbom', 'bytes'],
    ['sigstore', 'issuer'], ['sigstore', 'certificateIdentity'], ['sigstore', 'transparencyLogRequired'],
    ['windowsTrust', 'authenticodeVerified'], ['windowsTrust', 'smartScreenReputationPromised'], ['windowsTrust', 'label'],
    ['supportedWindows'], ['releaseNotesUrl'],
  ]
  const mutations = random.int(1, 3)
  for (let index = 0; index < mutations; index += 1) {
    const depth = random.int(1, paths.length)
    const target = paths[depth - 1]
    let parent = candidate
    for (const part of target.slice(0, -1)) {
      parent = parent?.[part]
      if (parent === undefined || parent === null) break
    }
    const leaf = target[target.length - 1]
    if (parent === undefined || parent === null || typeof parent !== 'object') continue
    switch (random.int(0, 5)) {
      case 0: delete parent[leaf]; break
      case 1: parent[leaf] = null; break
      case 2: parent[leaf] = random.int(0, 1) === 0 ? random.int(-5, 300) : `tampered-${leaf}`; break
      case 3: parent[leaf] = parent[leaf] === true ? 'true' : false; break
      case 4: parent[leaf] = `${parent[leaf] ?? ''}../../escape`; break
      default: parent[leaf] = random.pick(['beta', 'owner', 'stable', 'x86_64', 'aarch64', '1.2.3', '9.9.9', 'latest'])
    }
  }
  return candidate
}

function makeRandom(seed) {
  let state = seed | 0
  const next = () => {
    state = (state * 1103515245 + 12345) & 0x7fffffff
    return state / 0x7fffffff
  }
  return {
    next,
    int: (low, high) => low + Math.floor(next() * (high - low + 1)),
    pick: (values) => values[Math.floor(next() * values.length)],
  }
}

test('the validator survives thousands of mutated manifests without crashing', () => {
  let rejected = 0
  let accepted = 0
  for (let seed = 1; seed <= 1500; seed += 1) {
    const candidate = mutate(manifestFixture(), makeRandom(seed * 7919))
    try {
      validateReleaseManifest(candidate)
      accepted += 1
    } catch (error) {
      rejected += 1
      assert.ok(error instanceof Error)
    }
  }
  assert.ok(accepted > 0, 'the untouched fixture must still validate')
  assert.ok(rejected > 0, 'mutations must be rejected')
})

test('structural attacks stay rejected', () => {
  const valid = manifestFixture()
  for (const candidate of [
    valid,
    null,
    undefined,
    'manifest',
    [],
    { ...valid, artifact: { ...valid.artifact, filename: '../../etc/passwd' } },
    { ...valid, artifact: { ...valid.artifact, sha256: valid.artifact.sha256.toUpperCase() } },
    { ...valid, source: { ...valid.source, ref: 'refs/heads/main' } },
    { ...valid, sigstore: { ...valid.sigstore, transparencyLogRequired: false } },
  ]) {
    if (candidate === valid) {
      assert.doesNotThrow(() => validateReleaseManifest(candidate))
    } else {
      assert.throws(() => validateReleaseManifest(candidate))
    }
  }
})
