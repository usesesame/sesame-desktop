import assert from 'node:assert/strict'
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { RELEASE_REPOSITORY, RELEASE_WORKFLOW, SIGSTORE_ISSUER, fileSha256, releaseIdentity } from './release-evidence-lib.mjs'
import {
  LATEST_MANIFEST_FILENAME,
  RELEASE_SET_DIGEST_LABEL,
  assertCandidateMatchesAssets,
  collectPublishAssets,
  interpretCandidateSubmission,
  latestReceiptBindsInstaller,
  planReleasePublication,
} from './release-publish-reconcile.mjs'

const version = '1.2.3'
const tag = `v${version}`
const ref = `refs/tags/${tag}`
const identity = releaseIdentity(RELEASE_REPOSITORY, RELEASE_WORKFLOW, ref)
const setDigest = 'c'.repeat(64)

async function evidenceFixture() {
  const root = await mkdtemp(path.join(tmpdir(), 'sesame-publish-reconcile-'))
  const files = {
    artifact: 'Sesame_1.2.3_x64-setup.exe',
    updaterSignature: 'Sesame_1.2.3_x64-setup.exe.sig',
    sbom: 'sesame-1.2.3.cdx.json',
    manifest: 'sesame-1.2.3-windows-x86_64.release.json',
  }
  await writeFile(path.join(root, files.artifact), 'fictional installer bytes')
  await writeFile(path.join(root, files.updaterSignature), 'A'.repeat(64))
  await writeFile(path.join(root, files.sbom), '{"bomFormat":"CycloneDX"}\n')
  const describe = async (filename) => ({ filename, sha256: await fileSha256(path.join(root, filename)), bytes: (await readFile(path.join(root, filename))).length })
  const manifest = {
    schemaVersion: 1, product: 'Sesame', releaseKind: 'unsigned-windows-early-access', version, channel: 'beta', platform: 'windows', architecture: 'x86_64',
    source: { repository: RELEASE_REPOSITORY, workflow: RELEASE_WORKFLOW, ref, commit: 'a'.repeat(40) },
    artifact: await describe(files.artifact),
    updaterSignature: { ...await describe(files.updaterSignature), signingKeyId: 'updater-1' },
    sbom: await describe(files.sbom),
    sigstore: { issuer: SIGSTORE_ISSUER, certificateIdentity: identity, transparencyLogRequired: true },
    windowsTrust: { authenticodeVerified: false, smartScreenReputationPromised: false, label: 'Unsigned Windows early-access build' },
    supportedWindows: 'Windows 10,Windows 11', releaseNotesUrl: 'https://usesesame.app/releases/1.2.3',
  }
  await writeFile(path.join(root, files.manifest), `${JSON.stringify(manifest, null, 2)}\n`)
  await writeFile(path.join(root, `${files.artifact}.sigstore.json`), '{"fictional":"artifact bundle"}\n')
  await writeFile(path.join(root, `${files.manifest}.sigstore.json`), '{"fictional":"manifest bundle"}\n')
  const evidence = {
    schemaVersion: 1, verified: true, transparencyLogVerified: true, issuer: manifest.sigstore.issuer, certificateIdentity: identity,
    repository: RELEASE_REPOSITORY, workflow: RELEASE_WORKFLOW, ref, sourceCommit: manifest.source.commit,
    artifactSha256: manifest.artifact.sha256, manifestSha256: await fileSha256(path.join(root, files.manifest)),
    artifactBundleSha256: await fileSha256(path.join(root, `${files.artifact}.sigstore.json`)), manifestBundleSha256: await fileSha256(path.join(root, `${files.manifest}.sigstore.json`)), verifiedAt: '2026-09-06T00:00:00.000Z',
  }
  await writeFile(path.join(root, 'sigstore-evidence.json'), `${JSON.stringify(evidence, null, 2)}\n`)
  await writeFile(path.join(root, 'SHA256SUMS'), `${manifest.artifact.sha256}  ${files.artifact}\n`)
  await writeFile(path.join(root, 'verify-sesame-release.ps1'), 'param([string]$Installer)\n')
  return { files, manifest, root }
}

function candidateFixture(manifest) {
  const updater = {
    format: 'nsis', architecture: manifest.architecture,
    url: `https://github.com/${RELEASE_REPOSITORY}/releases/download/${tag}/${manifest.artifact.filename}`,
    objectKey: `windows/${version}/${manifest.artifact.filename}`,
    sha256: manifest.artifact.sha256, bytes: manifest.artifact.bytes,
    updaterCapable: true, updaterSignature: 's'.repeat(64), updaterSigningKeyId: 'updater-1',
    distributionClass: 'early_access', sigstoreVerified: true, sigstoreIssuer: SIGSTORE_ISSUER,
    sigstoreIdentity: identity, sigstoreBundleSha256: 'b'.repeat(64),
    authenticodeVerified: false,
  }
  const receiptLines = [
    'sesame-release-candidate-v3', version, 'beta', 'windows', 'x86_64', 'Windows 10,Windows 11',
    manifest.releaseNotesUrl, updater.url, updater.objectKey, updater.sha256, String(updater.bytes),
    updater.updaterSignature, updater.updaterSigningKeyId, updater.distributionClass, 'true',
    updater.sigstoreIssuer, updater.sigstoreIdentity, updater.sigstoreBundleSha256, 'e'.repeat(43),
    'false', '', '', '',
  ]
  const candidate = {
    schemaVersion: 3, version, channel: 'beta', platform: 'windows', architecture: 'x86_64',
    supportedWindows: 'Windows 10,Windows 11', releaseNotesUrl: manifest.releaseNotesUrl,
    setDigest, artifacts: [updater], candidateSigningKeyId: 'candidate-1', candidateSignature: 'g'.repeat(86),
  }
  const latest = {
    version,
    url: updater.url,
    notes: `Verification and release notes: ${manifest.releaseNotesUrl}`,
    platforms: { 'windows-x86_64-nsis': { url: updater.url, signature: updater.updaterSignature } },
    candidateReceipt: { payload: receiptLines.join('\n'), signingKeyId: 'candidate-1', signature: 'g'.repeat(86) },
  }
  return { candidate, latest, updater }
}

async function publishFixture() {
  const evidence = await evidenceFixture()
  const { candidate, latest, updater } = candidateFixture(evidence.manifest)
  await writeFile(path.join(evidence.root, LATEST_MANIFEST_FILENAME), `${JSON.stringify(latest, null, 2)}\n`)
  const publicRoot = `${evidence.root}-public`
  await mkdir(publicRoot)
  for (const name of ['SHA256SUMS', `${evidence.files.artifact}.sigstore.json`, `${evidence.files.manifest}.sigstore.json`, evidence.files.sbom, evidence.files.manifest, 'sigstore-evidence.json', 'verify-sesame-release.ps1']) {
    await writeFile(path.join(publicRoot, name), `${name} public evidence bytes\n`)
  }
  const { assets } = await collectPublishAssets(evidence.root, publicRoot, evidence.files.manifest)
  return { assets, candidate, evidence, latest, publicRoot, updater }
}

const releaseWith = (assets, extra = {}) => ({ isDraft: false, body: 'notes', assets, ...extra })
const remoteAsset = (asset, override = {}) => ({ name: asset.name, size: asset.bytes, sha256: asset.sha256, ...override })

test('the publish set is exactly the installer, updater signature, static manifest, and audited public evidence', async () => {
  const value = await publishFixture()
  try {
    const names = value.assets.map((asset) => asset.name).sort()
    assert.equal(names.length, 10)
    assert.deepEqual(names, [
      'SHA256SUMS',
      LATEST_MANIFEST_FILENAME,
      'sesame-1.2.3.cdx.json',
      value.evidence.files.manifest,
      `${value.evidence.files.manifest}.sigstore.json`,
      'sigstore-evidence.json',
      value.evidence.files.artifact,
      `${value.evidence.files.artifact}.sigstore.json`,
      value.evidence.files.updaterSignature,
      'verify-sesame-release.ps1',
    ].sort())
    assert.equal(value.assets.find((asset) => asset.role === 'installer').sha256, value.evidence.manifest.artifact.sha256)
  } finally {
    await rm(value.evidence.root, { recursive: true, force: true })
    await rm(value.publicRoot, { recursive: true, force: true })
  }
})

test('a fresh publication creates the release with every verified asset', async () => {
  const value = await publishFixture()
  try {
    const plan = planReleasePublication({ release: null, expectedAssets: value.assets, setDigest })
    assert.equal(plan.action, 'create')
    assert.deepEqual(plan.upload.sort(), value.assets.map((asset) => asset.name).sort())
    assert.deepEqual(plan.conflicts, [])
  } finally {
    await rm(value.evidence.root, { recursive: true, force: true })
    await rm(value.publicRoot, { recursive: true, force: true })
  }
})

test('retrying after a GitHub success verifies every asset by digest and uploads nothing', async () => {
  const value = await publishFixture()
  try {
    const plan = planReleasePublication({ release: releaseWith(value.assets.map((asset) => remoteAsset(asset))), expectedAssets: value.assets, setDigest })
    assert.equal(plan.action, 'complete')
    assert.deepEqual(plan.upload, [])
    assert.deepEqual(plan.conflicts, [])
  } finally {
    await rm(value.evidence.root, { recursive: true, force: true })
    await rm(value.publicRoot, { recursive: true, force: true })
  }
})

test('retrying after a partial publish uploads exactly the missing assets', async () => {
  const value = await publishFixture()
  try {
    const present = value.assets.slice(0, 8)
    const plan = planReleasePublication({ release: releaseWith(present.map((asset) => remoteAsset(asset))), expectedAssets: value.assets, setDigest })
    assert.equal(plan.action, 'resume')
    assert.deepEqual(plan.upload.sort(), value.assets.slice(8).map((asset) => asset.name).sort())
    assert.deepEqual(plan.conflicts, [])
  } finally {
    await rm(value.evidence.root, { recursive: true, force: true })
    await rm(value.publicRoot, { recursive: true, force: true })
  }
})

test('conflicting digests, sizes, extra assets, drafts, and a foreign set digest stop the run before any mutation', async () => {
  const value = await publishFixture()
  try {
    const installer = value.assets.find((asset) => asset.role === 'installer')
    const digestConflict = planReleasePublication({
      release: releaseWith(value.assets.map((asset) => remoteAsset(asset, asset.role === 'installer' ? { sha256: 'd'.repeat(64) } : {}))),
      expectedAssets: value.assets, setDigest,
    })
    assert.equal(digestConflict.action, 'conflict')
    assert.ok(digestConflict.conflicts.some((line) => line.includes(installer.name) && line.includes('d'.repeat(64))))
    assert.deepEqual(digestConflict.upload, [])

    const sizeConflict = planReleasePublication({
      release: releaseWith(value.assets.map((asset) => remoteAsset(asset, asset.role === 'installer' ? { size: asset.bytes + 1 } : {}))),
      expectedAssets: value.assets, setDigest,
    })
    assert.ok(sizeConflict.conflicts.some((line) => line.includes(installer.name) && line.includes('bytes')))

    const extra = planReleasePublication({
      release: releaseWith([...value.assets.map((asset) => remoteAsset(asset)), remoteAsset({ name: 'release-token.env', bytes: 3, sha256: 'd'.repeat(64) })]),
      expectedAssets: value.assets, setDigest,
    })
    assert.ok(extra.conflicts.some((line) => line.includes('release-token.env')))

    const draft = planReleasePublication({ release: releaseWith(value.assets.map((asset) => remoteAsset(asset)), { isDraft: true }), expectedAssets: value.assets, setDigest })
    assert.ok(draft.conflicts.some((line) => line.includes('draft')))

    const foreignDigest = planReleasePublication({ release: releaseWith(value.assets.map((asset) => remoteAsset(asset)), { body: `${RELEASE_SET_DIGEST_LABEL}: ${'d'.repeat(64)}` }), expectedAssets: value.assets, setDigest })
    assert.ok(foreignDigest.conflicts.some((line) => line.includes('d'.repeat(64))))

    const anchorTolerated = planReleasePublication({ release: releaseWith(value.assets.map((asset) => remoteAsset(asset)), { body: `older notes without the anchor\n` }), expectedAssets: value.assets, setDigest })
    assert.equal(anchorTolerated.action, 'complete')
  } finally {
    await rm(value.evidence.root, { recursive: true, force: true })
    await rm(value.publicRoot, { recursive: true, force: true })
  }
})

test('the candidate, static manifest, and installer bytes must describe the same release asset', async () => {
  const value = await publishFixture()
  try {
    assert.equal(assertCandidateMatchesAssets(value.candidate, value.assets, { repository: RELEASE_REPOSITORY, tag, latest: value.latest }), value.latest)

    const wrongVersion = structuredClone(value.candidate)
    wrongVersion.version = '9.9.9'
    assert.throws(() => assertCandidateMatchesAssets(wrongVersion, value.assets, { repository: RELEASE_REPOSITORY, tag, latest: value.latest }), /does not describe release tag/)

    const foreignURL = structuredClone(value.candidate)
    foreignURL.artifacts[0].url = `https://github.com/attacker/desktop/releases/download/${tag}/${value.evidence.files.artifact}`
    assert.throws(() => assertCandidateMatchesAssets(foreignURL, value.assets, { repository: RELEASE_REPOSITORY, tag, latest: value.latest }), /exact release asset URL/)

    const otherInstaller = structuredClone(value.candidate)
    otherInstaller.artifacts[0].sha256 = 'd'.repeat(64)
    assert.throws(() => assertCandidateMatchesAssets(otherInstaller, value.assets, { repository: RELEASE_REPOSITORY, tag, latest: value.latest }), /verified installer bytes/)

    const retargetedReceipt = structuredClone(value.latest)
    retargetedReceipt.candidateReceipt.payload = retargetedReceipt.candidateReceipt.payload.replace(value.updater.sha256, 'd'.repeat(64))
    assert.throws(() => latestReceiptBindsInstaller(retargetedReceipt, { version, url: value.updater.url, sha256: value.updater.sha256 }), /different installer bytes/)

    const retargetedPlatform = structuredClone(value.latest)
    retargetedPlatform.platforms['windows-x86_64-nsis'].url = 'https://attacker.invalid/Sesame.exe'
    assert.throws(() => latestReceiptBindsInstaller(retargetedPlatform, { version, url: value.updater.url, sha256: value.updater.sha256 }), /platform URL/)
  } finally {
    await rm(value.evidence.root, { recursive: true, force: true })
    await rm(value.publicRoot, { recursive: true, force: true })
  }
})

test('a server success followed by a client timeout replays as accepted, while conflicts stay named', () => {
  assert.deepEqual(interpretCandidateSubmission(201, '{"release":{"id":"r1"}}'), { outcome: 'accepted' })
  assert.deepEqual(interpretCandidateSubmission(201, ''), { outcome: 'accepted' })
  const conflict = interpretCandidateSubmission(409, '{"error":"release_candidate_conflict"}')
  assert.equal(conflict.outcome, 'conflict')
  assert.match(conflict.message, /different signed evidence/)
  assert.equal(interpretCandidateSubmission(502, 'bad gateway').outcome, 'retryable')
  assert.equal(interpretCandidateSubmission(400, 'invalid').outcome, 'rejected')
})

test('the public evidence directory stays free of the installer and its signature', async () => {
  const value = await publishFixture()
  try {
    const names = await readdir(value.publicRoot)
    assert.ok(!names.includes(value.evidence.files.artifact))
    assert.ok(!names.includes(value.evidence.files.updaterSignature))
  } finally {
    await rm(value.evidence.root, { recursive: true, force: true })
    await rm(value.publicRoot, { recursive: true, force: true })
  }
})
