import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { generateKeyPairSync, sign } from 'node:crypto'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { promisify } from 'node:util'
import test from 'node:test'

import { RELEASE_REPOSITORY, RELEASE_WORKFLOW, SIGSTORE_ISSUER, releaseIdentity } from './release-evidence-lib.mjs'
import { prepareReleaseSet, releaseSetSigningPayload } from './release-set.mjs'

const run = promisify(execFile)
const script = resolve('tools/create-static-update-manifest.mjs')
const version = '1.2.3'
const ref = `refs/tags/v${version}`
const sigstoreIdentity = releaseIdentity(RELEASE_REPOSITORY, RELEASE_WORKFLOW, ref)

function fictionalArtifact(format, character, overrides = {}) {
  const updaterCapable = format === 'nsis'
  const sha256 = character.repeat(64)
  return {
    format,
    architecture: 'x86_64',
    url: `https://releases.example.test/v${version}/Sesame.${format}`,
    objectKey: `packages/v${version}/Sesame.${format}`,
    sha256,
    bytes: 42,
    updaterCapable,
    updaterSignature: updaterCapable ? 'A'.repeat(64) : '',
    updaterSigningKeyId: updaterCapable ? 'updater-1' : '',
    distributionClass: 'early_access',
    sigstoreVerified: true,
    sigstoreIssuer: SIGSTORE_ISSUER,
    sigstoreIdentity,
    sigstoreBundleSha256: 'b'.repeat(64),
    sigstoreEvidence: {
      schemaVersion: 1,
      verified: true,
      transparencyLogVerified: true,
      issuer: SIGSTORE_ISSUER,
      certificateIdentity: sigstoreIdentity,
      repository: RELEASE_REPOSITORY,
      workflow: RELEASE_WORKFLOW,
      ref,
      artifactSha256: sha256,
      artifactBundleSha256: 'b'.repeat(64),
    },
    authenticodeVerified: false,
    ...overrides,
  }
}

function signCandidate(candidate) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  candidate.candidateSigningKeyId = 'candidate-1'
  candidate.candidateSignature = sign(null, Buffer.from(releaseSetSigningPayload(candidate)), privateKey).toString('base64url')
  const spki = publicKey.export({ format: 'der', type: 'spki' })
  return { candidate, candidatePublicKey: spki.subarray(spki.length - 32).toString('base64url') }
}

function fictionalWindowsCandidate() {
  return signCandidate(prepareReleaseSet({
    version,
    channel: 'beta',
    platform: 'windows',
    architecture: 'x86_64',
    supportedWindows: 'Windows 10,Windows 11',
    releaseNotesUrl: `https://releases.example.test/v${version}`,
    artifacts: [fictionalArtifact('nsis', 'a', {
      url: `https://releases.example.test/v${version}/Sesame_${version}_x64-setup.exe`,
      objectKey: `windows/v${version}/Sesame_${version}_x64-setup.exe`,
    })],
  }))
}

function fictionalLinuxCandidate() {
  return signCandidate(prepareReleaseSet({
    version,
    channel: 'beta',
    platform: 'linux',
    architecture: 'x86_64',
    supportedWindows: '',
    releaseNotesUrl: `https://releases.example.test/v${version}`,
    artifacts: [
      fictionalArtifact('appimage', 'a'),
      fictionalArtifact('deb', 'd'),
      fictionalArtifact('rpm', 'e'),
    ],
  }))
}

test('static updater manifest carries the updater-capable package and exact set receipt', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sesame-update-manifest-'))
  try {
    const candidatePath = join(directory, 'candidate.json')
    const outputPath = join(directory, 'latest.json')
    const { candidate, candidatePublicKey } = fictionalWindowsCandidate()
    await writeFile(candidatePath, JSON.stringify(candidate))
    await run(process.execPath, [script, candidatePath, outputPath], {
      env: {
        ...process.env,
        SESAME_PUBLIC_UPDATE_ARTIFACT_URL: `https://github.com/usesesame/sesame-desktop/releases/download/v${version}/Sesame_${version}_x64-setup.exe`,
        SESAME_RELEASE_CANDIDATE_PUBLIC_KEY: candidatePublicKey,
      },
    })
    const manifest = JSON.parse(await readFile(outputPath, 'utf8'))
    assert.equal(manifest.version, version)
    assert.deepEqual(Object.keys(manifest.platforms), ['windows-x86_64-nsis'])
    assert.equal(manifest.platforms['windows-x86_64-nsis'].signature, 'A'.repeat(64))
    assert.equal(manifest.candidateReceipt.signingKeyId, 'candidate-1')
    assert.equal(manifest.candidateReceipt.payload, releaseSetSigningPayload(candidate))
    const claims = manifest.candidateReceipt.payload.split('\n')
    assert.equal(claims[11], candidate.artifacts[0].url)
    assert.equal(claims[13], candidate.artifacts[0].sha256)
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
})

test('static updater manifest refuses a release set with no updater-capable package', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sesame-update-manifest-'))
  try {
    const candidatePath = join(directory, 'candidate.json')
    const outputPath = join(directory, 'latest.json')
    const { candidate } = fictionalLinuxCandidate()
    await writeFile(candidatePath, JSON.stringify(candidate))
    await assert.rejects(run(process.execPath, [script, candidatePath, outputPath], {
      env: { ...process.env, SESAME_PUBLIC_UPDATE_ARTIFACT_URL: 'https://releases.example.test/Sesame.AppImage' },
    }), /updater-capable desktop release set/)
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
})

test('static updater manifest refuses insecure and package-mismatched public URLs', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sesame-update-manifest-'))
  try {
    const candidatePath = join(directory, 'candidate.json')
    const outputPath = join(directory, 'latest.json')
    const { candidate } = fictionalWindowsCandidate()
    await writeFile(candidatePath, JSON.stringify(candidate))
    for (const artifactURL of [
      `http://github.example.test/Sesame_${version}_x64-setup.exe`,
      'https://github.example.test/other.exe',
      `https://github.example.test/Sesame_${version}_x64-setup.exe?token=fictional`,
    ]) {
      await assert.rejects(run(process.execPath, [script, candidatePath, outputPath], {
        env: { ...process.env, SESAME_PUBLIC_UPDATE_ARTIFACT_URL: artifactURL },
      }))
    }
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
})
