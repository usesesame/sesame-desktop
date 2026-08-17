import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { promisify } from 'node:util'
import test from 'node:test'

const run = promisify(execFile)
const script = resolve('tools/create-static-update-manifest.mjs')

function fictionalCandidate() {
  const candidate = {
    schemaVersion: 2,
    version: '1.2.3',
    channel: 'production',
    platform: 'windows',
    architecture: 'x86_64',
    supportedWindows: 'Windows 10,Windows 11',
    releaseNotesURL: 'https://releases.example.test/v1.2.3',
    artifact: {
      objectKey: 'windows/v1.2.3/Sesame_1.2.3_x64-setup.exe',
      sha256: 'a'.repeat(64),
      bytes: 42,
      updaterSignature: 'A'.repeat(64),
      updaterSigningKeyId: 'updater-1',
      distributionClass: 'production',
      sigstoreVerified: true,
      sigstoreIssuer: 'https://token.actions.githubusercontent.com',
      sigstoreIdentity: 'https://github.com/usesesame/Sesame/.github/workflows/release.yml@refs/tags/v1.2.3',
      sigstoreBundleSha256: 'b'.repeat(64),
      sigstoreEvidence: { schemaVersion: 1, verified: true, artifactSha256: 'a'.repeat(64) },
      authenticodeVerified: true,
      authenticodeSubject: 'CN=Sesame Test Publisher',
      authenticodeThumbprint: 'F'.repeat(40),
      authenticodeEvidence: { verified: true, subject: 'CN=Sesame Test Publisher' },
    },
    candidateSigningKeyId: 'candidate-1',
    candidateSignature: '',
  }
  const stableJSON = (value) => {
    if (value === null || typeof value !== 'object') return JSON.stringify(value)
    if (Array.isArray(value)) return `[${value.map(stableJSON).join(',')}]`
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJSON(value[key])}`).join(',')}}`
  }
  const digest = (value) => createHash('sha256').update(stableJSON(value)).digest('base64url')
  const artifact = candidate.artifact
  const payload = [
    'sesame-release-candidate-v2', candidate.version, candidate.channel, candidate.platform,
    candidate.architecture, candidate.supportedWindows, candidate.releaseNotesURL, artifact.objectKey,
    artifact.sha256, String(artifact.bytes), artifact.updaterSignature, artifact.updaterSigningKeyId,
    artifact.distributionClass, String(artifact.sigstoreVerified), artifact.sigstoreIssuer,
    artifact.sigstoreIdentity, artifact.sigstoreBundleSha256, digest(artifact.sigstoreEvidence),
    String(artifact.authenticodeVerified), artifact.authenticodeSubject,
    artifact.authenticodeThumbprint, digest(artifact.authenticodeEvidence),
  ].join('\n')
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  candidate.candidateSignature = sign(null, Buffer.from(payload), privateKey).toString('base64url')
  const spki = publicKey.export({ format: 'der', type: 'spki' })
  return { candidate, candidatePublicKey: spki.subarray(spki.length - 32).toString('base64url') }
}

test('static updater manifest carries the public artifact and exact signed receipt payload', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sesame-update-manifest-'))
  try {
    const candidatePath = join(directory, 'candidate.json')
    const outputPath = join(directory, 'latest.json')
    const { candidate, candidatePublicKey } = fictionalCandidate()
    await writeFile(candidatePath, JSON.stringify(candidate))
    await run(process.execPath, [script, candidatePath, outputPath], {
      env: {
        ...process.env,
        SESAME_PUBLIC_UPDATE_ARTIFACT_URL: 'https://github.com/usesesame/sesame-desktop/releases/download/v1.2.3/Sesame_1.2.3_x64-setup.exe',
        SESAME_RELEASE_CANDIDATE_PUBLIC_KEY: candidatePublicKey,
      },
    })
    const manifest = JSON.parse(await readFile(outputPath, 'utf8'))
    assert.equal(manifest.version, '1.2.3')
    assert.deepEqual(Object.keys(manifest.platforms), ['windows-x86_64-nsis'])
    assert.equal(manifest.platforms['windows-x86_64-nsis'].signature, 'A'.repeat(64))
    assert.equal(manifest.candidateReceipt.signingKeyId, 'candidate-1')
    assert.equal(manifest.candidateReceipt.payload.split('\n').length, 22)
    assert.equal(manifest.candidateReceipt.payload.split('\n')[8], 'a'.repeat(64))
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
})

test('static updater manifest refuses insecure and artifact-mismatched public URLs', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sesame-update-manifest-'))
  try {
    const candidatePath = join(directory, 'candidate.json')
    const outputPath = join(directory, 'latest.json')
    const { candidate } = fictionalCandidate()
    await writeFile(candidatePath, JSON.stringify(candidate))
    for (const artifactURL of [
      'http://github.example.test/Sesame_1.2.3_x64-setup.exe',
      'https://github.example.test/other.exe',
      'https://github.example.test/Sesame_1.2.3_x64-setup.exe?token=secret',
    ]) {
      await assert.rejects(run(process.execPath, [script, candidatePath, outputPath], {
        env: { ...process.env, SESAME_PUBLIC_UPDATE_ARTIFACT_URL: artifactURL },
      }))
    }
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
})
