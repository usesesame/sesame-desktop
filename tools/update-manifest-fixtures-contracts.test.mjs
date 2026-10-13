import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { createPrivateKey, createPublicKey, sign } from 'node:crypto'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { promisify } from 'node:util'
import test from 'node:test'

import { RELEASE_REPOSITORY, RELEASE_WORKFLOW, SIGSTORE_ISSUER, releaseIdentity } from './release-evidence-lib.mjs'
import { prepareReleaseSet, releaseSetSigningPayload, updateReceiptV3 } from './release-set.mjs'

const run = promisify(execFile)
const script = resolve('tools/create-static-update-manifest.mjs')
const fixtureDirectory = resolve('src-tauri/tests/fixtures/update-manifests')
const regenerate = process.env.SESAME_REGENERATE_UPDATE_FIXTURES === '1'
const version = '1.2.3'
const ref = `refs/tags/v${version}`
const artifactURL = `https://downloads.example.test/v${version}/Sesame_${version}_x64-setup.exe`
const candidateKeyId = 'fictional-candidate-key'
const sigstoreIdentity = releaseIdentity(RELEASE_REPOSITORY, RELEASE_WORKFLOW, ref)

const privateKey = createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 7)]),
  format: 'der',
  type: 'pkcs8',
})
const publicSPKI = createPublicKey(privateKey).export({ format: 'der', type: 'spki' })
const candidatePublicKey = publicSPKI.subarray(publicSPKI.length - 32).toString('base64url')

function fictionalCandidate(distributionClass) {
  const production = distributionClass === 'production'
  const candidate = prepareReleaseSet({
    version,
    channel: 'beta',
    platform: 'windows',
    architecture: 'x86_64',
    supportedWindows: 'Windows 10,Windows 11',
    releaseNotesUrl: `https://downloads.example.test/v${version}/notes`,
    artifacts: [{
      format: 'nsis',
      architecture: 'x86_64',
      url: artifactURL,
      objectKey: `windows/v${version}/Sesame_${version}_x64-setup.exe`,
      sha256: 'a'.repeat(64),
      bytes: 42,
      updaterCapable: true,
      updaterSignature: 'A'.repeat(64),
      updaterSigningKeyId: 'fictional-updater-key',
      distributionClass,
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
        artifactSha256: 'a'.repeat(64),
        artifactBundleSha256: 'b'.repeat(64),
      },
      authenticodeVerified: production,
      ...(production ? {
        authenticodeEvidence: { schemaVersion: 1, verified: true, subject: 'CN=Fictional Publisher', thumbprint: 'c'.repeat(40) },
        authenticodeSubject: 'CN=Fictional Publisher',
        authenticodeThumbprint: 'c'.repeat(40),
      } : {}),
    }],
  })
  candidate.candidateSigningKeyId = candidateKeyId
  candidate.candidateSignature = sign(null, Buffer.from(releaseSetSigningPayload(candidate)), privateKey).toString('base64url')
  return candidate
}

async function createManifest(distributionClass, receiptLayout) {
  const directory = await mkdtemp(join(tmpdir(), 'sesame-update-fixture-'))
  try {
    const candidate = fictionalCandidate(distributionClass)
    const candidatePath = join(directory, 'candidate.json')
    const outputPath = join(directory, 'latest.json')
    const env = {
      ...process.env,
      SESAME_PUBLIC_UPDATE_ARTIFACT_URL: artifactURL,
      SESAME_RELEASE_CANDIDATE_PUBLIC_KEY: candidatePublicKey,
    }
    delete env.SESAME_UPDATE_RECEIPT_V3_FILE
    await writeFile(candidatePath, JSON.stringify(candidate))
    if (receiptLayout === 'v3') {
      const receiptPath = join(directory, 'update-receipt.json')
      const payload = updateReceiptV3(candidate)
      await writeFile(receiptPath, JSON.stringify({
        payload,
        signingKeyId: candidateKeyId,
        signature: sign(null, Buffer.from(payload), privateKey).toString('base64url'),
      }))
      env.SESAME_UPDATE_RECEIPT_V3_FILE = receiptPath
    }
    await run(process.execPath, [script, candidatePath, outputPath], { env })
    return readFile(outputPath, 'utf8')
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}

const fixtures = [
  { file: 'release-set-early-access.latest.json', distributionClass: 'early_access', receiptLayout: 'release-set', header: 'sesame-release-set-candidate-v1', lines: 17 },
  { file: 'v3-early-access.latest.json', distributionClass: 'early_access', receiptLayout: 'v3', header: 'sesame-release-candidate-v3', lines: 23 },
  { file: 'v3-production.latest.json', distributionClass: 'production', receiptLayout: 'v3', header: 'sesame-release-candidate-v3', lines: 23 },
]

const receiptKeyFile = 'receipt-key.json'
const receiptKeyContent = `${JSON.stringify({ publicKey: candidatePublicKey, keyId: candidateKeyId }, null, 2)}\n`

async function assertFixture(file, expected) {
  if (regenerate) {
    await writeFile(join(fixtureDirectory, file), expected, 'utf8')
    return
  }
  const committed = await readFile(join(fixtureDirectory, file), 'utf8')
  assert.equal(committed, expected, `${file} differs from the release tool output. Run with SESAME_REGENERATE_UPDATE_FIXTURES=1 after a deliberate format change.`)
}

test('the committed receipt key is the fictional fixture key', async () => {
  await assertFixture(receiptKeyFile, receiptKeyContent)
})

for (const fixture of fixtures) {
  test(`${fixture.file} is the exact output of the release tool`, async () => {
    const generated = await createManifest(fixture.distributionClass, fixture.receiptLayout)
    await assertFixture(fixture.file, generated)
    const manifest = JSON.parse(generated)
    const claims = manifest.candidateReceipt.payload.split('\n')
    assert.equal(claims[0], fixture.header)
    assert.equal(claims.length, fixture.lines)
    assert.equal(manifest.url, artifactURL)
    assert.equal(manifest.platforms['windows-x86_64-nsis'].url, artifactURL)
    assert.equal(manifest.candidateReceipt.signingKeyId, candidateKeyId)
    assert.equal(manifest.version, version)
    if (fixture.receiptLayout === 'v3') {
      assert.equal(claims[13], fixture.distributionClass)
      assert.equal(claims[19], String(fixture.distributionClass === 'production'))
    }
  })
}
