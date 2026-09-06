import { createPublicKey, verify } from 'node:crypto'
import { readFile, writeFile } from 'node:fs/promises'
import { basename, resolve } from 'node:path'

import { releaseSetSigningPayload, updateReceiptV3, verifyReleaseSet } from './release-set.mjs'

const [candidatePath, outputPath] = process.argv.slice(2)
if (!candidatePath || !outputPath) {
  throw new Error('Usage: node tools/create-static-update-manifest.mjs <candidate.json> <latest.json>')
}

const artifactURLValue = process.env.SESAME_PUBLIC_UPDATE_ARTIFACT_URL
let artifactURL
try {
  artifactURL = new URL(artifactURLValue)
} catch {
  throw new Error('SESAME_PUBLIC_UPDATE_ARTIFACT_URL must be a valid public HTTPS URL.')
}
if (
  artifactURL.protocol !== 'https:' || artifactURL.hostname === '' || artifactURL.username !== '' ||
  artifactURL.password !== '' || artifactURL.search !== '' || artifactURL.hash !== ''
) {
  throw new Error('SESAME_PUBLIC_UPDATE_ARTIFACT_URL must be a credential-free HTTPS URL without a query or fragment.')
}

const candidate = JSON.parse(await readFile(resolve(candidatePath), 'utf8'))
verifyReleaseSet(candidate)
const artifact = candidate.artifacts.find((item) => item.updaterCapable)
const lineValue = (value) => typeof value === 'string' && value !== '' && !value.includes('\n') && !value.includes('\r')
if (
  !artifact || !lineValue(candidate.channel) ||
  !lineValue(artifact?.objectKey) || !lineValue(artifact?.updaterSignature) ||
  artifact.updaterSignature.length < 64 || !/^[0-9a-f]{64}$/.test(artifact.sha256) ||
  !Number.isSafeInteger(artifact.bytes) || artifact.bytes <= 0 ||
  !lineValue(artifact.updaterSigningKeyId) || !['early_access', 'production'].includes(artifact.distributionClass) ||
  artifact.sigstoreVerified !== true || !lineValue(artifact.sigstoreIssuer) ||
  !lineValue(artifact.sigstoreIdentity) || !/^[0-9a-f]{64}$/.test(artifact.sigstoreBundleSha256) ||
  typeof artifact.authenticodeVerified !== 'boolean' ||
  (artifact.distributionClass === 'early_access' && artifact.authenticodeVerified) ||
  (artifact.distributionClass === 'production' && !artifact.authenticodeVerified) ||
  (artifact.authenticodeVerified && (!lineValue(artifact.authenticodeSubject) || !lineValue(artifact.authenticodeThumbprint))) ||
  !lineValue(candidate.candidateSigningKeyId) || !lineValue(candidate.candidateSignature) ||
  Buffer.from(candidate.candidateSignature, 'base64url').length !== 64
) {
  throw new Error('The candidate is not a complete updater-capable desktop release set.')
}
try {
  const releaseNotes = new URL(candidate.releaseNotesUrl)
  if (releaseNotes.protocol !== 'https:' || releaseNotes.username || releaseNotes.password || releaseNotes.hash) throw new Error()
} catch {
  throw new Error('The candidate release-notes URL is not safe for a public updater manifest.')
}

const objectFilename = basename(artifact.objectKey)
const publicFilename = decodeURIComponent(basename(artifactURL.pathname))
if (!objectFilename || publicFilename !== objectFilename) {
  throw new Error('The public update URL must name the exact candidate artifact filename.')
}

const candidatePayload = releaseSetSigningPayload(candidate)

const candidatePublicKey = process.env.SESAME_RELEASE_CANDIDATE_PUBLIC_KEY?.trim()
if (candidatePublicKey) {
  const rawKey = Buffer.from(candidatePublicKey, 'base64url')
  if (rawKey.length !== 32) {
    throw new Error('SESAME_RELEASE_CANDIDATE_PUBLIC_KEY must be a base64url Ed25519 public key.')
  }
  const publicKey = createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), rawKey]),
    format: 'der',
    type: 'spki',
  })
  if (!verify(null, Buffer.from(candidatePayload), publicKey, Buffer.from(candidate.candidateSignature, 'base64url'))) {
    throw new Error('The candidate signature does not verify over the reconstructed static-manifest receipt.')
  }
}

// The manifest receipt must be verifiable by every released client. Clients
// before 0.2.3 only understand the v3 receipt layout, so the release pipeline
// provides the separately signed v3 receipt and this manifest ships that.
const receiptFile = process.env.SESAME_UPDATE_RECEIPT_V3_FILE?.trim()
let candidateReceipt
if (receiptFile) {
  const receipt = JSON.parse(await readFile(resolve(receiptFile), 'utf8'))
  if (
    typeof receipt?.payload !== 'string' || receipt.payload !== updateReceiptV3(candidate) ||
    receipt.signingKeyId !== candidate.candidateSigningKeyId ||
    typeof receipt.signature !== 'string' || Buffer.from(receipt.signature, 'base64url').length !== 64
  ) {
    throw new Error('The provided update receipt does not describe this release set.')
  }
  if (candidatePublicKey && !verify(
    null,
    Buffer.from(receipt.payload),
    createPublicKey({
      key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(candidatePublicKey, 'base64url')]),
      format: 'der',
      type: 'spki',
    }),
    Buffer.from(receipt.signature, 'base64url'),
  )) {
    throw new Error('The update receipt signature does not verify.')
  }
  candidateReceipt = { payload: receipt.payload, signingKeyId: receipt.signingKeyId, signature: receipt.signature }
} else {
  candidateReceipt = {
    payload: candidatePayload,
    signingKeyId: candidate.candidateSigningKeyId,
    signature: candidate.candidateSignature,
  }
}

const target = `${candidate.platform}-${candidate.architecture}-${artifact.format}`
const manifest = {
  version: candidate.version,
  url: artifactURL.toString(),
  notes: `Verification and release notes: ${candidate.releaseNotesUrl}`,
  platforms: {
    [target]: {
      url: artifactURL.toString(),
      signature: artifact.updaterSignature,
    },
  },
  candidateReceipt,
}

await writeFile(resolve(outputPath), `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
console.log(`Created static updater manifest: ${resolve(outputPath)}`)
