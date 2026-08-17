import { createHash, createPublicKey, verify } from 'node:crypto'
import { readFile, writeFile } from 'node:fs/promises'
import { basename, resolve } from 'node:path'

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
const artifact = candidate?.artifact
const lineValue = (value) => typeof value === 'string' && value !== '' && !value.includes('\n') && !value.includes('\r')
if (
  candidate?.schemaVersion !== 2 || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(candidate.version) ||
  !lineValue(candidate.channel) ||
  candidate.platform !== 'windows' || !['x86_64', 'aarch64'].includes(candidate.architecture) ||
  !lineValue(candidate.supportedWindows) || !lineValue(candidate.releaseNotesURL) ||
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
  throw new Error('The candidate is not a complete schema-v2 Windows updater record.')
}
try {
  const releaseNotes = new URL(candidate.releaseNotesURL)
  if (releaseNotes.protocol !== 'https:' || releaseNotes.username || releaseNotes.password || releaseNotes.hash) throw new Error()
} catch {
  throw new Error('The candidate release-notes URL is not safe for a public updater manifest.')
}

const objectFilename = basename(artifact.objectKey)
const publicFilename = decodeURIComponent(basename(artifactURL.pathname))
if (!objectFilename || publicFilename !== objectFilename) {
  throw new Error('The public update URL must name the exact candidate artifact filename.')
}

const stableJSON = (value) => {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(stableJSON).join(',')}]`
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJSON(value[key])}`).join(',')}}`
}
const evidenceDigest = (value) => value === undefined
  ? ''
  : createHash('sha256').update(stableJSON(value)).digest('base64url')
const sigstoreEvidenceDigest = evidenceDigest(artifact.sigstoreEvidence)
const authenticodeEvidenceDigest = evidenceDigest(artifact.authenticodeEvidence)
if (!sigstoreEvidenceDigest || (artifact.authenticodeVerified && !authenticodeEvidenceDigest)) {
  throw new Error('The candidate lacks the evidence needed to reconstruct its signed receipt.')
}

const candidatePayload = [
  'sesame-release-candidate-v2', candidate.version, candidate.channel, candidate.platform,
  candidate.architecture, candidate.supportedWindows, candidate.releaseNotesURL, artifact.objectKey,
  artifact.sha256, String(artifact.bytes), artifact.updaterSignature, artifact.updaterSigningKeyId,
  artifact.distributionClass, String(artifact.sigstoreVerified), artifact.sigstoreIssuer,
  artifact.sigstoreIdentity, artifact.sigstoreBundleSha256, sigstoreEvidenceDigest,
  String(artifact.authenticodeVerified), artifact.authenticodeSubject ?? '',
  artifact.authenticodeThumbprint ?? '', authenticodeEvidenceDigest,
].join('\n')

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

const target = `windows-${candidate.architecture}-nsis`
const manifest = {
  version: candidate.version,
  notes: `Verification and release notes: ${candidate.releaseNotesURL}`,
  platforms: {
    [target]: {
      url: artifactURL.toString(),
      signature: artifact.updaterSignature,
    },
  },
  candidateReceipt: {
    payload: candidatePayload,
    signingKeyId: candidate.candidateSigningKeyId,
    signature: candidate.candidateSignature,
  },
}

await writeFile(resolve(outputPath), `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
console.log(`Created static updater manifest: ${resolve(outputPath)}`)
