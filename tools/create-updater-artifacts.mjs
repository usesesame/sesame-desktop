import { createHash, createPrivateKey, sign } from 'node:crypto'
import { readFile, writeFile, mkdir } from 'node:fs/promises'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { prepareReleaseSet, releaseSetSigningPayload } from './release-set.mjs'

const [artifactPath, signaturePath, sigstorePath, authenticodePath] = process.argv.slice(2)
if (!artifactPath || !signaturePath || !sigstorePath) {
  throw new Error('Usage: node tools/create-updater-artifacts.mjs <artifact> <tauri-signature> <sigstore-evidence.json> [authenticode-evidence.json]')
}

const artifactObjectKey = process.env.SESAME_RELEASE_ARTIFACT_OBJECT_KEY
const signingKeyID = process.env.SESAME_UPDATER_SIGNING_KEY_ID
const candidateSigningKeyID = process.env.SESAME_RELEASE_CANDIDATE_SIGNING_KEY_ID
const candidateSigningKey = process.env.SESAME_RELEASE_CANDIDATE_SIGNING_KEY
const updaterPublicKey = process.env.SESAME_UPDATER_PUBLIC_KEY
const supportedWindows = process.env.SESAME_SUPPORTED_WINDOWS
const releaseNotesURL = process.env.SESAME_RELEASE_NOTES_URL
const publicArtifactURL = process.env.SESAME_PUBLIC_UPDATE_ARTIFACT_URL
const channel = process.env.SESAME_RELEASE_CHANNEL ?? 'beta'
const architecture = process.env.SESAME_RELEASE_ARCHITECTURE
const validHTTPSURL = (value) => {
  try {
    const url = new URL(value)
    return url.protocol === 'https:' && url.hostname !== '' && url.username === '' && url.password === '' && url.hash === ''
  } catch {
    return false
  }
}
const validObjectKey = (value) => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}$/.test(value) && !value.includes('//') && !value.split('/').some((part) => part === '.' || part === '..')
if (!validObjectKey(artifactObjectKey)) {
  throw new Error('SESAME_RELEASE_ARTIFACT_OBJECT_KEY must be an opaque private-storage object key, not a URL.')
}
if (!signingKeyID || signingKeyID.length > 120) {
  throw new Error('SESAME_UPDATER_SIGNING_KEY_ID is required.')
}
if (!candidateSigningKeyID || !candidateSigningKey || !updaterPublicKey || !supportedWindows || !validHTTPSURL(releaseNotesURL)) {
  throw new Error('The updater public key, candidate signing key and ID, supported Windows versions, and an HTTPS release-notes URL are required.')
}
if (architecture !== 'x86_64' && architecture !== 'aarch64') {
  throw new Error('SESAME_RELEASE_ARCHITECTURE must be x86_64 or aarch64 and must describe the built artifact, not the CI runner.')
}

const run = promisify(execFile)

const workspace = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const packageJSON = JSON.parse(await readFile(path.join(workspace, 'package.json'), 'utf8'))
const [artifact, signature, sigstore, authenticode] = await Promise.all([
  readFile(artifactPath),
  readFile(signaturePath, 'utf8'),
  readFile(sigstorePath, 'utf8').then(JSON.parse),
  authenticodePath ? readFile(authenticodePath, 'utf8').then(JSON.parse) : Promise.resolve(null),
])
const updaterSignature = signature.trim()
if (updaterSignature.length < 64) throw new Error('The Tauri updater signature is missing or malformed.')
if (authenticode !== null && (typeof authenticode !== 'object' || Array.isArray(authenticode))) {
  throw new Error('Authenticode evidence must be a JSON object produced by the signing job.')
}

const authenticodeVerified = authenticode?.verified === true
const authenticodeSubject = typeof authenticode?.subject === 'string' ? authenticode.subject : ''
const authenticodeThumbprint = typeof authenticode?.thumbprint === 'string' ? authenticode.thumbprint : ''
if (authenticodeVerified && (!authenticodeSubject || !authenticodeThumbprint)) {
  throw new Error('Verified Authenticode evidence must include both subject and thumbprint.')
}
const artifactSHA256 = createHash('sha256').update(artifact).digest('hex')
if (
  sigstore === null || typeof sigstore !== 'object' || Array.isArray(sigstore) ||
  sigstore.schemaVersion !== 1 || sigstore.verified !== true || sigstore.transparencyLogVerified !== true ||
  sigstore.artifactSha256 !== artifactSHA256 || typeof sigstore.issuer !== 'string' || !sigstore.issuer ||
  typeof sigstore.certificateIdentity !== 'string' || !sigstore.certificateIdentity ||
  typeof sigstore.artifactBundleSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(sigstore.artifactBundleSha256)
) {
  throw new Error('Sigstore evidence must be a verified, transparency-logged record for the exact artifact.')
}
const distributionClass = authenticodeVerified ? 'production' : 'early_access'

// Minisign-verify the exact artifact before the CI key signs a receipt, so a receipt can never turn a merely present .sig file into trusted evidence.
await run('cargo', ['run', '--quiet', '--manifest-path', 'src-tauri/Cargo.toml', '--bin', 'verify-updater-artifact', '--', artifactPath, signaturePath], {
  cwd: workspace,
  env: { ...process.env, SESAME_UPDATER_PUBLIC_KEY: updaterPublicKey },
})

if (!validHTTPSURL(publicArtifactURL)) {
  throw new Error('SESAME_PUBLIC_UPDATE_ARTIFACT_URL must be the HTTPS URL the installer is downloaded from.')
}
const candidate = prepareReleaseSet({
  version: packageJSON.version,
  channel,
  platform: 'windows',
  architecture,
  supportedWindows,
  releaseNotesUrl: releaseNotesURL,
  artifacts: [{
    format: 'nsis',
    architecture,
    url: publicArtifactURL,
    objectKey: artifactObjectKey,
    sha256: artifactSHA256,
    bytes: artifact.length,
    updaterCapable: true,
    updaterSignature,
    updaterSigningKeyId: signingKeyID,
    distributionClass,
    sigstoreEvidence: sigstore,
    sigstoreVerified: true,
    sigstoreIssuer: sigstore.issuer,
    sigstoreIdentity: sigstore.certificateIdentity,
    sigstoreBundleSha256: sigstore.artifactBundleSha256,
    // Explicit false so no release path mistakes Sigstore or an updater signature for Windows publisher signing.
    authenticodeVerified,
    ...(authenticode === null ? {} : {
      authenticodeEvidence: authenticode,
      authenticodeSubject,
      authenticodeThumbprint,
    }),
  }],
})
const signingPayload = releaseSetSigningPayload(candidate)
const candidateSeed = Buffer.from(candidateSigningKey, 'base64url')
if (candidateSeed.length !== 32) throw new Error('SESAME_RELEASE_CANDIDATE_SIGNING_KEY must be a base64url 32-byte Ed25519 seed.')
const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), candidateSeed])
candidate.candidateSigningKeyId = candidateSigningKeyID
candidate.candidateSignature = sign(null, Buffer.from(signingPayload), createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' })).toString('base64url')
const outputDirectory = path.join(workspace, 'release-artifacts')
await mkdir(outputDirectory, { recursive: true })
const outputPath = path.join(outputDirectory, `sesame-${candidate.version}-${candidate.platform}-${candidate.architecture}.candidate.json`)
await writeFile(outputPath, `${JSON.stringify(candidate, null, 2)}\n`, 'utf8')
console.log(`Created verified-candidate input: ${outputPath}`)
