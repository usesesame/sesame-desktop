import { createPrivateKey, sign } from 'node:crypto'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { prepareReleaseSet, releaseSetSigningPayload } from './release-set.mjs'
import { validateLinuxEvidenceDirectory } from './linux-release-evidence.mjs'

export function buildLinuxCandidate({ manifest, evidence, signingKey, signingKeyId, assetBase, objectKeyPrefix }) {
  const validHTTPS = (value) => {
    try {
      const url = new URL(value)
      return url.protocol === 'https:' && url.hostname !== '' && url.username === '' && url.password === '' && url.hash === '' && url.search === ''
    } catch {
      return false
    }
  }
  const validPrefix = (value) => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}$/.test(value) && !value.includes('//') && !value.split('/').some((part) => part === '.' || part === '..')
  if (!signingKeyId || !signingKey) throw new Error('The candidate signing key and ID are required.')
  if (!validHTTPS(assetBase?.replace(/\/$/, ''))) throw new Error('The HTTPS release asset base URL is required.')
  if (!validPrefix(objectKeyPrefix?.replace(/\/$/, ''))) throw new Error('The object key prefix must be an opaque private-storage key prefix, not a URL.')

  const artifacts = manifest.artifacts.map((artifact) => {
    const sigstore = evidence.artifacts.find((entry) => entry.filename === artifact.filename)
    return {
      format: artifact.format,
      architecture: manifest.architecture,
      url: `${assetBase.replace(/\/$/, '')}/${artifact.filename}`,
      objectKey: `${objectKeyPrefix.replace(/\/$/, '')}/${artifact.filename}`,
      sha256: artifact.sha256,
      bytes: artifact.bytes,
      updaterCapable: false,
      distributionClass: 'early_access',
      sigstoreVerified: true,
      sigstoreIssuer: evidence.issuer,
      sigstoreIdentity: evidence.certificateIdentity,
      sigstoreBundleSha256: sigstore.bundleSha256,
      sigstoreEvidence: {
        schemaVersion: 1,
        verified: true,
        transparencyLogVerified: true,
        issuer: evidence.issuer,
        certificateIdentity: evidence.certificateIdentity,
        repository: evidence.repository,
        workflow: evidence.workflow,
        ref: evidence.ref,
        artifactSha256: artifact.sha256,
        artifactBundleSha256: sigstore.bundleSha256,
      },
      authenticodeVerified: false,
    }
  })
  const candidate = prepareReleaseSet({
    version: manifest.version,
    channel: manifest.channel,
    platform: 'linux',
    architecture: manifest.architecture,
    releaseNotesUrl: manifest.releaseNotesUrl,
    artifacts,
  })
  const candidateSeed = Buffer.from(signingKey, 'base64url')
  if (candidateSeed.length !== 32) throw new Error('SESAME_RELEASE_CANDIDATE_SIGNING_KEY must be a base64url 32-byte Ed25519 seed.')
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), candidateSeed])
  const privateKey = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' })
  candidate.candidateSigningKeyId = signingKeyId
  candidate.candidateSignature = sign(null, Buffer.from(releaseSetSigningPayload(candidate)), privateKey).toString('base64url')
  return candidate
}

const [directoryInput, manifestFilename] = process.argv.slice(2)
const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
if (invokedDirectly) {
  if (!directoryInput || !manifestFilename) {
    throw new Error('Usage: node tools/create-linux-release-candidate.mjs <handoff-directory> <manifest-filename>')
  }
  const { manifest, evidence } = await validateLinuxEvidenceDirectory(path.resolve(directoryInput), manifestFilename)
  const candidate = buildLinuxCandidate({
    manifest,
    evidence,
    signingKey: process.env.SESAME_RELEASE_CANDIDATE_SIGNING_KEY,
    signingKeyId: process.env.SESAME_RELEASE_CANDIDATE_SIGNING_KEY_ID,
    assetBase: process.env.SESAME_PUBLIC_RELEASE_ASSET_BASE,
    objectKeyPrefix: process.env.SESAME_RELEASE_ARTIFACT_OBJECT_KEY_PREFIX,
  })
  const workspace = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
  const outputDirectory = path.join(workspace, 'release-artifacts')
  await mkdir(outputDirectory, { recursive: true })
  const outputPath = path.join(outputDirectory, `sesame-${candidate.version}-linux-${candidate.architecture}.candidate.json`)
  await writeFile(outputPath, `${JSON.stringify(candidate, null, 2)}\n`, 'utf8')
  process.stdout.write(`Created verified Linux candidate: ${outputPath}\n`)
}
