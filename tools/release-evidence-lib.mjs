import { createHash } from 'node:crypto'
import { readFile, stat } from 'node:fs/promises'
import path from 'node:path'

export const SIGSTORE_ISSUER = 'https://token.actions.githubusercontent.com'
export const RELEASE_REPOSITORY = 'usesesame/sesame-desktop'
export const RELEASE_WORKFLOW = '.github/workflows/release-early-access.yml'

const sha256Pattern = /^[0-9a-f]{64}$/
const versionPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/
const architectureSet = new Set(['x86_64', 'aarch64'])
const channelSet = new Set(['owner', 'beta'])

export const sha256 = (value) => createHash('sha256').update(value).digest('hex')
export const fileSha256 = async (file) => sha256(await readFile(file))

export function stableJSON(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(stableJSON).join(',')}]`
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJSON(value[key])}`).join(',')}}`
}

export function releaseIdentity(repository, workflow, ref) {
  return `https://github.com/${repository}/${workflow}@${ref}`
}

export function assertSafeReleaseFilename(value, label = 'filename') {
  if (typeof value !== 'string' || value.length < 1 || value.length > 180 || path.basename(value) !== value || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value)) {
    throw new Error(`${label} must be a plain release filename.`)
  }
  return value
}

export function validateReleaseManifest(manifest) {
  if (manifest?.schemaVersion !== 1 || manifest.product !== 'Sesame' || manifest.releaseKind !== 'unsigned-windows-early-access') {
    throw new Error('Release manifest identity is invalid.')
  }
  if (!versionPattern.test(manifest.version) || !architectureSet.has(manifest.architecture) || !channelSet.has(manifest.channel)) {
    throw new Error('Release manifest version, architecture, or channel is invalid.')
  }
  const expectedRef = `refs/tags/v${manifest.version}`
  if (manifest.source?.repository !== RELEASE_REPOSITORY || manifest.source?.workflow !== RELEASE_WORKFLOW || manifest.source?.ref !== expectedRef || !/^[0-9a-f]{40}$/.test(manifest.source?.commit ?? '')) {
    throw new Error('Release manifest is not bound to the protected Sesame tag workflow.')
  }
  const expectedIdentity = releaseIdentity(RELEASE_REPOSITORY, RELEASE_WORKFLOW, expectedRef)
  if (manifest.sigstore?.issuer !== SIGSTORE_ISSUER || manifest.sigstore?.certificateIdentity !== expectedIdentity || manifest.sigstore?.transparencyLogRequired !== true) {
    throw new Error('Release manifest Sigstore policy is invalid.')
  }
  if (manifest.windowsTrust?.authenticodeVerified !== false || manifest.windowsTrust?.smartScreenReputationPromised !== false || manifest.windowsTrust?.label !== 'Unsigned Windows early-access build') {
    throw new Error('Release manifest does not disclose the unsigned Windows trust state.')
  }
  for (const [label, item] of Object.entries({ artifact: manifest.artifact, updaterSignature: manifest.updaterSignature, sbom: manifest.sbom })) {
    assertSafeReleaseFilename(item?.filename, `${label} filename`)
    if (!sha256Pattern.test(item?.sha256 ?? '') || !Number.isSafeInteger(item?.bytes) || item.bytes <= 0) {
      throw new Error(`${label} digest or byte count is invalid.`)
    }
  }
  if (typeof manifest.updaterSignature.signingKeyId !== 'string' || manifest.updaterSignature.signingKeyId.length < 1 || manifest.updaterSignature.signingKeyId.length > 120) {
    throw new Error('Updater signing key identity is invalid.')
  }
  let releaseNotes
  try {
    releaseNotes = new URL(manifest.releaseNotesUrl)
  } catch {
    throw new Error('Release notes URL is invalid.')
  }
  if (releaseNotes.protocol !== 'https:' || releaseNotes.username || releaseNotes.password || releaseNotes.hash) {
    throw new Error('Release notes URL must be credential-free HTTPS without a fragment.')
  }
  if (typeof manifest.supportedWindows !== 'string' || manifest.supportedWindows.length < 1 || manifest.supportedWindows.length > 200 || /[\r\n]/.test(manifest.supportedWindows)) {
    throw new Error('Supported Windows disclosure is invalid.')
  }
  return manifest
}

export function validateSigstoreEvidence(evidence, manifest) {
  validateReleaseManifest(manifest)
  if (evidence?.schemaVersion !== 1 || evidence.verified !== true || evidence.transparencyLogVerified !== true) {
    throw new Error('Sigstore evidence is not a verified release record.')
  }
  if (evidence.issuer !== manifest.sigstore.issuer || evidence.certificateIdentity !== manifest.sigstore.certificateIdentity || evidence.repository !== manifest.source.repository || evidence.workflow !== manifest.source.workflow || evidence.ref !== manifest.source.ref || evidence.sourceCommit !== manifest.source.commit) {
    throw new Error('Sigstore evidence identity does not match the release manifest.')
  }
  for (const value of [evidence.artifactSha256, evidence.manifestSha256, evidence.artifactBundleSha256, evidence.manifestBundleSha256]) {
    if (!sha256Pattern.test(value ?? '')) throw new Error('Sigstore evidence contains an invalid digest.')
  }
  if (evidence.artifactSha256 !== manifest.artifact.sha256) {
    throw new Error('Sigstore evidence describes different installer bytes.')
  }
  return evidence
}

export async function validateEvidenceDirectory(directory, manifestFilename) {
  const root = path.resolve(directory)
  assertSafeReleaseFilename(manifestFilename, 'manifest filename')
  const manifestPath = path.join(root, manifestFilename)
  const manifestBytes = await readFile(manifestPath)
  const manifest = validateReleaseManifest(JSON.parse(manifestBytes.toString('utf8')))
  const sigstoreEvidencePath = path.join(root, 'sigstore-evidence.json')
  const evidence = validateSigstoreEvidence(JSON.parse(await readFile(sigstoreEvidencePath, 'utf8')), manifest)
  const paths = {
    artifact: path.join(root, manifest.artifact.filename),
    updaterSignature: path.join(root, manifest.updaterSignature.filename),
    sbom: path.join(root, manifest.sbom.filename),
    artifactBundle: path.join(root, `${manifest.artifact.filename}.sigstore.json`),
    manifestBundle: path.join(root, `${manifestFilename}.sigstore.json`),
    manifest: manifestPath,
  }
  const expected = {
    artifact: manifest.artifact,
    updaterSignature: manifest.updaterSignature,
    sbom: manifest.sbom,
  }
  for (const key of Object.keys(expected)) {
    const size = (await stat(paths[key])).size
    const digest = await fileSha256(paths[key])
    if (size !== expected[key].bytes || digest !== expected[key].sha256) throw new Error(`${key} does not match the signed release manifest.`)
  }
  if (await fileSha256(paths.manifest) !== evidence.manifestSha256 || await fileSha256(paths.artifactBundle) !== evidence.artifactBundleSha256 || await fileSha256(paths.manifestBundle) !== evidence.manifestBundleSha256) {
    throw new Error('A manifest or Sigstore bundle was substituted after verification.')
  }
  return { evidence, manifest, paths }
}
