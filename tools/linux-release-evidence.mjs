import { readFile, stat } from 'node:fs/promises'
import path from 'node:path'

import { LINUX_RELEASE_WORKFLOW, RELEASE_REPOSITORY, SIGSTORE_ISSUER, assertSafeReleaseFilename, fileSha256, releaseIdentity } from './release-evidence-lib.mjs'
import { applicableReleaseFormats } from './release-set.mjs'

export const LINUX_RELEASE_KIND = 'unsigned-linux-early-access'
export { LINUX_RELEASE_WORKFLOW }

const sha256Pattern = /^[0-9a-f]{64}$/
const versionPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/
const architectureSet = new Set(['x86_64', 'aarch64'])
const channelSet = new Set(['owner', 'beta'])

const describeFile = async (file) => ({ sha256: await fileSha256(file), bytes: (await stat(file)).size })

export function validateLinuxReleaseManifest(manifest) {
  if (manifest?.schemaVersion !== 1 || manifest.product !== 'Sesame' || manifest.releaseKind !== LINUX_RELEASE_KIND) {
    throw new Error('Linux release manifest identity is invalid.')
  }
  if (!versionPattern.test(manifest.version) || !architectureSet.has(manifest.architecture) || !channelSet.has(manifest.channel) || manifest.platform !== 'linux') {
    throw new Error('Linux release manifest version, architecture, channel, or platform is invalid.')
  }
  const expectedRef = `refs/tags/v${manifest.version}`
  if (manifest.source?.repository !== RELEASE_REPOSITORY || manifest.source?.workflow !== LINUX_RELEASE_WORKFLOW || manifest.source?.ref !== expectedRef || !/^[0-9a-f]{40}$/.test(manifest.source?.commit ?? '')) {
    throw new Error('Linux release manifest is not bound to the protected Sesame tag workflow.')
  }
  const expectedIdentity = releaseIdentity(RELEASE_REPOSITORY, LINUX_RELEASE_WORKFLOW, expectedRef)
  if (manifest.sigstore?.issuer !== SIGSTORE_ISSUER || manifest.sigstore?.certificateIdentity !== expectedIdentity || manifest.sigstore?.transparencyLogRequired !== true) {
    throw new Error('Linux release manifest Sigstore policy is invalid.')
  }
  const formats = applicableReleaseFormats('linux')
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length !== formats.length || !formats.every((format) => manifest.artifacts.some((artifact) => artifact.format === format))) {
    throw new Error(`Linux release manifest must carry exactly the ${formats.join(', ')} packages.`)
  }
  const names = new Set()
  for (const artifact of manifest.artifacts) {
    assertSafeReleaseFilename(artifact?.filename, `${artifact?.format} filename`)
    if (!sha256Pattern.test(artifact?.sha256 ?? '') || !Number.isSafeInteger(artifact?.bytes) || artifact.bytes <= 0) {
      throw new Error(`${artifact?.format} digest or byte count is invalid.`)
    }
    if (names.has(artifact.filename)) throw new Error(`Linux release manifest repeats ${artifact.filename}.`)
    names.add(artifact.filename)
  }
  for (const [label, file] of Object.entries({ sbom: manifest.sbom, shipped: manifest.linuxLifecycle?.shipped, vault: manifest.linuxLifecycle?.vault })) {
    assertSafeReleaseFilename(file?.filename, `${label} filename`)
    if (!sha256Pattern.test(file?.sha256 ?? '') || !Number.isSafeInteger(file?.bytes) || file.bytes <= 0) {
      throw new Error(`Linux release manifest ${label} record is invalid.`)
    }
  }
  let releaseNotes
  try {
    releaseNotes = new URL(manifest.releaseNotesUrl)
  } catch {
    throw new Error('Linux release notes URL is invalid.')
  }
  if (releaseNotes.protocol !== 'https:' || releaseNotes.username || releaseNotes.password || releaseNotes.hash) {
    throw new Error('Linux release notes URL must be credential-free HTTPS without a fragment.')
  }
  return manifest
}

export function validateLinuxSigstoreEvidence(evidence, manifest) {
  validateLinuxReleaseManifest(manifest)
  if (evidence?.schemaVersion !== 1 || evidence.verified !== true || evidence.transparencyLogVerified !== true) {
    throw new Error('Linux Sigstore evidence is not a verified release record.')
  }
  if (evidence.issuer !== manifest.sigstore.issuer || evidence.certificateIdentity !== manifest.sigstore.certificateIdentity || evidence.repository !== manifest.source.repository || evidence.workflow !== manifest.source.workflow || evidence.ref !== manifest.source.ref || evidence.sourceCommit !== manifest.source.commit) {
    throw new Error('Linux Sigstore evidence identity does not match the release manifest.')
  }
  for (const value of [evidence.manifestSha256, evidence.manifestBundleSha256]) {
    if (!sha256Pattern.test(value ?? '')) throw new Error('Linux Sigstore evidence contains an invalid manifest digest.')
  }
  if (!Array.isArray(evidence.artifacts) || evidence.artifacts.length !== manifest.artifacts.length) {
    throw new Error('Linux Sigstore evidence does not cover every package.')
  }
  for (const artifact of manifest.artifacts) {
    const record = evidence.artifacts.find((entry) => entry.filename === artifact.filename)
    if (!record || record.sha256 !== artifact.sha256 || !sha256Pattern.test(record.bundleSha256 ?? '')) {
      throw new Error(`Linux Sigstore evidence does not verify ${artifact.filename}.`)
    }
  }
  return evidence
}

export async function validateLinuxEvidenceDirectory(directory, manifestFilename) {
  const root = path.resolve(directory)
  assertSafeReleaseFilename(manifestFilename, 'Linux manifest filename')
  const manifestPath = path.join(root, manifestFilename)
  const manifest = validateLinuxReleaseManifest(JSON.parse(await readFile(manifestPath, 'utf8')))
  const evidencePath = path.join(root, 'linux-sigstore-evidence.json')
  const evidence = validateLinuxSigstoreEvidence(JSON.parse(await readFile(evidencePath, 'utf8')), manifest)
  const paths = { manifest: manifestPath, evidence: evidencePath, artifacts: {}, bundles: {} }
  for (const artifact of manifest.artifacts) {
    const artifactPath = path.join(root, artifact.filename)
    const bundlePath = path.join(root, `${artifact.filename}.sigstore.json`)
    const artifactRecord = await describeFile(artifactPath)
    const bundleRecord = await describeFile(bundlePath)
    if (artifactRecord.sha256 !== artifact.sha256 || artifactRecord.bytes !== artifact.bytes) throw new Error(`${artifact.filename} does not match the signed Linux release manifest.`)
    const sigstoreRecord = evidence.artifacts.find((entry) => entry.filename === artifact.filename)
    if (bundleRecord.sha256 !== sigstoreRecord.bundleSha256) throw new Error(`${artifact.filename} Sigstore bundle was substituted.`)
    paths.artifacts[artifact.filename] = artifactPath
    paths.bundles[artifact.filename] = bundlePath
  }
  const manifestRecord = await describeFile(manifestPath)
  const manifestBundle = await describeFile(path.join(root, `${manifestFilename}.sigstore.json`))
  if (manifestRecord.sha256 !== evidence.manifestSha256 || manifestBundle.sha256 !== evidence.manifestBundleSha256) {
    throw new Error('The Linux manifest or its Sigstore bundle was substituted after verification.')
  }
  for (const [label, file] of Object.entries({ sbom: manifest.sbom, shipped: manifest.linuxLifecycle.shipped, vault: manifest.linuxLifecycle.vault })) {
    const filePath = path.join(root, file.filename)
    const record = await describeFile(filePath)
    if (record.sha256 !== file.sha256 || record.bytes !== file.bytes) throw new Error(`The Linux ${label} record does not match the manifest.`)
  }
  return { manifest, evidence, paths, manifestSha256: manifestRecord.sha256 }
}
