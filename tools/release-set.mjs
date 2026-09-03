import { createHash } from 'node:crypto'

import { linuxFormats } from './release-platforms/linux.mjs'
import { windowsFormats } from './release-platforms/windows.mjs'
import { RELEASE_REPOSITORY, RELEASE_WORKFLOW, SIGSTORE_ISSUER, releaseIdentity, stableJSON } from './release-evidence-lib.mjs'

const sha256Pattern = /^[0-9a-f]{64}$/
const versionPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/
const architectureSet = new Set(['x86_64', 'aarch64'])
const channelSet = new Set(['owner', 'beta'])
const formatSet = new Set([...windowsFormats, ...linuxFormats])
const formatsByPlatform = { windows: windowsFormats, linux: linuxFormats }

const digest = (value, encoding = 'hex') => createHash('sha256').update(value).digest(encoding)
const evidenceDigest = (value) => value == null ? '' : digest(stableJSON(value), 'base64url')
const recordKey = (artifact) => `${artifact.format}:${artifact.architecture}`

export function applicableReleaseFormats(platform) {
  const formats = formatsByPlatform[platform]
  if (!formats) throw new Error('Release set platform must be windows or linux.')
  return [...formats]
}

function validateURL(value, label) {
  let parsed
  try { parsed = new URL(value) } catch { throw new Error(`${label} must be a credential-free HTTPS URL.`) }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash || parsed.search || !parsed.hostname) {
    throw new Error(`${label} must be a credential-free HTTPS URL.`)
  }
}

function releaseSetDigestPayload(releaseSet) {
  const records = [...releaseSet.artifacts].sort((left, right) => recordKey(left).localeCompare(recordKey(right)))
  const lines = [
    'sesame-release-set-digest-v1', releaseSet.version, releaseSet.channel, releaseSet.platform,
    releaseSet.architecture, releaseSet.supportedWindows ?? '', releaseSet.releaseNotesUrl,
  ]
  for (const artifact of records) {
    lines.push(
      'artifact', artifact.format, artifact.architecture, artifact.url, artifact.objectKey,
      artifact.sha256, String(artifact.bytes), String(artifact.updaterCapable),
      artifact.updaterSignature ?? '', artifact.updaterSigningKeyId ?? '', artifact.distributionClass,
      String(artifact.sigstoreVerified), artifact.sigstoreIssuer, artifact.sigstoreIdentity,
      artifact.sigstoreBundleSha256, evidenceDigest(artifact.sigstoreEvidence),
      String(artifact.authenticodeVerified), artifact.authenticodeSubject ?? '',
      artifact.authenticodeThumbprint ?? '', evidenceDigest(artifact.authenticodeEvidence),
    )
  }
  return lines.join('\n')
}

export function calculateReleaseSetDigest(releaseSet) {
  return digest(releaseSetDigestPayload(releaseSet))
}

export function releaseSetSigningPayload(releaseSet) {
  const updater = releaseSet.artifacts.find((artifact) => artifact.updaterCapable)
  return [
    'sesame-release-set-candidate-v1', releaseSet.version, releaseSet.channel, releaseSet.platform,
    releaseSet.architecture, releaseSet.supportedWindows ?? '', releaseSet.releaseNotesUrl,
    releaseSet.setDigest, 'updater', updater?.format ?? '', updater?.architecture ?? '',
    updater?.url ?? '', updater?.objectKey ?? '', updater?.sha256 ?? '',
    updater ? String(updater.bytes) : '', updater?.updaterSignature ?? '',
    updater?.updaterSigningKeyId ?? '',
  ].join('\n')
}

export function verifyReleaseSet(releaseSet) {
  if (releaseSet?.schemaVersion !== 3 || !versionPattern.test(releaseSet.version) || !channelSet.has(releaseSet.channel)) {
    throw new Error('Release set identity is invalid.')
  }
  if (!architectureSet.has(releaseSet.architecture)) throw new Error('Release set architecture is invalid.')
  validateURL(releaseSet.releaseNotesUrl, 'Release notes URL')
  const requiredFormats = applicableReleaseFormats(releaseSet.platform)
  if (releaseSet.platform === 'windows' && (typeof releaseSet.supportedWindows !== 'string' || releaseSet.supportedWindows.length === 0)) {
    throw new Error('Windows release sets must disclose supported Windows versions.')
  }
  if (releaseSet.platform === 'linux' && releaseSet.supportedWindows) {
    throw new Error('Linux release sets cannot declare supported Windows versions.')
  }
  if (!Array.isArray(releaseSet.artifacts)) throw new Error('Release set artifacts are required.')
  const seen = new Set()
  for (const artifact of releaseSet.artifacts) {
    const key = recordKey(artifact)
    if (seen.has(key)) throw new Error(`Release set contains duplicate ${key} records.`)
    seen.add(key)
    if (!formatSet.has(artifact.format) || artifact.architecture !== releaseSet.architecture || !requiredFormats.includes(artifact.format)) {
      throw new Error(`Release set contains an inapplicable ${key} record.`)
    }
    validateURL(artifact.url, `${artifact.format} download URL`)
    if (!sha256Pattern.test(artifact.sha256) || !Number.isSafeInteger(artifact.bytes) || artifact.bytes <= 0) {
      throw new Error(`${key} digest or byte count is invalid.`)
    }
    if (typeof artifact.objectKey !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}$/.test(artifact.objectKey) || artifact.objectKey.includes('//') || artifact.objectKey.split('/').some((part) => part === '.' || part === '..')) {
      throw new Error(`${key} object key is invalid.`)
    }
    const shouldUpdate = releaseSet.platform === 'windows' && artifact.format === 'nsis'
    if (artifact.updaterCapable !== shouldUpdate) throw new Error(`${key} updater capability is invalid.`)
    if (shouldUpdate && ((artifact.updaterSignature?.length ?? 0) < 64 || !artifact.updaterSigningKeyId)) {
      throw new Error(`${key} updater evidence is incomplete.`)
    }
    if (!shouldUpdate && (artifact.updaterSignature || artifact.updaterSigningKeyId)) {
      throw new Error(`${key} claims updater evidence without updater capability.`)
    }
    const expectedRef = `refs/tags/v${releaseSet.version}`
    const expectedIdentity = releaseIdentity(RELEASE_REPOSITORY, RELEASE_WORKFLOW, expectedRef)
    if (artifact.sigstoreVerified !== true || artifact.sigstoreIssuer !== SIGSTORE_ISSUER || artifact.sigstoreIdentity !== expectedIdentity || artifact.sigstoreEvidence?.verified !== true || artifact.sigstoreEvidence?.transparencyLogVerified !== true || artifact.sigstoreEvidence?.artifactSha256 !== artifact.sha256 || artifact.sigstoreEvidence?.issuer !== SIGSTORE_ISSUER || artifact.sigstoreEvidence?.certificateIdentity !== expectedIdentity || artifact.sigstoreEvidence?.repository !== RELEASE_REPOSITORY || artifact.sigstoreEvidence?.workflow !== RELEASE_WORKFLOW || artifact.sigstoreEvidence?.ref !== expectedRef || artifact.sigstoreBundleSha256 !== artifact.sigstoreEvidence?.artifactBundleSha256) {
      throw new Error(`${key} Sigstore evidence does not verify the exact package.`)
    }
    if (!sha256Pattern.test(artifact.sigstoreBundleSha256)) throw new Error(`${key} Sigstore bundle digest is invalid.`)
    if (artifact.authenticodeVerified === true && (!artifact.authenticodeEvidence || !artifact.authenticodeSubject || !artifact.authenticodeThumbprint)) {
      throw new Error(`${key} Authenticode evidence is incomplete.`)
    }
    const eligible = artifact.sigstoreVerified && ((artifact.distributionClass === 'early_access' && !artifact.authenticodeVerified) || (artifact.distributionClass === 'production' && artifact.authenticodeVerified))
    if (!eligible) throw new Error(`${key} distribution evidence is ineligible.`)
  }
  const missing = requiredFormats.filter((format) => !seen.has(`${format}:${releaseSet.architecture}`))
  if (missing.length > 0) throw new Error(`Release set is missing required formats: ${missing.join(', ')}.`)
  if (releaseSet.setDigest !== calculateReleaseSetDigest(releaseSet)) throw new Error('Release set digest does not match its immutable records.')
  return releaseSet
}

export function prepareReleaseSet(input) {
  const prepared = { ...input, schemaVersion: 3, artifacts: [...input.artifacts].sort((left, right) => recordKey(left).localeCompare(recordKey(right))) }
  prepared.setDigest = calculateReleaseSetDigest(prepared)
  return verifyReleaseSet(prepared)
}

export function reconcileReleaseSet(expected, actual) {
  verifyReleaseSet(expected)
  const actualArtifacts = Array.isArray(actual?.artifacts) ? actual.artifacts : []
  const missing = []
  const conflicts = []
  const actualByKey = new Map()
  for (const artifact of actualArtifacts) {
    const key = recordKey(artifact)
    if (actualByKey.has(key)) conflicts.push(key)
    actualByKey.set(key, artifact)
  }
  for (const artifact of expected.artifacts) {
    const current = actualByKey.get(recordKey(artifact))
    if (!current) missing.push(recordKey(artifact))
    else if (stableJSON(current) !== stableJSON(artifact)) conflicts.push(recordKey(artifact))
  }
  for (const artifact of actualArtifacts) {
    if (!expected.artifacts.some((item) => recordKey(item) === recordKey(artifact))) conflicts.push(recordKey(artifact))
  }
  if (expected.version !== actual?.version || expected.channel !== actual?.channel || expected.platform !== actual?.platform || expected.architecture !== actual?.architecture || expected.supportedWindows !== actual?.supportedWindows || expected.releaseNotesUrl !== actual?.releaseNotesUrl || expected.setDigest !== actual?.setDigest) {
    conflicts.unshift('release-set')
  }
  return { complete: missing.length === 0 && conflicts.length === 0, missing, conflicts: [...new Set(conflicts)] }
}
