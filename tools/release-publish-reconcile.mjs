import { readdir, stat } from 'node:fs/promises'
import path from 'node:path'

import { assertSafeReleaseFilename, fileSha256, validateEvidenceDirectory } from './release-evidence-lib.mjs'

export const LATEST_MANIFEST_FILENAME = 'latest.json'
export const RELEASE_SET_DIGEST_LABEL = 'Release set digest'
export const RELEASE_VISIBILITY_DRAFT = 'draft'
export const RELEASE_VISIBILITY_PUBLISHED = 'published'
const sha256Pattern = /^[0-9a-f]{64}$/
const versionPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/

// An unsigned installer must stay an unpublished draft until Authenticode
// signing exists and a maintainer publishes the release deliberately. An
// unset or unknown value therefore resolves to the draft policy, not to public.
export function parseReleaseVisibility(value) {
  if (value === undefined || value === null || value === '' || value === RELEASE_VISIBILITY_DRAFT) {
    return RELEASE_VISIBILITY_DRAFT
  }
  if (value === RELEASE_VISIBILITY_PUBLISHED) return RELEASE_VISIBILITY_PUBLISHED
  throw new Error(`Unknown release visibility ${value}; use ${RELEASE_VISIBILITY_DRAFT} or ${RELEASE_VISIBILITY_PUBLISHED}.`)
}

// The Windows and Linux lanes publish into one release per tag. Each lane
// reconciles its own asset set and ignores the other lane's assets by exact
// version-bound name shape, so an unrelated file still stops the run.

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

export function windowsLaneAssetPatterns(version) {
  const escaped = escapeRegExp(version)
  return [
    /^latest\.json$/,
    /^SHA256SUMS$/,
    /^sigstore-evidence\.json$/,
    /^verify-sesame-release\.ps1$/,
    new RegExp(`^sesame-${escaped}\\.cdx\\.json$`),
    new RegExp(`^sesame-${escaped}-windows-[^/]+\\.release\\.json(\\.sigstore\\.json)?$`),
    new RegExp(`^Sesame_${escaped}_[^/]+\\.exe$`),
    new RegExp(`^Sesame_${escaped}_[^/]+\\.exe\\.sig$`),
    new RegExp(`^Sesame_${escaped}_[^/]+\\.exe\\.sigstore\\.json$`),
  ]
}

export function linuxLaneAssetPatterns(version) {
  const escaped = escapeRegExp(version)
  return [
    /^SHA256SUMS-linux$/,
    /^sesame-linux\.cdx\.json$/,
    /^linux-sigstore-evidence\.json$/,
    /^linux-shipped-package\.json$/,
    /^linux-installed-package\.json$/,
    new RegExp(`^sesame-${escaped}-linux-[^/]+\\.release\\.json(\\.sigstore\\.json)?$`),
    new RegExp(`^Sesame-${escaped}-.*\\.AppImage(\\.sigstore\\.json)?$`),
    new RegExp(`^Sesame_${escaped}_[^/]+\\.AppImage(\\.sigstore\\.json)?$`),
    new RegExp(`^Sesame_${escaped}_.*\\.deb(\\.sigstore\\.json)?$`),
    new RegExp(`^Sesame-${escaped}-.*\\.rpm(\\.sigstore\\.json)?$`),
  ]
}

// A retry re-derives the whole plan from digests instead of trusting asset
// names: a release that already exists must match byte for byte or the run
// stops before touching anything.
export async function collectPublishAssets(handoffDirectory, publicDirectory, manifestFilename) {
  const { manifest, paths } = await validateEvidenceDirectory(handoffDirectory, manifestFilename)
  const latestPath = path.join(path.resolve(handoffDirectory), LATEST_MANIFEST_FILENAME)
  const latestStat = await stat(latestPath)
  const publicNames = (await readdir(path.resolve(publicDirectory))).sort()
  for (const name of [...publicNames, LATEST_MANIFEST_FILENAME]) assertSafeReleaseFilename(name, 'publish asset filename')
  const assets = [
    { role: 'installer', name: manifest.artifact.filename, path: paths.artifact, sha256: manifest.artifact.sha256, bytes: manifest.artifact.bytes },
    { role: 'updater-signature', name: manifest.updaterSignature.filename, path: paths.updaterSignature, sha256: manifest.updaterSignature.sha256, bytes: manifest.updaterSignature.bytes },
    { role: 'update-manifest', name: LATEST_MANIFEST_FILENAME, path: latestPath, sha256: await fileSha256(latestPath), bytes: latestStat.size },
  ]
  for (const name of publicNames) {
    const filePath = path.join(path.resolve(publicDirectory), name)
    const fileStat = await stat(filePath)
    if (!fileStat.isFile()) throw new Error(`Public release evidence entry ${name} is not a regular file.`)
    const publicSha256 = await fileSha256(filePath)
    const handoffPath = path.join(path.resolve(handoffDirectory), name)
    const handoffStat = await stat(handoffPath).then((value) => value, () => null)
    if (!handoffStat?.isFile()) throw new Error(`Public release evidence entry ${name} has no canonical handoff copy.`)
    const handoffSha256 = await fileSha256(handoffPath)
    if (publicSha256 !== handoffSha256 || fileStat.size !== handoffStat.size) {
      throw new Error(`Public release evidence entry ${name} does not match its handoff copy.`)
    }
    assets.push({ role: 'public-evidence', name, path: filePath, sha256: publicSha256, bytes: fileStat.size })
  }
  const names = new Set()
  for (const asset of assets) {
    if (names.has(asset.name)) throw new Error(`Duplicate publish asset name ${asset.name}.`)
    names.add(asset.name)
  }
  return { manifest, assets }
}

export function latestReceiptBindsInstaller(latest, { version, url, sha256, bytes }) {
  if (latest?.version !== version || typeof latest?.candidateReceipt?.payload !== 'string') {
    throw new Error('The static update manifest does not carry this release set.')
  }
  const lines = latest.candidateReceipt.payload.split('\n')
  if (lines[0] !== 'sesame-release-candidate-v3' || lines.length !== 23) {
    throw new Error('The static update manifest receipt is not the v3 layout this pipeline ships.')
  }
  if (lines[1] !== version || lines[7] !== url || lines[9] !== sha256 || lines[10] !== String(bytes)) {
    throw new Error('The static update manifest points at different installer bytes than the verified candidate.')
  }
  for (const target of Object.values(latest.platforms ?? {})) {
    if (target?.url !== url) throw new Error('The static update manifest platform URL does not match the verified candidate.')
  }
  return latest
}

export function assertCandidateMatchesAssets(candidate, assets, { repository, tag, latest }) {
  if (candidate?.schemaVersion !== 3 || candidate?.version !== tag.slice(1) || !versionPattern.test(candidate?.version ?? '')) {
    throw new Error(`The candidate does not describe release tag ${tag}.`)
  }
  if (!sha256Pattern.test(candidate?.setDigest ?? '')) throw new Error('The candidate carries no release set digest.')
  const installer = assets.find((asset) => asset.role === 'installer')
  const updateManifest = assets.find((asset) => asset.role === 'update-manifest')
  const updater = candidate.artifacts?.find((artifact) => artifact.updaterCapable)
  if (!installer || !updateManifest || !updater) throw new Error('The publish set is missing the installer, static manifest, or updater record.')
  if (updater.sha256 !== installer.sha256) {
    throw new Error(`The candidate updater record (${updater.sha256}) does not bind the verified installer bytes (${installer.sha256}).`)
  }
  const expectedURL = `https://github.com/${repository}/releases/download/${tag}/${installer.name}`
  if (updater.url !== expectedURL) {
    throw new Error(`The candidate download URL (${updater.url}) is not the exact release asset URL (${expectedURL}).`)
  }
  return latestReceiptBindsInstaller(latest, { version: candidate.version, url: updater.url, sha256: updater.sha256, bytes: installer.bytes })
}

export function planReleasePublication({ release, expectedAssets, setDigest, foreignAssets = [], visibility = RELEASE_VISIBILITY_DRAFT }) {
  if (!release) {
    return {
      action: 'create',
      upload: expectedAssets.map((asset) => asset.name),
      conflicts: [],
      anchor: 'create',
      draft: visibility === RELEASE_VISIBILITY_DRAFT,
    }
  }
  const conflicts = []
  // A draft under the public policy has no recorded decision to publish it, so
  // the run stops instead of publishing or overwriting it. A published release
  // under the draft policy is a deliberate post-approval state; retries converge.
  if (release.isDraft && visibility === RELEASE_VISIBILITY_PUBLISHED) {
    conflicts.push('The existing release is a draft: publish or delete it deliberately before this job can converge.')
  }
  const remote = new Map((release.assets ?? []).map((asset) => [asset.name, asset]))
  const upload = []
  for (const asset of expectedAssets) {
    const current = remote.get(asset.name)
    if (!current) {
      upload.push(asset.name)
      continue
    }
    if (typeof current.size === 'number' && current.size !== asset.bytes) {
      conflicts.push(`${asset.name} exists with ${current.size} bytes instead of ${asset.bytes}.`)
      continue
    }
    if (current.sha256 !== asset.sha256) {
      conflicts.push(`${asset.name} exists with sha256 ${current.sha256} instead of ${asset.sha256}.`)
    }
  }
  for (const name of remote.keys()) {
    if (expectedAssets.some((asset) => asset.name === name)) continue
    if (foreignAssets.some((pattern) => pattern.test(name))) continue
    conflicts.push(`The release carries unexpected asset ${name}.`)
  }
  const declared = (release.body ?? '')
    .split('\n')
    .filter((line) => line.startsWith(`${RELEASE_SET_DIGEST_LABEL}: `))
    .map((line) => line.slice(`${RELEASE_SET_DIGEST_LABEL}: `.length).trim())
  let anchor
  if (declared.includes(setDigest)) anchor = 'present'
  else if (declared.length === 0) anchor = 'missing'
  else if (declared.every((value) => sha256Pattern.test(value))) anchor = 'append'
  else anchor = 'malformed'
  if (anchor === 'missing') {
    conflicts.push(`The release notes omit the ${RELEASE_SET_DIGEST_LABEL.toLowerCase()} anchor this pipeline ships.`)
  } else if (anchor === 'malformed') {
    conflicts.push(`The release notes carry a malformed ${RELEASE_SET_DIGEST_LABEL.toLowerCase()} line.`)
  }
  return {
    action: conflicts.length > 0 ? 'conflict' : upload.length > 0 ? 'resume' : 'complete',
    upload,
    conflicts,
    anchor,
    draft: release.isDraft === true,
  }
}

// The server accepts an exact replay with 201, so the same POST is both the
// state query and the mutation; a timeout after acceptance converges on the
// next attempt without a second candidate.
export function interpretCandidateSubmission(status, body) {
  if (status === 201) return { outcome: 'accepted' }
  const detail = body.slice(0, 500)
  if (status === 409) return { outcome: 'conflict', message: `the server already binds this release tuple to different signed evidence: ${detail}` }
  if (status >= 500) return { outcome: 'retryable', message: detail }
  return { outcome: 'rejected', message: detail }
}
