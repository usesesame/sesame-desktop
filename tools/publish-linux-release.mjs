import { execFile } from 'node:child_process'
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { promisify } from 'node:util'

import { assertSafeReleaseFilename, fileSha256 } from './release-evidence-lib.mjs'
import { RELEASE_SET_DIGEST_LABEL, planReleasePublication, windowsLaneAssetPatterns } from './release-publish-reconcile.mjs'
import { assertCandidateArtifactsBindAssets, validateLinuxEvidenceDirectory } from './linux-release-evidence.mjs'

const [handoffInput, manifestFilename, candidateFilename, notesFilename] = process.argv.slice(2)
if (!handoffInput || !manifestFilename || !candidateFilename) {
  throw new Error('Usage: node tools/publish-linux-release.mjs <handoff-dir> <manifest-filename> <candidate-filename> [notes-file]')
}
const repository = process.env.GITHUB_REPOSITORY
const tag = process.env.GITHUB_REF_NAME
if (!repository || !tag) throw new Error('Set GITHUB_REPOSITORY and GITHUB_REF_NAME.')
if (!process.env.GH_TOKEN) throw new Error('GH_TOKEN is required to query and mutate the GitHub release.')

const handoff = path.resolve(handoffInput)
const { manifest } = await validateLinuxEvidenceDirectory(handoff, manifestFilename)
if (manifest.source.repository !== repository) throw new Error(`The verified evidence belongs to ${manifest.source.repository}, not ${repository}.`)
if (tag !== `v${manifest.version}`) throw new Error(`Tag ${tag} does not match the verified release version ${manifest.version}.`)

const expected = [
  ...manifest.artifacts.map((artifact) => artifact.filename),
  ...manifest.artifacts.map((artifact) => `${artifact.filename}.sigstore.json`),
  manifestFilename,
  `${manifestFilename}.sigstore.json`,
  'linux-sigstore-evidence.json',
  'SHA256SUMS-linux',
  manifest.sbom.filename,
  manifest.linuxLifecycle.shipped.filename,
  manifest.linuxLifecycle.vault.filename,
]
const existing = new Set(await readdir(handoff))
for (const name of expected) {
  assertSafeReleaseFilename(name, 'publish asset filename')
  if (!existing.has(name)) throw new Error(`Linux release evidence is missing ${name}.`)
}
const assets = []
for (const name of expected) {
  const filePath = path.join(handoff, name)
  const fileStat = await stat(filePath)
  if (!fileStat.isFile()) throw new Error(`Linux release evidence entry ${name} is not a regular file.`)
  assets.push({ name, path: filePath, sha256: await fileSha256(filePath), bytes: fileStat.size })
}
const names = new Set()
for (const asset of assets) {
  if (names.has(asset.name)) throw new Error(`Duplicate publish asset name ${asset.name}.`)
  names.add(asset.name)
}

const candidate = JSON.parse(await readFile(path.resolve(candidateFilename), 'utf8'))
if (candidate?.platform !== 'linux' || candidate?.version !== manifest.version || !/^[0-9a-f]{64}$/.test(candidate?.setDigest ?? '')) {
  throw new Error('The candidate does not describe this Linux release.')
}
assertCandidateArtifactsBindAssets(candidate, assets, { repository, tag })

const gh = async (args) => promisify(execFile)('gh', args, { env: process.env, maxBuffer: 16 * 1024 * 1024 })
const fetchRelease = async () => {
  try {
    const { stdout } = await gh(['api', `repos/${repository}/releases/tags/${tag}`])
    return JSON.parse(stdout)
  } catch (error) {
    if (/HTTP 404/.test(error.stderr ?? '')) return null
    throw error
  }
}
const downloadAssets = async (remoteAssets) => {
  const directory = await mkdtemp(path.join(tmpdir(), 'sesame-linux-release-assets-'))
  try {
    const verified = []
    for (const asset of remoteAssets) {
      await gh(['release', 'download', tag, '--repo', repository, '--pattern', asset.name, '--dir', directory])
      const filePath = path.join(directory, asset.name)
      verified.push({ name: asset.name, size: asset.size, sha256: await fileSha256(filePath) })
    }
    return verified
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}

const appendSetDigest = async (body, directory) => {
  const notes = `${body.replace(/\n*$/, '')}\n\n${RELEASE_SET_DIGEST_LABEL}: ${candidate.setDigest}\n`
  const notesPath = path.join(directory, 'release-notes.md')
  await writeFile(notesPath, notes)
  await gh(['release', 'edit', tag, '--repo', repository, '--notes-file', notesPath])
}

const reconcile = async (release) => {
  const plan = planReleasePublication({
    release: { isDraft: release.draft === true, body: release.body, assets: await downloadAssets(release.assets ?? []) },
    expectedAssets: assets,
    setDigest: candidate.setDigest,
    foreignAssets: windowsLaneAssetPatterns(manifest.version),
  })
  if (plan.action === 'conflict') {
    throw new Error([
      `The existing release ${tag} does not match this run's verified evidence; nothing was changed.`,
      ...plan.conflicts,
    ].join('\n'))
  }
  const byName = new Map(assets.map((asset) => [asset.name, asset]))
  if (plan.upload.length > 0) await gh(['release', 'upload', tag, '--repo', repository, ...plan.upload.map((name) => byName.get(name).path)])
  if (plan.anchor === 'append') {
    const directory = await mkdtemp(path.join(tmpdir(), 'sesame-linux-release-notes-'))
    try {
      await appendSetDigest(release.body ?? '', directory)
    } finally {
      await rm(directory, { recursive: true, force: true })
    }
  }
  process.stdout.write(`Release ${tag} ${plan.action === 'complete' ? 'already carries' : 'now carries'} all ${assets.length} verified assets.\n`)
}

let release = await fetchRelease()
if (!release) {
  if (!notesFilename) throw new Error('Creating the release requires a notes file.')
  try {
    await gh(['release', 'create', tag, '--repo', repository, '--title', `Sesame ${tag}`, '--notes-file', notesFilename, ...assets.map((asset) => asset.path)])
    process.stdout.write(`Created release ${tag} with ${assets.length} verified assets.\n`)
  } catch (error) {
    if (!/HTTP 422|already[_ ]exists|already exists/i.test(error.stderr ?? '')) throw error
    release = await fetchRelease()
    if (!release) throw error
  }
}
if (release) await reconcile(release)
