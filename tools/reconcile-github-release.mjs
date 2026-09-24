import { execFile } from 'node:child_process'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { promisify } from 'node:util'

import { fileSha256 } from './release-evidence-lib.mjs'
import {
  RELEASE_SET_DIGEST_LABEL,
  RELEASE_VISIBILITY_DRAFT,
  assertCandidateMatchesAssets,
  collectPublishAssets,
  linuxLaneAssetPatterns,
  parseReleaseVisibility,
  planReleasePublication,
} from './release-publish-reconcile.mjs'

const [handoffDirectory, publicDirectory, manifestFilename, candidateFilename, notesFilename] = process.argv.slice(2)
if (!handoffDirectory || !publicDirectory || !manifestFilename || !candidateFilename) {
  throw new Error('Usage: node tools/reconcile-github-release.mjs <handoff-dir> <public-evidence-dir> <manifest-filename> <candidate-filename> [notes-file]')
}

const repository = process.env.GITHUB_REPOSITORY
const tag = process.env.GITHUB_REF_NAME
if (!repository || !tag) throw new Error('Set GITHUB_REPOSITORY and GITHUB_REF_NAME.')
if (!process.env.GH_TOKEN) throw new Error('GH_TOKEN is required to query and mutate the GitHub release.')
const visibility = parseReleaseVisibility(process.env.SESAME_RELEASE_VISIBILITY)

const run = promisify(execFile)
const gh = async (args) => run('gh', args, { env: process.env, maxBuffer: 16 * 1024 * 1024 })

const { manifest, assets } = await collectPublishAssets(handoffDirectory, publicDirectory, manifestFilename)
if (manifest.source.repository !== repository) throw new Error(`The verified evidence belongs to ${manifest.source.repository}, not ${repository}.`)
if (tag !== `v${manifest.version}`) throw new Error(`Tag ${tag} does not match the verified release version ${manifest.version}.`)
const candidate = JSON.parse(await readFile(candidateFilename, 'utf8'))
const latest = JSON.parse(await readFile(assets.find((asset) => asset.role === 'update-manifest').path, 'utf8'))
assertCandidateMatchesAssets(candidate, assets, { repository, tag, latest })

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
  const directory = await mkdtemp(path.join(tmpdir(), 'sesame-release-assets-'))
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

const assetPaths = (names) => names.map((name) => assets.find((asset) => asset.name === name).path)

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
    foreignAssets: linuxLaneAssetPatterns(manifest.version),
    visibility,
  })
  if (plan.action === 'conflict') {
    throw new Error([
      `The existing release ${tag} does not match this run's verified evidence; nothing was changed.`,
      ...plan.conflicts,
      'Re-run only the failed publish job so it reuses this run\'s artifacts, or reconcile the release and server candidate deliberately.',
    ].join('\n'))
  }
  if (plan.upload.length > 0) await gh(['release', 'upload', tag, '--repo', repository, ...assetPaths(plan.upload)])
  if (plan.anchor === 'append') {
    const directory = await mkdtemp(path.join(tmpdir(), 'sesame-release-notes-'))
    try {
      await appendSetDigest(release.body ?? '', directory)
    } finally {
      await rm(directory, { recursive: true, force: true })
    }
  }
  const state = plan.draft ? 'unpublished draft' : 'published release'
  process.stdout.write(`Release ${tag} ${plan.action === 'complete' ? 'already carries' : 'now carries'} all ${assets.length} verified assets as an ${state}.\n`)
}

let release = await fetchRelease()
if (!release) {
  if (!notesFilename) throw new Error('Creating the release requires a notes file.')
  try {
    await gh([
      'release', 'create', tag,
      '--repo', repository,
      '--title', `Sesame ${tag}`,
      '--notes-file', notesFilename,
      ...(visibility === RELEASE_VISIBILITY_DRAFT ? ['--draft'] : []),
      ...assetPaths(assets.map((asset) => asset.name)),
    ])
    process.stdout.write(`Created ${visibility === RELEASE_VISIBILITY_DRAFT ? 'unpublished draft' : 'published'} release ${tag} with ${assets.length} verified assets.\n`)
  } catch (error) {
    if (!/HTTP 422|already[_ ]exists|already exists/i.test(error.stderr ?? '')) throw error
    release = await fetchRelease()
    if (!release) throw error
  }
}
if (release) await reconcile(release)
