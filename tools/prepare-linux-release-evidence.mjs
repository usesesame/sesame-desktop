import { copyFile, mkdir, readFile, stat, writeFile } from 'node:fs/promises'
import path from 'node:path'

import { RELEASE_REPOSITORY, fileSha256 } from './release-evidence-lib.mjs'
import { LINUX_RELEASE_KIND, LINUX_RELEASE_WORKFLOW } from './linux-release-evidence.mjs'
import { validateLinuxPackageEvidence } from './linux-installed-package-gate.mjs'
import { validateLinuxShippedEvidence } from './linux-shipped-package-gate.mjs'

const [appimageInput, debInput, rpmInput, sbomInput, outputInput] = process.argv.slice(2)
if (!appimageInput || !debInput || !rpmInput || !sbomInput || !outputInput) {
  throw new Error('Usage: node tools/prepare-linux-release-evidence.mjs <appimage> <deb> <rpm> <sbom> <output-directory>')
}

const required = (name) => {
  const value = process.env[name]?.trim()
  if (!value) throw new Error(`${name} is required.`)
  return value
}
const version = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8')).version
const repository = required('GITHUB_REPOSITORY')
const commit = required('GITHUB_SHA')
const ref = required('GITHUB_REF')
const architecture = required('SESAME_RELEASE_ARCHITECTURE')
const channel = process.env.SESAME_RELEASE_CHANNEL?.trim() || 'beta'
if (repository !== RELEASE_REPOSITORY || ref !== `refs/tags/v${version}` || !/^[0-9a-f]{40}$/.test(commit)) {
  throw new Error('Linux release evidence must come from the protected Sesame version tag in usesesame/sesame-desktop.')
}

const shippedEvidencePath = path.resolve(required('SESAME_SHIPPED_PACKAGE_EVIDENCE'))
const vaultEvidencePath = path.resolve(required('SESAME_VAULT_PACKAGE_EVIDENCE'))
const shippedEvidence = validateLinuxShippedEvidence(JSON.parse(await readFile(shippedEvidencePath, 'utf8')))
const vaultEvidence = validateLinuxPackageEvidence(JSON.parse(await readFile(vaultEvidencePath, 'utf8')))

const output = path.resolve(outputInput)
await mkdir(output, { recursive: false })
const describe = async (file) => ({ filename: path.basename(file), sha256: await fileSha256(file), bytes: (await stat(file)).size })
const deployNotes = required('SESAME_RELEASE_NOTES_URL')
let releaseNotes
try {
  releaseNotes = new URL(deployNotes)
} catch {
  throw new Error('SESAME_RELEASE_NOTES_URL is invalid.')
}
if (releaseNotes.protocol !== 'https:' || releaseNotes.username || releaseNotes.password || releaseNotes.hash) {
  throw new Error('SESAME_RELEASE_NOTES_URL must be credential-free HTTPS without a fragment.')
}

const packages = [
  { format: 'appimage', path: path.resolve(appimageInput) },
  { format: 'deb', path: path.resolve(debInput) },
  { format: 'rpm', path: path.resolve(rpmInput) },
]
const artifacts = []
for (const entry of packages) {
  const record = await describe(entry.path)
  await copyFile(entry.path, path.join(output, record.filename))
  artifacts.push({ format: entry.format, ...record })
}
const debArtifact = artifacts.find((artifact) => artifact.format === 'deb')
if (debArtifact.sha256 !== shippedEvidence.package.sha256) {
  throw new Error('The shipped-package evidence does not describe the deb in this release set.')
}
if (shippedEvidence.package.version !== version || vaultEvidence.package.version !== version) {
  throw new Error('The package evidence does not describe this release version.')
}

const copies = {}
for (const [label, source, filename] of [
  ['sbom', path.resolve(sbomInput), 'sesame-linux.cdx.json'],
  ['shipped', shippedEvidencePath, 'linux-shipped-package.json'],
  ['vault', vaultEvidencePath, 'linux-installed-package.json'],
]) {
  const target = path.join(output, filename)
  await copyFile(source, target)
  copies[label] = await describe(target)
}

const manifest = {
  schemaVersion: 1,
  product: 'Sesame',
  releaseKind: LINUX_RELEASE_KIND,
  version,
  channel,
  platform: 'linux',
  architecture,
  source: { repository, workflow: LINUX_RELEASE_WORKFLOW, ref, commit },
  artifacts,
  sbom: copies.sbom,
  linuxLifecycle: { shipped: copies.shipped, vault: copies.vault },
  sigstore: {
    issuer: 'https://token.actions.githubusercontent.com',
    certificateIdentity: `https://github.com/${repository}/${LINUX_RELEASE_WORKFLOW}@${ref}`,
    transparencyLogRequired: true,
  },
  releaseNotesUrl: deployNotes,
}
const manifestFilename = `sesame-${version}-linux-${architecture}.release.json`
await writeFile(path.join(output, manifestFilename), `${JSON.stringify(manifest, null, 2)}\n`)
const sums = [...artifacts, copies.sbom, copies.shipped, copies.vault].map((item) => `${item.sha256}  ${item.filename}`).join('\n')
await writeFile(path.join(output, 'SHA256SUMS-linux'), `${sums}\n`)
process.stdout.write(`${manifestFilename}\n`)
