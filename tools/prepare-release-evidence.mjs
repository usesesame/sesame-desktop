import { copyFile, mkdir, readFile, stat, writeFile } from 'node:fs/promises'
import path from 'node:path'

import { RELEASE_REPOSITORY, RELEASE_WORKFLOW, SIGSTORE_ISSUER, fileSha256, releaseIdentity } from './release-evidence-lib.mjs'

const [artifactInput, updaterSignatureInput, sbomInput, outputInput] = process.argv.slice(2)
if (!artifactInput || !updaterSignatureInput || !sbomInput || !outputInput) {
  throw new Error('Usage: node tools/prepare-release-evidence.mjs <installer> <updater-signature> <sbom> <output-directory>')
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
  throw new Error('Release evidence must come from the protected Sesame version tag in usesesame/sesame-desktop.')
}

const output = path.resolve(outputInput)
await mkdir(output, { recursive: false })
const inputs = {
  artifact: path.resolve(artifactInput),
  updaterSignature: path.resolve(updaterSignatureInput),
  sbom: path.resolve(sbomInput),
}
const filenames = Object.fromEntries(Object.entries(inputs).map(([key, value]) => [key, path.basename(value)]))
for (const [key, value] of Object.entries(inputs)) await copyFile(value, path.join(output, filenames[key]))

const describe = async (key) => ({ filename: filenames[key], sha256: await fileSha256(inputs[key]), bytes: (await stat(inputs[key])).size })
const artifact = await describe('artifact')
const updaterSignature = await describe('updaterSignature')
const sbom = await describe('sbom')
const manifest = {
  schemaVersion: 1,
  product: 'Sesame',
  releaseKind: 'unsigned-windows-early-access',
  version,
  channel,
  platform: 'windows',
  architecture,
  source: { repository, workflow: RELEASE_WORKFLOW, ref, commit },
  artifact,
  updaterSignature: { ...updaterSignature, signingKeyId: required('SESAME_UPDATER_SIGNING_KEY_ID') },
  sbom,
  sigstore: {
    issuer: SIGSTORE_ISSUER,
    certificateIdentity: releaseIdentity(repository, RELEASE_WORKFLOW, ref),
    transparencyLogRequired: true,
  },
  windowsTrust: {
    authenticodeVerified: false,
    smartScreenReputationPromised: false,
    label: 'Unsigned Windows early-access build',
  },
  supportedWindows: required('SESAME_SUPPORTED_WINDOWS'),
  releaseNotesUrl: required('SESAME_RELEASE_NOTES_URL'),
}
const manifestFilename = `sesame-${version}-windows-${architecture}.release.json`
await writeFile(path.join(output, manifestFilename), `${JSON.stringify(manifest, null, 2)}\n`)
const sums = [artifact, updaterSignature, sbom].map((item) => `${item.sha256}  ${item.filename}`).join('\n')
await writeFile(path.join(output, 'SHA256SUMS'), `${sums}\n`)
process.stdout.write(`${manifestFilename}\n`)
