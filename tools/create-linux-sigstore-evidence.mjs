import { execFile } from 'node:child_process'
import { readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { promisify } from 'node:util'

import { fileSha256 } from './release-evidence-lib.mjs'
import { validateLinuxReleaseManifest } from './linux-release-evidence.mjs'

const [directoryInput, manifestFilename] = process.argv.slice(2)
if (!directoryInput || !manifestFilename) {
  throw new Error('Usage: node tools/create-linux-sigstore-evidence.mjs <handoff-directory> <manifest-filename>')
}
const root = path.resolve(directoryInput)
const manifestPath = path.join(root, manifestFilename)
const manifest = validateLinuxReleaseManifest(JSON.parse(await readFile(manifestPath, 'utf8')))
const cosign = process.env.SESAME_COSIGN_BIN?.trim() || 'cosign'
const run = promisify(execFile)
const verify = (blob, bundle) => run(cosign, ['verify-blob', blob, '--bundle', bundle, '--certificate-identity', manifest.sigstore.certificateIdentity, '--certificate-oidc-issuer', manifest.sigstore.issuer], { windowsHide: true })

const artifacts = []
for (const artifact of manifest.artifacts) {
  const artifactPath = path.join(root, artifact.filename)
  const bundlePath = path.join(root, `${artifact.filename}.sigstore.json`)
  await verify(artifactPath, bundlePath)
  const digest = await fileSha256(artifactPath)
  if (digest !== artifact.sha256) throw new Error(`Sigstore verification passed for ${artifact.filename} bytes that do not match the manifest.`)
  artifacts.push({ filename: artifact.filename, sha256: digest, bundleSha256: await fileSha256(bundlePath) })
}
const manifestBundlePath = path.join(root, `${manifestFilename}.sigstore.json`)
await verify(manifestPath, manifestBundlePath)

const evidence = {
  schemaVersion: 1,
  verified: true,
  transparencyLogVerified: true,
  issuer: manifest.sigstore.issuer,
  certificateIdentity: manifest.sigstore.certificateIdentity,
  repository: manifest.source.repository,
  workflow: manifest.source.workflow,
  ref: manifest.source.ref,
  sourceCommit: manifest.source.commit,
  manifestSha256: await fileSha256(manifestPath),
  manifestBundleSha256: await fileSha256(manifestBundlePath),
  artifacts,
  verifiedAt: new Date().toISOString(),
}
await writeFile(path.join(root, 'linux-sigstore-evidence.json'), `${JSON.stringify(evidence, null, 2)}\n`)
process.stdout.write(`Verified ${artifacts.length} Linux packages and the release manifest.\n`)
