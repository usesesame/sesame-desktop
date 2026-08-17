import { execFile } from 'node:child_process'
import { readFile, writeFile } from 'node:fs/promises'
import { promisify } from 'node:util'
import path from 'node:path'

import { fileSha256, validateReleaseManifest } from './release-evidence-lib.mjs'

const [artifactInput, manifestInput, artifactBundleInput, manifestBundleInput, outputInput] = process.argv.slice(2)
if (!artifactInput || !manifestInput || !artifactBundleInput || !manifestBundleInput || !outputInput) {
  throw new Error('Usage: node tools/create-sigstore-evidence.mjs <installer> <manifest> <installer-bundle> <manifest-bundle> <output>')
}
const artifact = path.resolve(artifactInput)
const manifestPath = path.resolve(manifestInput)
const artifactBundle = path.resolve(artifactBundleInput)
const manifestBundle = path.resolve(manifestBundleInput)
const manifest = validateReleaseManifest(JSON.parse(await readFile(manifestPath, 'utf8')))
const cosign = process.env.SESAME_COSIGN_BIN?.trim() || 'cosign'
const run = promisify(execFile)
const verify = (blob, bundle) => run(cosign, ['verify-blob', blob, '--bundle', bundle, '--certificate-identity', manifest.sigstore.certificateIdentity, '--certificate-oidc-issuer', manifest.sigstore.issuer], { windowsHide: true })
await verify(artifact, artifactBundle)
await verify(manifestPath, manifestBundle)
const artifactSha256 = await fileSha256(artifact)
if (artifactSha256 !== manifest.artifact.sha256) throw new Error('Sigstore verification passed for installer bytes that do not match the manifest.')
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
  artifactSha256,
  manifestSha256: await fileSha256(manifestPath),
  artifactBundleSha256: await fileSha256(artifactBundle),
  manifestBundleSha256: await fileSha256(manifestBundle),
  verifiedAt: new Date().toISOString(),
}
await writeFile(path.resolve(outputInput), `${JSON.stringify(evidence, null, 2)}\n`)
