import { execFile } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { promisify } from 'node:util'

import { validateLinuxEvidenceDirectory } from './linux-release-evidence.mjs'
import { validateLinuxPackageEvidence } from './linux-installed-package-gate.mjs'
import { validateLinuxShippedEvidence } from './linux-shipped-package-gate.mjs'

const [directoryInput, manifestFilename] = process.argv.slice(2)
if (!directoryInput || !manifestFilename) {
  throw new Error('Usage: node tools/verify-linux-release-evidence.mjs <handoff-directory> <manifest-filename>')
}
const root = path.resolve(directoryInput)
const { manifest, paths } = await validateLinuxEvidenceDirectory(root, manifestFilename)
const shipped = JSON.parse(await readFile(path.join(root, manifest.linuxLifecycle.shipped.filename), 'utf8'))
const vault = JSON.parse(await readFile(path.join(root, manifest.linuxLifecycle.vault.filename), 'utf8'))
validateLinuxShippedEvidence(shipped)
validateLinuxPackageEvidence(vault)

const cosign = process.env.SESAME_COSIGN_BIN?.trim() || 'cosign'
const run = promisify(execFile)
const verify = (blob, bundle) => run(cosign, ['verify-blob', blob, '--bundle', bundle, '--certificate-identity', manifest.sigstore.certificateIdentity, '--certificate-oidc-issuer', manifest.sigstore.issuer], { windowsHide: true })
for (const artifact of manifest.artifacts) {
  await verify(paths.artifacts[artifact.filename], paths.bundles[artifact.filename])
}
await verify(paths.manifest, path.join(root, `${manifestFilename}.sigstore.json`))
process.stdout.write(`Verified Sesame ${manifest.version} ${manifest.architecture} Linux release evidence and both installed-package gates.\n`)
