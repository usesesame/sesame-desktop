import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

import { validateEvidenceDirectory } from './release-evidence-lib.mjs'

const [directory, manifestFilename, mode = '--public'] = process.argv.slice(2)
if (!directory || !manifestFilename || !['--public', '--internal'].includes(mode)) {
  throw new Error('Usage: node tools/verify-release-evidence.mjs <evidence-directory> <manifest-filename> [--public|--internal]')
}
const { manifest, paths } = await validateEvidenceDirectory(directory, manifestFilename)
const run = promisify(execFile)
const cosign = process.env.SESAME_COSIGN_BIN?.trim() || 'cosign'
const verify = (blob, bundle) => run(cosign, ['verify-blob', blob, '--bundle', bundle, '--certificate-identity', manifest.sigstore.certificateIdentity, '--certificate-oidc-issuer', manifest.sigstore.issuer], { windowsHide: true })
await verify(paths.manifest, paths.manifestBundle)
await verify(paths.artifact, paths.artifactBundle)
if (mode === '--internal') {
  const updaterPublicKey = process.env.SESAME_UPDATER_PUBLIC_KEY?.trim()
  if (!updaterPublicKey) throw new Error('SESAME_UPDATER_PUBLIC_KEY is required for internal release verification.')
  await run('cargo', ['run', '--quiet', '--manifest-path', 'src-tauri/Cargo.toml', '--bin', 'verify-updater-artifact', '--', paths.artifact, paths.updaterSignature], {
    env: { ...process.env, SESAME_UPDATER_PUBLIC_KEY: updaterPublicKey }, windowsHide: true,
  })
}
process.stdout.write(`Verified Sesame ${manifest.version} ${manifest.architecture} release evidence.\n`)
