import { execFile } from 'node:child_process'
import {
  createPrivateKey,
  createPublicKey,
  createHash,
  randomBytes,
  sign,
} from 'node:crypto'
import { copyFile, mkdir, rm, writeFile } from 'node:fs/promises'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

const run = promisify(execFile)
const workspace = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const artifactsRoot = resolve(workspace, 'release-artifacts')
const outputArgument = process.argv[2]
if (!outputArgument) {
  throw new Error('Usage: node tools/prepare-updater-vm-lab.mjs <release-artifacts/output-directory>')
}
const output = resolve(workspace, outputArgument)
const outputLocation = relative(artifactsRoot, output)
if (!outputLocation || outputLocation === '..' || outputLocation.startsWith(`..${sep}`)) {
  throw new Error('The updater lab output must be a new directory under release-artifacts/.')
}

const privateDirectory = join(output, '.private-build-material')
const publicDirectory = join(output, 'PUBLIC')
const installersDirectory = join(output, 'INSTALLERS')
const updaterDirectory = join(output, 'UPDATER')
const toolsDirectory = join(output, 'TOOLS')
const password = 'Fictional-REL003-Updater-Lab-Only'
const port = 18787
const host = '127.0.0.1'
const keyID = 'rel003-lab-candidate-20260812'
const tauriCLI = join(workspace, 'node_modules', '@tauri-apps', 'cli', 'tauri.js')
let completed = false

function ed25519(seed = randomBytes(32)) {
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed])
  const privateKey = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' })
  const spki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' })
  return { privateKey, publicKey: spki.subarray(spki.length - 32).toString('base64url') }
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

async function build(overlay, environment, noSign) {
  const args = [tauriCLI, 'build', '--bundles', 'nsis', '--config', overlay]
  if (noSign) args.push('--no-sign')
  await run(process.execPath, args, { cwd: workspace, env: environment, maxBuffer: 32 * 1024 * 1024 })
}

await mkdir(output, { recursive: false })
await mkdir(privateDirectory)
await mkdir(publicDirectory)
await mkdir(installersDirectory)
await mkdir(updaterDirectory)
await mkdir(toolsDirectory)

try {
  const updaterKeyPath = join(privateDirectory, 'updater.key')
  await run(
    process.execPath,
    [tauriCLI, 'signer', 'generate', '--ci', '--password', password, '--write-keys', updaterKeyPath],
    { cwd: workspace },
  )
  const updaterPublicKey = (await readFile(`${updaterKeyPath}.pub`, 'utf8')).trim()
  const capability = ed25519()
  const candidate = ed25519()
  const commonEnvironment = {
    ...process.env,
    SESAME_API_BASE_URL: `http://${host}:${port}`,
    SESAME_CAPABILITY_PUBLIC_KEY: capability.publicKey,
    SESAME_UPDATER_PUBLIC_KEY: updaterPublicKey,
    SESAME_UPDATE_MANIFEST_URL: `http://${host}:${port}/latest.json`,
    SESAME_ALLOW_INSECURE_UPDATE_LOOPBACK: '1',
    SESAME_RELEASE_CANDIDATE_PUBLIC_KEY: candidate.publicKey,
    SESAME_RELEASE_CANDIDATE_KEY_ID: keyID,
  }
  const oldOverlay = join(publicDirectory, 'tauri.updater-lab-old.json')
  const newOverlay = join(publicDirectory, 'tauri.updater-lab-new.json')
  const updaterPlugin = {
    pubkey: updaterPublicKey,
    dangerousInsecureTransportProtocol: true,
  }
  await writeFile(
    oldOverlay,
    `${JSON.stringify({ version: '0.1.0', bundle: { createUpdaterArtifacts: false }, plugins: { updater: updaterPlugin } }, null, 2)}\n`,
  )
  await writeFile(
    newOverlay,
    `${JSON.stringify({ version: '0.1.1', bundle: { createUpdaterArtifacts: true }, plugins: { updater: updaterPlugin } }, null, 2)}\n`,
  )

  await build(oldOverlay, commonEnvironment, true)
  await copyFile(
    join(workspace, 'src-tauri', 'target', 'release', 'bundle', 'nsis', 'Sesame_0.1.0_x64-setup.exe'),
    join(installersDirectory, 'Sesame_0.1.0_updater-lab_x64-setup.exe'),
  )

  await build(
    newOverlay,
    {
      ...commonEnvironment,
      TAURI_SIGNING_PRIVATE_KEY: (await readFile(updaterKeyPath, 'utf8')).trim(),
      TAURI_SIGNING_PRIVATE_KEY_PASSWORD: password,
    },
    false,
  )
  const bundleDirectory = join(workspace, 'src-tauri', 'target', 'release', 'bundle', 'nsis')
  const newInstaller = join(bundleDirectory, 'Sesame_0.1.1_x64-setup.exe')
  const archive = newInstaller
  const signaturePath = `${archive}.sig`
  await copyFile(newInstaller, join(installersDirectory, 'Sesame_0.1.1_updater-lab_x64-setup.exe'))
  await copyFile(archive, join(updaterDirectory, 'Sesame_0.1.1_x64-setup.exe'))
  await copyFile(signaturePath, join(updaterDirectory, 'Sesame_0.1.1_x64-setup.exe.sig'))

  const archiveBytes = await readFile(archive)
  const updaterSignature = (await readFile(signaturePath, 'utf8')).trim()
  const receiptPayload = [
    'sesame-release-candidate-v2',
    '0.1.1',
    'beta',
    'windows',
    'x86_64',
    'Windows 10,Windows 11',
    'https://releases.example.invalid/rel003-updater-lab',
    'windows/0.1.1/Sesame_0.1.1_x64-setup.exe',
    sha256(archiveBytes),
    String(archiveBytes.length),
    updaterSignature,
    'rel003-lab-updater-20260812',
    'early_access',
    'true',
    'https://token.actions.githubusercontent.com',
    'https://github.com/usesesame/Sesame/.github/workflows/release-early-access.yml@refs/tags/v0.1.1',
    'b'.repeat(64),
    Buffer.alloc(32, 0xcc).toString('base64url'),
    'false',
    '',
    '',
    '',
  ].join('\n')
  const candidateSignature = sign(null, Buffer.from(receiptPayload), candidate.privateKey).toString('base64url')
  const receipt = { payload: receiptPayload, signingKeyId: keyID, signature: candidateSignature }
  const manifest = {
    version: '0.1.1',
    notes: 'Fictional REL-003 signed updater lab.',
    pub_date: '2026-08-12T00:00:00Z',
    url: `http://${host}:${port}/artifact`,
    signature: updaterSignature,
    candidateReceipt: receipt,
  }
  await writeFile(join(publicDirectory, 'manifest-good.json'), `${JSON.stringify(manifest)}\n`)
  await writeFile(
    join(publicDirectory, 'manifest-relabelled.json'),
    `${JSON.stringify({ ...manifest, version: '9.9.9' })}\n`,
  )

  const capabilityPayload = Buffer.from(
    JSON.stringify({
      schemaVersion: 1,
      minimumDesktopVersion: '0.1.0',
      latestDesktopVersion: '0.1.1',
      features: { desktopLinking: true, downloads: false, updater: true, sync: false },
      expiresAt: '2030-01-01T00:00:00Z',
    }),
  )
  const capabilityEnvelope = {
    payload: capabilityPayload.toString('base64url'),
    signature: sign(null, capabilityPayload, capability.privateKey).toString('base64url'),
  }
  await writeFile(
    join(publicDirectory, 'capability-envelope.json'),
    `${JSON.stringify(capabilityEnvelope)}\n`,
  )
  await writeFile(
    join(output, 'lab-config.json'),
    `${JSON.stringify({
      host,
      port,
      linkCode: 'SESAME-REL003-LAB-LINK-CODE-ONLY-2026',
      accessToken: 'sesame-rel003-fictional-loopback-token',
      capabilityEnvelope: 'PUBLIC/capability-envelope.json',
      goodManifest: 'PUBLIC/manifest-good.json',
      relabelledManifest: 'PUBLIC/manifest-relabelled.json',
      updaterArtifact: 'UPDATER/Sesame_0.1.1_x64-setup.exe',
    }, null, 2)}\n`,
  )
  await writeFile(
    join(output, 'PUBLIC-KEYS.json'),
    `${JSON.stringify({ updaterPublicKey, capabilityPublicKey: capability.publicKey, candidatePublicKey: candidate.publicKey, candidateKeyID: keyID }, null, 2)}\n`,
  )
  await copyFile(join(workspace, 'tools', 'serve-updater-vm-lab.mjs'), join(output, 'serve-updater-vm-lab.mjs'))
  await copyFile(join(workspace, 'tools', 'verify-updater-vm-lab.mjs'), join(output, 'verify-updater-vm-lab.mjs'))
  await copyFile(
    join(workspace, 'src-tauri', 'target', 'release', 'verify-updater-artifact.exe'),
    join(toolsDirectory, 'verify-updater-artifact.exe'),
  )
  await writeFile(
    join(output, 'README.md'),
    'Updater VM lab. Copy this directory into the lab VM, run serve-updater-vm-lab.mjs, then verify-updater-vm-lab.mjs. Loopback only.\n',
  ) 
  completed = true
  console.log(`Created REL-003 updater lab: ${output}`)
} finally {
  await rm(privateDirectory, { recursive: true, force: true })
  if (!completed) await rm(output, { recursive: true, force: true })
}
