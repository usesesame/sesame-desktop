import { spawn } from 'node:child_process'
import { execFileSync } from 'node:child_process'
import { createHash, createPublicKey, verify } from 'node:crypto'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { join, resolve } from 'node:path'

const rootArgument = process.argv[2]
if (!rootArgument) throw new Error('Usage: node tools/verify-updater-vm-lab.mjs <lab-directory>')
const root = resolve(rootArgument)
const readJSON = (file) => JSON.parse(readFileSync(join(root, file), 'utf8'))
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex')
const publicKey = (encoded) => createPublicKey({
  key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(encoded, 'base64url')]),
  format: 'der',
  type: 'spki',
})

if (existsSync(join(root, '.private-build-material'))) {
  throw new Error('Ephemeral private build material remains in the updater lab.')
}
for (const file of readdirSync(root, { recursive: true })) {
  if (/\.(?:key|pem|pfx|p12)$/i.test(file) || /private/i.test(file)) {
    throw new Error(`Private-key-shaped payload remains in the updater lab: ${file}`)
  }
}
const config = readJSON('lab-config.json')
if (config.host !== '127.0.0.1') throw new Error('Updater lab is not loopback-only.')
const keys = readJSON('PUBLIC-KEYS.json')
const good = readJSON(config.goodManifest)
const relabelled = readJSON(config.relabelledManifest)
const artifact = readFileSync(join(root, config.updaterArtifact))
const detachedSignature = readFileSync(`${join(root, config.updaterArtifact)}.sig`, 'utf8').trim()
const updaterVerifier = join(root, 'TOOLS', 'verify-updater-artifact.exe')
if (existsSync(updaterVerifier)) {
  execFileSync(updaterVerifier, [join(root, config.updaterArtifact), `${join(root, config.updaterArtifact)}.sig`], {
    cwd: root,
    env: { ...process.env, SESAME_UPDATER_PUBLIC_KEY: keys.updaterPublicKey },
    stdio: 'pipe',
  })
}
const claims = good.candidateReceipt.payload.split('\n')
if (
  claims.length !== 23 ||
  claims[0] !== 'sesame-release-candidate-v3' ||
  claims[1] !== good.version ||
  claims[3] !== 'windows' ||
  claims[4] !== 'x86_64' ||
  claims[7] !== good.url ||
  claims[9] !== hash(artifact) ||
  claims[10] !== String(artifact.length) ||
  claims[11] !== detachedSignature ||
  claims[13] !== 'early_access' ||
  claims[14] !== 'true' ||
  claims[15] !== 'https://token.actions.githubusercontent.com' ||
  claims[16] !== 'https://github.com/usesesame/sesame-desktop/.github/workflows/release-early-access.yml@refs/tags/v0.1.1' ||
  claims[19] !== 'false' ||
  good.signature !== detachedSignature ||
  good.candidateReceipt.signingKeyId !== keys.candidateKeyID
) {
  throw new Error('Good updater manifest does not match its signed artifact claims.')
}
if (!verify(
  null,
  Buffer.from(good.candidateReceipt.payload),
  publicKey(keys.candidatePublicKey),
  Buffer.from(good.candidateReceipt.signature, 'base64url'),
)) {
  throw new Error('Release-candidate receipt signature is invalid.')
}
if (
  relabelled.version === claims[1] ||
  relabelled.candidateReceipt.payload !== good.candidateReceipt.payload ||
  relabelled.candidateReceipt.signature !== good.candidateReceipt.signature
) {
  throw new Error('Relabelled manifest does not isolate the version-label attack.')
}
const capability = readJSON(config.capabilityEnvelope)
if (!verify(
  null,
  Buffer.from(capability.payload, 'base64url'),
  publicKey(keys.capabilityPublicKey),
  Buffer.from(capability.signature, 'base64url'),
)) {
  throw new Error('Capability envelope signature is invalid.')
}
const installedNew = readFileSync(join(root, 'INSTALLERS', 'Sesame_0.1.1_updater-lab_x64-setup.exe'))
if (hash(installedNew) !== hash(artifact)) {
  throw new Error('The interactive 0.1.1 installer differs from the signed updater artifact.')
}

async function waitForServer(child) {
  let output = ''
  child.stdout.on('data', (chunk) => { output += chunk })
  child.stderr.on('data', (chunk) => { output += chunk })
  const deadline = Date.now() + 10_000
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://${config.host}:${config.port}/health`)
      if (response.ok) return
    } catch {
      /* the process may still be binding the loopback socket */
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 100))
  }
  child.kill()
  throw new Error(`Updater lab server did not start: ${output.slice(-1000)}`)
}

async function probe(mode) {
  const child = spawn(process.execPath, [join(root, 'serve-updater-vm-lab.mjs'), '--root', root, '--mode', mode], {
    cwd: root,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  })
  try {
    await waitForServer(child)
    const base = `http://${config.host}:${config.port}`
    const authorization = { Authorization: `Sesame ${config.accessToken}` }
    const publicManifest = await fetch(`${base}/latest.json`)
    if (!publicManifest.ok) throw new Error('Public updater manifest is unavailable without an account token.')
    const capabilities = await fetch(`${base}/v1/capabilities`)
    if (!capabilities.ok) throw new Error('Capability endpoint failed.')
    const linked = await fetch(`${base}/v1/desktop/link`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: config.linkCode, deviceName: 'Windows desktop' }),
    })
    if (linked.status !== 201) throw new Error('Lab desktop link failed.')
    const replay = await fetch(`${base}/v1/desktop/link`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: config.linkCode, deviceName: 'Windows desktop' }),
    })
    if (replay.status !== 401) throw new Error('Lab desktop link code was reusable.')
    const manifestResponse = await fetch(`${base}/latest.json`)
    const served = await manifestResponse.json()
    if (served.version !== (mode === 'good' ? '0.1.1' : '9.9.9')) throw new Error(`Wrong ${mode} manifest served.`)
    const artifactResponse = await fetch(served.url)
    if (!artifactResponse.ok || hash(Buffer.from(await artifactResponse.arrayBuffer())) !== claims[8]) {
      throw new Error('Lab artifact delivery changed the signed bytes.')
    }
    await fetch(`${base}/shutdown`, { method: 'POST', headers: authorization })
    await new Promise((resolveExit, reject) => {
      const timeout = setTimeout(() => reject(new Error('Updater lab server did not stop.')), 5_000)
      child.once('exit', () => { clearTimeout(timeout); resolveExit() })
    })
  } finally {
    if (child.exitCode === null) child.kill()
  }
}

await probe('good')
await probe('relabelled')
console.log('REL-003 updater VM lab structure, signatures, and loopback protocol verified.')
