import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { createHash, createPublicKey, verify } from 'node:crypto'
import { cp, mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

const run = promisify(execFile)
const toolsDirectory = path.dirname(fileURLToPath(import.meta.url))
const fictionalPrivateKey = 'FICTIONAL-UPDATER-PRIVATE-KEY-FOR-CONTRACT-TESTS'
const fictionalPublicKey = 'FICTIONAL-UPDATER-PUBLIC-KEY-FOR-CONTRACT-TESTS'

const mockedTauriCLI = `
import { createHash } from 'node:crypto'
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'

const [command, ...args] = process.argv.slice(2)
const option = (name) => args[args.indexOf(name) + 1]
const log = (entry) => appendFileSync(path.join(process.cwd(), 'tauri-calls.jsonl'), JSON.stringify(entry) + '\\n')

if (command === 'signer') {
  const keyPath = option('--write-keys')
  writeFileSync(keyPath, '${fictionalPrivateKey}\\n')
  writeFileSync(keyPath + '.pub', '${fictionalPublicKey}\\n')
  log({ command: 'signer', password: option('--password') })
} else if (command === 'build') {
  const overlay = JSON.parse(readFileSync(option('--config'), 'utf8'))
  const noSign = args.includes('--no-sign')
  log({
    command: 'build',
    version: overlay.version,
    noSign,
    updaterPublicKey: overlay.plugins.updater.pubkey,
    signingKeyPresent: process.env.TAURI_SIGNING_PRIVATE_KEY === '${fictionalPrivateKey}',
  })
  if (process.env.FICTIONAL_TAURI_FAILURE === 'new-build' && overlay.bundle.createUpdaterArtifacts) {
    console.error('fictional signed build failure')
    process.exit(3)
  }
  const directory = path.join(process.cwd(), 'src-tauri', 'target', 'release', 'bundle', 'nsis')
  mkdirSync(directory, { recursive: true })
  const installer = path.join(directory, 'Sesame_' + overlay.version + '_x64-setup.exe')
  writeFileSync(installer, 'fictional installer ' + overlay.version + '\\n')
  if (!noSign) {
    const digest = createHash('sha256').update(readFileSync(installer)).digest('hex')
    writeFileSync(installer + '.sig', 'fictional-signature-' + digest + '\\n')
  }
} else {
  process.exit(2)
}
`

async function fictionalWorkspace() {
  const root = await mkdtemp(path.join(tmpdir(), 'sesame-updater-lab-'))
  const tools = path.join(root, 'tools')
  await mkdir(tools, { recursive: true })
  for (const name of ['prepare-updater-vm-lab.mjs', 'serve-updater-vm-lab.mjs', 'verify-updater-vm-lab.mjs', 'release-set.mjs', 'release-evidence-lib.mjs']) {
    await cp(path.join(toolsDirectory, name), path.join(tools, name))
  }
  await cp(path.join(toolsDirectory, 'release-platforms'), path.join(tools, 'release-platforms'), { recursive: true })
  const cli = path.join(root, 'node_modules', '@tauri-apps', 'cli')
  await mkdir(cli, { recursive: true })
  await writeFile(path.join(cli, 'tauri.js'), mockedTauriCLI)
  await writeFile(path.join(root, 'package.json'), '{"type":"module"}\n')
  const release = path.join(root, 'src-tauri', 'target', 'release')
  await mkdir(release, { recursive: true })
  await writeFile(path.join(release, 'verify-updater-artifact.exe'), 'fictional verifier\n')
  await mkdir(path.join(root, 'release-artifacts'))
  return root
}

const prepare = (root, argument, environment = {}) => run(
  process.execPath,
  [path.join(root, 'tools', 'prepare-updater-vm-lab.mjs'), argument],
  { cwd: root, env: { ...process.env, ...environment } },
)

const readJSON = async (file) => JSON.parse(await readFile(file, 'utf8'))
const rawEd25519 = (value) => createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(value, 'base64url')]), format: 'der', type: 'spki' })
const exists = (file) => stat(file).then(() => true, () => false)

async function listFiles(directory) {
  const names = []
  for (const entry of await readdir(directory, { withFileTypes: true, recursive: true })) {
    if (entry.isFile()) names.push(path.join(entry.parentPath, entry.name))
  }
  return names
}

test('the updater lab preparer builds both installers, signs the receipt, and removes private material', async () => {
  const root = await fictionalWorkspace()
  try {
    const { stdout } = await prepare(root, 'release-artifacts/lab')
    const output = path.join(root, 'release-artifacts', 'lab')
    assert.match(stdout, /Created updater lab:/)

    const calls = (await readFile(path.join(root, 'tauri-calls.jsonl'), 'utf8')).trim().split('\n').map((line) => JSON.parse(line))
    assert.deepEqual(calls.map((call) => call.command), ['signer', 'build', 'build'])
    assert.equal(calls[1].version, '0.1.0')
    assert.equal(calls[1].noSign, true)
    assert.equal(calls[1].signingKeyPresent, false)
    assert.equal(calls[2].version, '0.1.1')
    assert.equal(calls[2].noSign, false)
    assert.equal(calls[2].signingKeyPresent, true)
    assert.equal(calls[1].updaterPublicKey, fictionalPublicKey)

    assert.deepEqual((await readdir(path.join(output, 'INSTALLERS'))).sort(), ['Sesame_0.1.0_updater-lab_x64-setup.exe', 'Sesame_0.1.1_updater-lab_x64-setup.exe'])
    assert.deepEqual((await readdir(path.join(output, 'UPDATER'))).sort(), ['Sesame_0.1.1_x64-setup.exe', 'Sesame_0.1.1_x64-setup.exe.sig'])
    assert.deepEqual(await readdir(path.join(output, 'TOOLS')), ['verify-updater-artifact.exe'])
    assert.equal(await exists(path.join(output, '.private-build-material')), false)
    for (const file of await listFiles(output)) {
      const text = await readFile(file, 'utf8')
      assert.ok(!text.includes(fictionalPrivateKey), `${path.relative(output, file)} carries the updater private key`)
      assert.ok(!text.includes('Fictional-REL003-Updater-Lab-Only'), `${path.relative(output, file)} carries the signing password`)
    }

    const keys = await readJSON(path.join(output, 'PUBLIC-KEYS.json'))
    const config = await readJSON(path.join(output, 'lab-config.json'))
    const good = await readJSON(path.join(output, 'PUBLIC', 'manifest-good.json'))
    const relabelled = await readJSON(path.join(output, 'PUBLIC', 'manifest-relabelled.json'))
    const installer = await readFile(path.join(output, 'UPDATER', 'Sesame_0.1.1_x64-setup.exe'))
    const installerSha256 = createHash('sha256').update(installer).digest('hex')
    const updaterSignature = (await readFile(path.join(output, 'UPDATER', 'Sesame_0.1.1_x64-setup.exe.sig'), 'utf8')).trim()

    assert.equal(keys.updaterPublicKey, fictionalPublicKey)
    assert.equal(good.version, '0.1.1')
    assert.equal(good.signature, updaterSignature)
    assert.equal(relabelled.version, '9.9.9')
    assert.deepEqual({ ...relabelled, version: '0.1.1' }, good)

    const lines = good.candidateReceipt.payload.split('\n')
    assert.equal(lines[0], 'sesame-release-set-candidate-v1')
    assert.equal(lines[1], '0.1.1')
    assert.equal(lines[7], config.releaseSetDigest)
    assert.match(config.releaseSetDigest, /^[0-9a-f]{64}$/)
    assert.equal(lines[13], installerSha256)
    assert.equal(lines[14], String(installer.length))
    assert.equal(lines[15], updaterSignature)
    assert.equal(good.candidateReceipt.signingKeyId, keys.candidateKeyID)
    assert.equal(
      verify(null, Buffer.from(good.candidateReceipt.payload), rawEd25519(keys.candidatePublicKey), Buffer.from(good.candidateReceipt.signature, 'base64url')),
      true,
    )

    const envelope = await readJSON(path.join(output, 'PUBLIC', 'capability-envelope.json'))
    assert.equal(
      verify(null, Buffer.from(envelope.payload, 'base64url'), rawEd25519(keys.capabilityPublicKey), Buffer.from(envelope.signature, 'base64url')),
      true,
    )
    assert.equal(JSON.parse(Buffer.from(envelope.payload, 'base64url').toString('utf8')).latestDesktopVersion, '0.1.1')
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('a failed signed build leaves no lab directory and no private material', async () => {
  const root = await fictionalWorkspace()
  try {
    await assert.rejects(prepare(root, 'release-artifacts/lab', { FICTIONAL_TAURI_FAILURE: 'new-build' }), /fictional signed build failure/)
    assert.equal(await exists(path.join(root, 'release-artifacts', 'lab')), false)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('the updater lab output must be a new directory under release-artifacts', async () => {
  const root = await fictionalWorkspace()
  try {
    for (const argument of ['elsewhere', '../escape', 'release-artifacts', 'release-artifacts/../escape']) {
      await assert.rejects(prepare(root, argument), /must be a new directory under release-artifacts/, argument)
    }
    await mkdir(path.join(root, 'release-artifacts', 'taken'))
    await assert.rejects(prepare(root, 'release-artifacts/taken'), /EEXIST/)
    assert.equal(await exists(path.join(root, 'tauri-calls.jsonl')), false)
    assert.equal(await exists(path.join(root, 'release-artifacts', 'taken')), true)
  } finally { await rm(root, { recursive: true, force: true }) }
})
