import { randomBytes } from 'node:crypto'
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { architectureName, launchApp, openBridge, platformName, recordStep, sha256, stopApp, summarize } from './desktop-e2e-bridge.mjs'
import { buildCompatibilityMatrix, loadFixtureManifest, repositoryRoot, RUN_SCHEMA } from './vault-compatibility-gate.mjs'

const binaryPattern = /^[0-9a-f]{64}$/

function parseArguments(argv) {
  const options = {}
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    if (argument === '--binary') options.binary = argv[++index]
    else if (argument === '--out') options.out = argv[++index]
    else if (argument === '--work-root') options.workRoot = argv[++index]
    else if (argument === '--fixtures') options.fixtures = argv[++index].split(',').map((value) => value.trim()).filter(Boolean)
    else if (argument === '--repo') options.repo = argv[++index]
    else if (argument === '--keep') options.keep = true
    else throw new Error(`Unknown argument: ${argument}`)
  }
  if (!options.binary || !options.out) {
    throw new Error('Usage: node tools/run-vault-restore-gate.mjs --binary <app> --out <report-directory> [--fixtures v0.1.0,v0.2.2] [--work-root <directory>] [--repo <directory>] [--keep]')
  }
  return options
}

async function runRestorePhase(bridge, { root, fixture, manifestEntry }) {
  const steps = []
  const password = manifestEntry.secrets.masterPassword

  recordStep(steps, 'status.before', await bridge.call('get_vault_status', {}))
  recordStep(steps, 'create_vault', await bridge.call('create_vault', { request: { masterPassword: 'fictional validation password' } }))

  const firstBackup = recordStep(steps, 'backup.before_restore', await bridge.call('create_backup', {}))
  if (firstBackup.ok) {
    const backupPath = path.join(root, 'backups', firstBackup.value)
    recordStep(steps, 'backup.before_restore.exists', { ok: (await stat(backupPath).catch(() => null))?.isFile() === true })
  }

  const beforeDigest = sha256(await readFile(fixture))
  const restored = recordStep(steps, 'restore_backup', await bridge.call('restore_backup', { request: { source: fixture, secret: password } }))
  const safetyName = restored.value?.safetyBackupName
  recordStep(steps, 'safety_backup.exists', {
    ok: Boolean(safetyName) && (await stat(path.join(root, 'backups', safetyName ?? '')).catch(() => null))?.isFile() === true,
    safetyBackupName: safetyName,
  })
  recordStep(steps, 'restore.source_unchanged', { ok: sha256(await readFile(fixture)) === beforeDigest })

  recordStep(steps, 'lock.before_unlock', await bridge.call('lock_vault', {}))
  const unlocked = recordStep(steps, 'unlock.password', await bridge.call('unlock_vault', { request: { masterPassword: password } }))
  const snapshot = unlocked.value ?? {}
  recordStep(steps, 'unlock.password.counts', {
    ok: snapshot.entries?.length === manifestEntry.counts.entries
      && snapshot.folders?.length === manifestEntry.counts.folders
      && snapshot.vaultName === manifestEntry.vault.name,
    value: { entries: snapshot.entries?.length, folders: snapshot.folders?.length, vaultName: snapshot.vaultName },
  })

  const newBackup = recordStep(steps, 'backup.restored', await bridge.call('create_backup', {}))
  if (newBackup.ok) {
    const backupPath = path.join(root, 'backups', newBackup.value)
    const verification = recordStep(steps, 'verify.restored_backup', await bridge.call('verify_backup', { request: { source: backupPath, secret: password } }))
    const fields = verification.value ?? {}
    recordStep(steps, 'verify.restored_backup.fields', {
      ok: fields.entryCount === manifestEntry.counts.entries
        && fields.formatVersion === manifestEntry.formatVersion
        && fields.vaultName === manifestEntry.vault.name,
      value: { entryCount: fields.entryCount, formatVersion: fields.formatVersion, vaultName: fields.vaultName },
    })
  }
  recordStep(steps, 'lock.restored', await bridge.call('lock_vault', {}))
  return steps
}

async function runRestartPhase(bridge, { root, manifestEntry }) {
  const steps = []
  const password = manifestEntry.secrets.masterPassword
  const kit = manifestEntry.secrets.recoveryKit

  const status = recordStep(steps, 'status.after_restart', await bridge.call('get_vault_status', {}))
  recordStep(steps, 'status.after_restart.locked', {
    ok: status.value?.exists === true && status.value?.unlocked === false,
    value: { exists: status.value?.exists, unlocked: status.value?.unlocked },
  })
  recordStep(steps, 'restart.unlock.password', await bridge.call('unlock_vault', { request: { masterPassword: password } }))
  recordStep(steps, 'restart.lock', await bridge.call('lock_vault', {}))
  recordStep(steps, 'restart.unlock.recovery_kit', await bridge.call('unlock_recovery_vault', { request: { recoveryKit: kit } }))

  const header = JSON.parse(await readFile(path.join(root, 'vault.sesame'), 'utf8'))
  recordStep(steps, 'active_vault.header', {
    ok: header.formatVersion === manifestEntry.formatVersion
      && header.setupComplete === true
      && header.recoveryWrap !== null
      && header.recoveryKdf !== null,
    value: {
      formatVersion: header.formatVersion,
      setupComplete: header.setupComplete,
      recoveryWrap: header.recoveryWrap !== null,
      recoveryKdf: header.recoveryKdf !== null,
    },
  })
  return steps
}

async function runPhases({ binary, root, phase, fixture, manifestEntry, logPath }) {
  const log = []
  const bridge = await openBridge(`vault-gate-${randomBytes(16).toString('hex')}`)
  const child = launchApp({ binary, root, bridge, log })
  try {
    if (!(await bridge.waitForConnection())) {
      throw new Error('The app never connected to the installed-app bridge. It is missing the test bridge or failed to start.')
    }
    return phase === 'restore'
      ? await runRestorePhase(bridge, { root, fixture, manifestEntry })
      : await runRestartPhase(bridge, { root, manifestEntry })
  } finally {
    await stopApp(child)
    bridge.close()
    await writeFile(logPath, log.join(''))
  }
}

export async function runVaultRestoreGate(options) {
  const repo = options.repo ? path.resolve(options.repo) : repositoryRoot
  const out = path.resolve(options.out)
  await mkdir(out, { recursive: true })

  const binary = path.resolve(options.binary)
  const binaryInfo = await stat(binary).catch(() => null)
  if (!binaryInfo?.isFile()) throw new Error(`The installed-app binary is missing: ${binary}`)
  const binarySha256 = sha256(await readFile(binary))
  if (!binaryPattern.test(binarySha256)) throw new Error('The installed-app binary digest is invalid.')

  const { matrix, matrixDigest } = await buildCompatibilityMatrix(repo)
  const { manifest } = await loadFixtureManifest(repo)
  const fixtureIds = options.fixtures ?? matrix.publishedVersions.map((version) => version.fixtureId)
  const version = JSON.parse(await readFile(path.join(repo, 'package.json'), 'utf8')).version
  const platform = platformName()
  const architecture = architectureName()
  const workRoot = options.workRoot ? path.resolve(options.workRoot) : await mkdtemp(path.join(tmpdir(), 'sesame-vault-gate-'))
  await mkdir(workRoot, { recursive: true })

  const runs = []
  let failed = 0
  for (const fixtureId of fixtureIds) {
    const published = matrix.publishedVersions.find((entry) => entry.fixtureId === fixtureId)
    if (!published) throw new Error(`The compatibility matrix has no published release ${fixtureId}.`)
    const manifestEntry = manifest.fixtures.find((entry) => entry.id === fixtureId)
    const fixture = path.join(repo, 'src-tauri/sesame-core/tests/fixtures/compatibility', published.fixtureFileName)
    const fixtureBytes = await readFile(fixture)
    if (sha256(fixtureBytes) !== published.fixtureDigestSha256) throw new Error(`Fixture ${fixtureId} does not match the recorded digest.`)

    const root = path.join(workRoot, fixtureId)
    await rm(root, { recursive: true, force: true })
    await mkdir(root, { recursive: true })
    const startedAt = new Date().toISOString()
    let phases
    try {
      const restoreSteps = await runPhases({
        binary, root, phase: 'restore', fixture, manifestEntry,
        logPath: path.join(out, `${platform}-${fixtureId}-restore.log`),
      })
      const restartSteps = await runPhases({
        binary, root, phase: 'restart', fixture, manifestEntry,
        logPath: path.join(out, `${platform}-${fixtureId}-restart.log`),
      })
      phases = { restore: await summarize(restoreSteps), restart: await summarize(restartSteps) }
    } catch (error) {
      phases = {
        restore: phases?.restore ?? { passed: 0, failed: 1, steps: [{ name: 'phase', ok: false, error: String(error.message ?? error) }] },
        restart: phases?.restart ?? { passed: 0, failed: 1, steps: [{ name: 'phase', ok: false, error: String(error.message ?? error) }] },
      }
    }
    const passed = phases.restore.failed === 0 && phases.restart.failed === 0
    if (!passed) failed += 1
    const record = {
      schema: RUN_SCHEMA,
      platform,
      architecture,
      version,
      buildKind: 'tauri-wdio-test-build',
      matrixDigest,
      fixtureManifestSha256: matrix.fixtureManifestSha256,
      fixtureId,
      fixtureSha256: published.fixtureDigestSha256,
      binarySha256,
      phases,
      result: passed ? 'passed' : 'failed',
      skipped: false,
      startedAt,
      finishedAt: new Date().toISOString(),
    }
    const reportPath = path.join(out, `${platform}-${fixtureId}.json`)
    const report = `${JSON.stringify(record, null, 2)}\n`
    await writeFile(reportPath, report)
    runs.push({ fixtureId, result: record.result, reportPath, reportSha256: sha256(report), phases: record.phases })
    process.stdout.write(`${platform} ${fixtureId}: restore ${phases.restore.passed}/${phases.restore.passed + phases.restore.failed}, restart ${phases.restart.passed}/${phases.restart.passed + phases.restart.failed}\n`)
  }

  if (!options.keep) await rm(workRoot, { recursive: true, force: true })
  return { failed, runs, binarySha256, matrixDigest, fixtureManifestSha256: matrix.fixtureManifestSha256 }
}

async function main() {
  const options = parseArguments(process.argv.slice(2))
  const { failed } = await runVaultRestoreGate(options)
  return failed === 0 ? 0 : 1
}

const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
if (invokedDirectly) {
  main().then((code) => {
    process.exitCode = code
  }).catch((error) => {
    process.stderr.write(`${error.stack ?? error}\n`)
    process.exitCode = 2
  })
}
