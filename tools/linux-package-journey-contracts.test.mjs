import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { EventEmitter } from 'node:events'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { evidenceStep, judgeAppStop, recordStep, sha256, stopApp } from './desktop-e2e-bridge.mjs'
import {
  PACKAGE_RUN_SCHEMA,
  driveFirstSession,
  driveRestartSession,
  journeyEditedPassword,
  journeyLogin,
  journeyMasterPassword,
  judgeLoginGone,
  judgeLoginReadBack,
  loginInput,
  requiredPackageSteps,
  validateLinuxPackageEvidence,
} from './linux-installed-package-gate.mjs'
import {
  SHIPPED_RUN_SCHEMA,
  judgePreviousDigest,
  judgeUpgradedVersion,
  judgeVersionOrder,
  parseChecksums,
  requiredShippedSteps,
  requiredUpgradeSteps,
  validateLinuxShippedEvidence,
  verifyPreviousPackage,
} from './linux-shipped-package-gate.mjs'
import { selectPreviousLinuxRelease } from './previous-linux-release.mjs'

const repository = process.cwd()
const journeyStepNames = ['login.save', 'vault.backup.verified', 'vault.backup.entries', 'vault.lock', 'vault.unlock', 'login.read_after_unlock', 'restart.unlock', 'restart.login.read', 'login.edit', 'login.read_after_edit', 'login.delete', 'login.gone', 'login.gone_after_unlock']
const secrets = [journeyMasterPassword, journeyLogin.password, journeyEditedPassword, journeyLogin.title, journeyLogin.username, journeyLogin.url]

function fakeApp(faults = {}) {
  const items = new Map()
  const state = { exists: false, unlocked: false, presence: false, calls: [], saves: [] }
  const listing = () => ({ entries: [...items.keys()].map((id) => ({ id, title: items.get(id).title })) })
  const locked = { ok: false, error: 'Unlock your vault first.' }
  const handlers = {
    get_vault_status: () => ({ ok: true, value: { exists: state.exists, unlocked: state.unlocked } }),
    create_vault: () => {
      state.exists = true
      state.unlocked = true
      return { ok: true, value: {} }
    },
    get_vault_snapshot: () => (state.unlocked ? { ok: true, value: listing() } : locked),
    save_login: ({ input }) => {
      if (!state.unlocked) return locked
      if (faults.rejectSave) return { ok: false, error: 'Sesame could not save the login.' }
      state.saves.push(input)
      const id = input.id ?? 'login-1'
      const previous = items.get(id)
      const password = previous && faults.ignoreEdit ? previous.password : input.password + (faults.corruptSave && !previous ? '-changed' : '')
      items.set(id, { title: input.title, url: input.url, username: input.username, password })
      return { ok: true, value: { id: faults.secondCopyOnEdit && previous ? 'login-2' : id, snapshot: listing() } }
    },
    create_backup: () => ({ ok: true, value: 'backup-fictional.sesame' }),
    verify_backup: () => ({ ok: true, value: { entryCount: faults.emptyBackup ? 0 : items.size } }),
    lock_vault: () => {
      state.unlocked = false
      state.presence = false
      return { ok: true }
    },
    unlock_vault: ({ request }) => {
      if (request.masterPassword !== journeyMasterPassword) return { ok: false, error: 'That master password did not unlock the vault.' }
      state.unlocked = true
      return { ok: true, value: listing() }
    },
    get_login_card: ({ id }) => {
      if (!state.unlocked) return locked
      const item = items.get(id)
      return item ? { ok: true, value: { id, title: item.title, url: item.url, username: item.username, hasPassword: item.password.length > 0 } } : { ok: false, error: 'That saved item no longer exists.' }
    },
    grant_presence: ({ secret }) => {
      state.presence = state.unlocked && secret === journeyMasterPassword
      return state.presence ? { ok: true } : { ok: false, error: 'The password was not accepted.' }
    },
    reveal_login_secret: ({ id }) => {
      if (!state.presence) return { ok: false, error: 'presenceRequired' }
      const item = items.get(id)
      return item ? { ok: true, value: item.password } : { ok: false, error: 'That saved login no longer exists.' }
    },
    delete_login: ({ id }) => {
      if (!state.unlocked) return locked
      if (!faults.keepAfterDelete) items.delete(id)
      state.presence = false
      return { ok: true, value: { deletedId: id, snapshot: listing() } }
    },
  }
  return {
    state,
    restart() {
      state.unlocked = false
      state.presence = false
    },
    async call(command, args) {
      state.calls.push(command)
      const handler = handlers[command]
      return handler ? handler(args ?? {}) : { ok: false, error: `${command} is not a command` }
    },
  }
}

async function runJourney(faults) {
  const app = fakeApp(faults)
  const journey = { loginId: null, baselineEntries: null }
  const steps = []
  await driveFirstSession({ bridge: app, steps, journey, vaultRoot: '/fictional/vault' })
  app.restart()
  await driveRestartSession({ bridge: app, steps, journey })
  return { app, steps }
}

const stepsNamed = (steps, name) => steps.filter((step) => step.name === name)
const failedNames = (steps) => steps.filter((step) => !step.ok).map((step) => step.name)

test('the journey saves a login, reads it back after unlock and restart, edits it, and deletes it', async () => {
  const { app, steps } = await runJourney()
  assert.deepEqual(failedNames(steps), [])
  for (const name of journeyStepNames) assert.equal(stepsNamed(steps, name).length, 1, `${name} was not recorded once`)
  assert.equal(app.state.saves.length, 2)
  const [first, second] = app.state.saves
  assert.equal(first.id, undefined)
  assert.equal(first.title, journeyLogin.title)
  assert.equal(first.username, journeyLogin.username)
  assert.equal(first.url, journeyLogin.url)
  assert.equal(first.password, journeyLogin.password)
  assert.equal(second.id, 'login-1')
  assert.equal(second.password, journeyEditedPassword)
  assert.ok(app.state.calls.indexOf('save_login') < app.state.calls.indexOf('create_backup'), 'the backup must be taken after the login is saved')
})

test('every journey step is required by the installed-package record', () => {
  for (const name of journeyStepNames.filter((entry) => !entry.startsWith('vault.lock') && entry !== 'vault.unlock')) {
    assert.ok(requiredPackageSteps.includes(name), `${name} is not required`)
  }
  assert.ok(requiredPackageSteps.includes('app.stop'))
  assert.ok(requiredPackageSteps.includes('restart.stop'))
})

test('the login payload carries every field the Rust command expects', () => {
  const input = loginInput(journeyLogin, 'login-7')
  assert.deepEqual(Object.keys(input).sort(), ['backupCodes', 'email', 'folder', 'id', 'keepBackupCodes', 'notes', 'password', 'recoveryEmail', 'recoveryNotApplicable', 'recoveryPhone', 'tags', 'title', 'url', 'urls', 'username'])
  assert.equal(loginInput(journeyLogin).id, undefined)
})

test('the journey uses only commands the desktop registers and permits', async () => {
  const handler = await readFile(path.join(repository, 'src-tauri', 'src', 'lib.rs'), 'utf8')
  const permissions = await readFile(path.join(repository, 'src-tauri', 'permissions', 'desktop.toml'), 'utf8')
  const { app } = await runJourney()
  for (const command of new Set(app.state.calls)) {
    assert.match(handler, new RegExp(`commands::${command},`), `${command} is not registered`)
    assert.match(permissions, new RegExp(`"${command}"`), `${command} is not permitted`)
  }
})

test('a saved login that reads back with a different password fails the journey', async () => {
  const { steps } = await runJourney({ corruptSave: true })
  const failed = failedNames(steps)
  assert.ok(failed.includes('login.read_after_unlock'))
  assert.ok(failed.includes('restart.login.read'))
  const reading = stepsNamed(steps, 'login.read_after_unlock')[0]
  assert.match(reading.error, /differently in these fields: password\./)
  for (const secret of secrets) assert.ok(!JSON.stringify(steps.map(evidenceStep)).includes(secret), 'a secret reached the evidence record')
})

test('an edit that is not stored fails the journey', async () => {
  const { steps } = await runJourney({ ignoreEdit: true })
  assert.deepEqual(failedNames(steps), ['login.read_after_edit'])
  assert.match(stepsNamed(steps, 'login.read_after_edit')[0].error, /password/)
})

test('an edit that saves a second login instead of updating fails the journey', async () => {
  const { steps } = await runJourney({ secondCopyOnEdit: true })
  assert.ok(failedNames(steps).includes('login.edit'))
})

test('a login that is still present after the delete fails the journey', async () => {
  const { steps } = await runJourney({ keepAfterDelete: true })
  assert.deepEqual(failedNames(steps), ['login.gone', 'login.gone_after_unlock'])
  assert.match(stepsNamed(steps, 'login.gone')[0].error, /still listed/)
})

test('a login that cannot be saved fails every step that depends on it', async () => {
  const { steps } = await runJourney({ rejectSave: true })
  const failed = failedNames(steps)
  for (const name of ['login.save', 'login.read_after_unlock', 'restart.login.read', 'login.edit', 'login.read_after_edit', 'login.delete', 'login.gone']) {
    assert.ok(failed.includes(name), `${name} passed without a saved login`)
  }
})

test('a backup that does not hold the saved login fails the journey', async () => {
  const { steps } = await runJourney({ emptyBackup: true })
  assert.deepEqual(failedNames(steps), ['vault.backup.entries'])
})

test('the read back names the differing fields and never prints their values', () => {
  const card = { title: journeyLogin.title, url: 'https://elsewhere.example', username: journeyLogin.username, hasPassword: true }
  const judged = judgeLoginReadBack(journeyLogin, card, 'fictional-other-password')
  assert.equal(judged.ok, false)
  assert.equal(judged.error, 'The saved login read back differently in these fields: url, password.')
  assert.equal(judgeLoginReadBack(journeyLogin, { ...card, url: journeyLogin.url }, journeyLogin.password).ok, true)
  assert.equal(judgeLoginReadBack(journeyLogin, { ...card, url: journeyLogin.url, hasPassword: false }, journeyLogin.password).ok, false)
  assert.equal(judgeLoginReadBack(journeyLogin, undefined, undefined).ok, false)
})

test('a login counts as gone only when it is unlisted and the vault says it no longer exists', () => {
  const missing = { ok: false, error: 'That saved item no longer exists.' }
  assert.equal(judgeLoginGone({ id: 'login-1', snapshot: { entries: [] }, card: missing }).ok, true)
  assert.equal(judgeLoginGone({ id: 'login-1', snapshot: { entries: [{ id: 'login-1' }] }, card: missing }).ok, false)
  assert.equal(judgeLoginGone({ id: 'login-1', snapshot: { entries: [] }, card: { ok: true, value: {} } }).ok, false)
  assert.equal(judgeLoginGone({ id: 'login-1', snapshot: { entries: [] }, card: { ok: false, error: 'Unlock your vault first.' } }).ok, false)
  assert.equal(judgeLoginGone({ id: 'login-1', snapshot: undefined, card: missing }).ok, false)
  assert.equal(judgeLoginGone({ id: null, snapshot: { entries: [] }, card: missing }).ok, false)
})

test('the evidence record keeps no login, password, or vault value', async () => {
  const { steps } = await runJourney()
  const record = JSON.stringify(steps.map(evidenceStep))
  for (const secret of secrets) assert.ok(!record.includes(secret), 'a secret reached the evidence record')
  assert.ok(!record.includes('login-1'), 'an item identifier reached the evidence record')
  const kept = evidenceStep(recordStep([], 'login.save', { ok: true, value: { id: 'login-1' } }))
  assert.deepEqual(kept, { name: 'login.save', ok: true })
  assert.deepEqual(evidenceStep({ name: 'app.stop', ok: true, value: { exitCode: 0 }, evidence: true }), { name: 'app.stop', ok: true, value: { exitCode: 0 } })
})

function installedRecord(overrides = {}) {
  return {
    schema: PACKAGE_RUN_SCHEMA,
    platform: 'linux',
    architecture: 'x86_64',
    version: '1.2.3',
    buildKind: 'tauri-wdio-test-package',
    installKind: 'dpkg',
    package: { filename: 'Sesame_1.2.3_amd64.deb', sha256: 'a'.repeat(64), bytes: 1024, name: 'sesame', version: '1.2.3', architecture: 'amd64' },
    binarySha256: 'b'.repeat(64),
    steps: requiredPackageSteps.map((name) => ({ name, ok: true })),
    restore: { failed: 0, runs: ['v0.1.0', 'v0.1.1', 'v0.2.0', 'v0.2.1', 'v0.2.2'].map((fixtureId) => ({ fixtureId, result: 'passed', reportSha256: 'c'.repeat(64) })) },
    result: 'passed',
    skipped: false,
    startedAt: '2026-09-13T00:00:00.000Z',
    finishedAt: '2026-09-13T00:30:00.000Z',
    ...overrides,
  }
}

test('an installed-package record without a passing journey step is not evidence', () => {
  assert.equal(validateLinuxPackageEvidence(installedRecord()).result, 'passed')
  for (const name of ['login.save', 'login.read_after_unlock', 'restart.login.read', 'login.read_after_edit', 'login.gone', 'app.stop', 'restart.stop']) {
    const failed = installedRecord({ steps: requiredPackageSteps.map((entry) => ({ name: entry, ok: entry !== name })) })
    assert.throws(() => validateLinuxPackageEvidence(failed), new RegExp(`did not pass ${name.replace('.', '\\.')}`))
    const missing = installedRecord({ steps: requiredPackageSteps.filter((entry) => entry !== name).map((entry) => ({ name: entry, ok: true })) })
    assert.throws(() => validateLinuxPackageEvidence(missing), new RegExp(`did not pass ${name.replace('.', '\\.')}`))
  }
})

function fakeChild(onSignal) {
  const child = new EventEmitter()
  child.pid = 2_147_483_000
  child.exitCode = null
  child.signalCode = null
  child.end = (exitCode, signalCode = null) => {
    child.exitCode = exitCode
    child.signalCode = signalCode
    child.emit('exit', exitCode, signalCode)
  }
  child.signals = []
  child.signalGroup = async (target, signal) => {
    target.signals.push(signal)
    onSignal(target, signal)
  }
  return child
}

const quickStop = { timeoutMs: 30, killTimeoutMs: 30 }

test('an app that ends after the stop signal records its exit status and passes', async () => {
  const child = fakeChild((target, signal) => {
    if (signal === 'SIGTERM') setTimeout(() => target.end(0), 5)
  })
  const stop = await stopApp(child, { ...quickStop, signalGroup: child.signalGroup })
  assert.deepEqual(child.signals, ['SIGTERM'])
  assert.equal(stop.signalled, true)
  assert.equal(stop.ended, true)
  assert.equal(stop.killed, false)
  assert.equal(stop.exitCode, 0)
  const judged = judgeAppStop(stop)
  assert.equal(judged.ok, true)
  assert.equal(judged.value.exitCode, 0)
  assert.equal(typeof judged.value.milliseconds, 'number')
})

test('an app that ends by the signal itself passes with its signal recorded', async () => {
  const child = fakeChild((target) => setTimeout(() => target.end(null, 'SIGTERM'), 5))
  const judged = judgeAppStop(await stopApp(child, { ...quickStop, signalGroup: child.signalGroup }))
  assert.equal(judged.ok, true)
  assert.equal(judged.value.signalCode, 'SIGTERM')
})

test('an app that ignores the stop signal fails the stop even when the kill ends it', async () => {
  const child = fakeChild((target, signal) => {
    if (signal === 'SIGKILL') setTimeout(() => target.end(null, 'SIGKILL'), 5)
  })
  const stop = await stopApp(child, { ...quickStop, signalGroup: child.signalGroup })
  assert.deepEqual(child.signals, ['SIGTERM', 'SIGKILL'])
  assert.equal(stop.ended, false)
  assert.equal(stop.killed, true)
  const judged = judgeAppStop(stop)
  assert.equal(judged.ok, false)
  assert.match(judged.error, /did not end within 30 ms/)
  assert.equal(judged.value.signalCode, 'SIGKILL')
})

test('an app that survives the kill as well fails the stop', async () => {
  const child = fakeChild(() => {})
  const judged = judgeAppStop(await stopApp(child, { ...quickStop, signalGroup: child.signalGroup }))
  assert.equal(judged.ok, false)
  assert.equal(judged.value.ended, false)
})

test('an app that crashes while stopping or had already gone does not pass', async () => {
  const crashing = fakeChild((target) => setTimeout(() => target.end(null, 'SIGSEGV'), 5))
  assert.match(judgeAppStop(await stopApp(crashing, { ...quickStop, signalGroup: crashing.signalGroup })).error, /crashed with SIGSEGV/)
  const gone = fakeChild(() => {})
  gone.end(1)
  const stop = await stopApp(gone, { ...quickStop, signalGroup: gone.signalGroup })
  assert.deepEqual(gone.signals, [])
  assert.equal(stop.signalled, false)
  assert.equal(judgeAppStop(stop).ok, false)
  assert.equal(judgeAppStop(undefined).ok, false)
})

async function realChild(script) {
  const child = spawn(process.execPath, ['-e', script], { stdio: ['ignore', 'pipe', 'ignore'], detached: true })
  await new Promise((resolve) => child.stdout.once('data', resolve))
  return child
}

test('a real process that ignores SIGTERM is reported as killed, and one that obeys is not', { skip: process.platform === 'win32' }, async () => {
  const stubborn = await realChild('process.on("SIGTERM", () => {}); setInterval(() => {}, 1000); process.stdout.write("ready")')
  const stubbornJudged = judgeAppStop(await stopApp(stubborn, { timeoutMs: 300, killTimeoutMs: 3000 }))
  assert.equal(stubbornJudged.ok, false)
  assert.equal(stubbornJudged.value.killed, true)
  assert.equal(stubbornJudged.value.signalCode, 'SIGKILL')
  const obedient = await realChild('setInterval(() => {}, 1000); process.stdout.write("ready")')
  const obedientJudged = judgeAppStop(await stopApp(obedient, { timeoutMs: 3000 }))
  assert.equal(obedientJudged.ok, true)
  assert.equal(obedientJudged.value.signalCode, 'SIGTERM')
})

test('the shipped gates record the stop they observed', async () => {
  const source = await readFile(path.join(repository, 'tools', 'linux-shipped-package-gate.mjs'), 'utf8')
  assert.doesNotMatch(source, /record\(steps, 'app\.stop', true\)/)
  assert.equal((source.match(/recordStop\(steps, 'app\.stop', stop\)/g) ?? []).length, 3)
  const installed = await readFile(path.join(repository, 'tools', 'linux-installed-package-gate.mjs'), 'utf8')
  assert.match(installed, /recordStop\(steps, 'app\.stop', await stopApp\(child\)\)/)
  assert.match(installed, /recordStop\(steps, 'restart\.stop', await stopApp\(child\)\)/)
})

const fictionalDeb = Buffer.from('fictional previous package bytes')
const fictionalName = 'Sesame_0.0.1_amd64.deb'
const sumsFor = (digest, name = fictionalName) => `${'0'.repeat(64)}  other-file.json\n${digest}  ${name}\n`

test('the previous package must match the digest its release lists', () => {
  const digest = sha256(fictionalDeb)
  assert.deepEqual(judgePreviousDigest({ filename: fictionalName, bytes: fictionalDeb, checksums: sumsFor(digest) }), { ok: true, value: { filename: fictionalName, sha256: digest } })
  const mismatch = judgePreviousDigest({ filename: fictionalName, bytes: fictionalDeb, checksums: sumsFor('f'.repeat(64)) })
  assert.equal(mismatch.ok, false)
  assert.match(mismatch.error, new RegExp(`has digest ${digest}, but the previous release checksums list ${'f'.repeat(64)}`))
  assert.equal(judgePreviousDigest({ filename: fictionalName, bytes: fictionalDeb, checksums: sumsFor(digest, 'Sesame_0.0.2_amd64.deb') }).ok, false)
  assert.equal(judgePreviousDigest({ filename: fictionalName, bytes: fictionalDeb, checksums: '' }).ok, false)
  assert.equal(judgePreviousDigest({ filename: fictionalName, bytes: fictionalDeb, checksums: `${digest.slice(1)}  ${fictionalName}\n` }).ok, false)
})

test('the checksum reader accepts binary markers and ignores paths and malformed lines', () => {
  const digest = 'a'.repeat(64)
  const entries = parseChecksums(`${digest} *plain.deb\n${digest}  nested/path.deb\n${digest}  ..\\\\evil.deb\nnot a checksum line\n${digest.toUpperCase()}  upper.deb\n`)
  assert.deepEqual([...entries.keys()].sort(), ['plain.deb', 'upper.deb'])
  assert.equal(entries.get('upper.deb'), digest)
})

test('a previous package with the wrong digest is refused before anything installs it', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'sesame-previous-package-'))
  try {
    const previousPath = path.join(directory, fictionalName)
    const sumsPath = path.join(directory, 'SHA256SUMS-linux')
    await writeFile(previousPath, fictionalDeb)
    await writeFile(sumsPath, sumsFor('e'.repeat(64)))
    const refused = []
    await assert.rejects(verifyPreviousPackage(refused, { previousPath, sumsPath }), /previous release checksums list e{64}/)
    assert.equal(refused.length, 1)
    assert.equal(refused[0].name, 'upgrade.previous_digest')
    assert.equal(refused[0].ok, false)
    await writeFile(sumsPath, sumsFor(sha256(fictionalDeb)))
    const accepted = []
    assert.deepEqual(await verifyPreviousPackage(accepted, { previousPath, sumsPath }), fictionalDeb)
    assert.equal(accepted[0].ok, true)
    await assert.rejects(verifyPreviousPackage([], { previousPath, sumsPath: path.join(directory, 'missing') }))
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
})

test('the upgrade must leave the candidate version installed', () => {
  assert.equal(judgeUpgradedVersion({ installedVersion: '1.2.3', expectedVersion: '1.2.3' }).ok, true)
  assert.match(judgeUpgradedVersion({ installedVersion: '1.2.2', expectedVersion: '1.2.3' }).error, /1\.2\.2 after the upgrade, not 1\.2\.3/)
  assert.equal(judgeUpgradedVersion({ installedVersion: '', expectedVersion: '1.2.3' }).ok, false)
})

function shippedRecord(overrides = {}) {
  return {
    schema: SHIPPED_RUN_SCHEMA,
    format: 'deb',
    platform: 'linux',
    architecture: 'x86_64',
    version: '1.2.3',
    installKind: 'dpkg',
    package: { filename: 'Sesame_1.2.3_amd64.deb', sha256: 'a'.repeat(64), bytes: 1024, name: 'sesame', version: '1.2.3', architecture: 'amd64' },
    previousPackage: null,
    binarySha256: 'b'.repeat(64),
    steps: requiredShippedSteps.map((name) => ({ name, ok: true })),
    result: 'passed',
    skipped: false,
    startedAt: '2026-09-13T00:00:00.000Z',
    finishedAt: '2026-09-13T00:05:00.000Z',
    ...overrides,
  }
}

test('a record that names a previous package needs every upgrade step to pass', () => {
  const previousPackage = { filename: fictionalName, sha256: 'c'.repeat(64), bytes: 10, name: 'sesame', version: '0.0.1', architecture: 'amd64' }
  const steps = [...requiredShippedSteps, ...requiredUpgradeSteps]
  assert.equal(validateLinuxShippedEvidence(shippedRecord({ previousPackage, steps: steps.map((name) => ({ name, ok: true })) })).result, 'passed')
  for (const name of ['upgrade.previous_digest', 'upgrade.version_order', 'upgrade.previous_stop', 'upgrade.candidate_installed', 'upgrade.candidate_launch', 'upgrade.candidate_stop']) {
    assert.ok(requiredUpgradeSteps.includes(name), `${name} is not required`)
    const failed = shippedRecord({ previousPackage, steps: steps.map((entry) => ({ name: entry, ok: entry !== name })) })
    assert.throws(() => validateLinuxShippedEvidence(failed), new RegExp(`did not pass ${name.replace('.', '\\.')}`))
  }
  assert.throws(() => validateLinuxShippedEvidence(shippedRecord({ previousPackage, steps: requiredShippedSteps.map((name) => ({ name, ok: true })) })), /did not pass upgrade\.previous_digest/)
})

test('the shipped gate needs the previous release checksums whenever it is given a previous package', async () => {
  const gate = path.join(repository, 'tools', 'linux-shipped-package-gate.mjs')
  const run = (...args) => new Promise((resolve) => {
    const child = spawn(process.execPath, [gate, ...args], { stdio: ['ignore', 'ignore', 'pipe'] })
    const errors = []
    child.stderr.on('data', (chunk) => errors.push(chunk))
    child.on('close', (code) => resolve({ code, stderr: Buffer.concat(errors).toString('utf8') }))
  })
  const withoutSums = await run('--package', 'Sesame_1.2.3_amd64.deb', '--out', 'unused', '--previous', fictionalName)
  assert.equal(withoutSums.code, 2)
  assert.match(withoutSums.stderr, /needs --previous-sums/)
  const sumsAlone = await run('--package', 'Sesame_1.2.3_amd64.deb', '--out', 'unused', '--previous-sums', 'SHA256SUMS-linux')
  assert.equal(sumsAlone.code, 2)
  assert.match(sumsAlone.stderr, /only applies together with --previous/)
})

function workflowStep(workflow, jobStart, jobEnd, marker) {
  const job = workflow.slice(workflow.indexOf(jobStart), jobEnd ? workflow.indexOf(jobEnd) : undefined)
  const step = job.split('\n      - ').find((entry) => entry.includes(marker))
  assert.ok(step, `no step contains ${marker}`)
  return step
}

test('both Linux workflows prove the upgrade from the newest older published release with a read-only token', async () => {
  for (const [file, jobStart, jobEnd] of [['ci.yml', '  linux-bundles:', '  linux-installed:'], ['release-linux-early-access.yml', '\n  build-and-test:\n', '\n  sign-and-attest:\n']]) {
    const workflow = await readFile(path.join(repository, '.github', 'workflows', file), 'utf8')
    const step = workflowStep(workflow, jobStart, jobEnd, '--previous ')
    assert.match(step, /GH_TOKEN: \$\{\{ github\.token \}\}/, `${file} does not use the job token`)
    assert.match(step, /version=\$\(node -p "require\('\.\/package\.json'\)\.version"\)/, `${file} does not take the candidate version from package.json`)
    assert.match(step, /gh api --paginate --slurp "repos\/\$GITHUB_REPOSITORY\/releases" > previous-releases\.json/, `${file} does not list every release`)
    assert.match(step, /tag=\$\(node tools\/previous-linux-release\.mjs --candidate "\$version" --releases previous-releases\.json\)/, `${file} does not select the previous release by version and assets`)
    assert.match(step, /gh release download "\$tag" --repo "\$GITHUB_REPOSITORY" --pattern "Sesame_\$\{tag#v\}_amd64\.deb" --pattern 'SHA256SUMS-linux' --dir previous-release/, `${file} does not download the selected release deb and its checksums`)
    assert.doesNotMatch(step, /gh release download --repo|--clobber|<\(/, `${file} must download the selected tag and fail when the selection fails`)
    assert.match(step, /--format deb\b/)
    assert.match(step, /--previous "previous-release\/Sesame_\$\{tag#v\}_amd64\.deb"/, `${file} does not pass the selected deb to the gate`)
    assert.match(step, /--previous-sums previous-release\/SHA256SUMS-linux/, `${file} does not pass the release checksums to the gate`)
    assert.ok(step.indexOf('previous-linux-release.mjs') < step.indexOf('gh release download'), `${file} must select the release before it downloads`)
    assert.ok(step.indexOf('gh release download') < step.indexOf('linux-shipped-package-gate.mjs'), `${file} must download before it runs the gate`)
    const job = workflow.slice(workflow.indexOf(jobStart), workflow.indexOf(jobEnd))
    assert.doesNotMatch(job, /contents: write/, `${file} gives the upgrade job write access`)
  }
})

function fictionalRelease(tag, overrides = {}) {
  const version = tag.slice(1)
  return {
    tag_name: tag,
    draft: false,
    prerelease: false,
    assets: [`Sesame_${version}_amd64.deb`, 'SHA256SUMS-linux', `Sesame_${version}_x64-setup.exe`].map((name) => ({ name, state: 'uploaded' })),
    ...overrides,
  }
}

test('the previous release is the newest published one older than the candidate that has the deb and its checksums', () => {
  const pages = [[fictionalRelease('v1.4.0'), fictionalRelease('v1.3.9')], [fictionalRelease('v1.2.0'), fictionalRelease('v1.10.0', { draft: true })]]
  assert.deepEqual(selectPreviousLinuxRelease(pages, '1.5.0'), { tag: 'v1.4.0', version: '1.4.0', deb: 'Sesame_1.4.0_amd64.deb' })
  assert.equal(selectPreviousLinuxRelease([fictionalRelease('v1.2.0'), fictionalRelease('v1.10.0')], '1.11.0').tag, 'v1.10.0')
})

test('the candidate itself, newer releases, drafts, prereleases and other tags are never the previous release', () => {
  const older = fictionalRelease('v1.3.0')
  assert.equal(selectPreviousLinuxRelease([[fictionalRelease('v1.4.0'), older]], '1.4.0').tag, 'v1.3.0')
  assert.equal(selectPreviousLinuxRelease([[fictionalRelease('v1.5.0'), older]], '1.4.0').tag, 'v1.3.0')
  assert.equal(selectPreviousLinuxRelease([[fictionalRelease('v1.3.5', { draft: true }), older]], '1.4.0').tag, 'v1.3.0')
  assert.equal(selectPreviousLinuxRelease([[fictionalRelease('v1.3.5', { prerelease: true }), older]], '1.4.0').tag, 'v1.3.0')
  assert.equal(selectPreviousLinuxRelease([[{ ...fictionalRelease('v1.3.5'), draft: undefined }, older]], '1.4.0').tag, 'v1.3.0')
  assert.equal(selectPreviousLinuxRelease([[fictionalRelease('v01.3.5'), fictionalRelease('v1.03.5'), older]], '1.4.0').tag, 'v1.3.0')
  assert.equal(selectPreviousLinuxRelease([[fictionalRelease('freshness'), fictionalRelease('v1.3.5-beta.1'), older]], '1.4.0').tag, 'v1.3.0')
})

test('a published release still waiting for its Linux files is passed over for the one before it', () => {
  const older = fictionalRelease('v1.3.0')
  const windowsOnly = fictionalRelease('v1.3.5', { assets: [{ name: 'Sesame_1.3.5_x64-setup.exe', state: 'uploaded' }] })
  const withoutSums = fictionalRelease('v1.3.4', { assets: [{ name: 'Sesame_1.3.4_amd64.deb', state: 'uploaded' }] })
  const halfUploaded = fictionalRelease('v1.3.3', { assets: [{ name: 'Sesame_1.3.3_amd64.deb', state: 'starter' }, { name: 'SHA256SUMS-linux', state: 'uploaded' }] })
  const wrongDeb = fictionalRelease('v1.3.2', { assets: [{ name: 'Sesame_1.3.0_amd64.deb', state: 'uploaded' }, { name: 'SHA256SUMS-linux', state: 'uploaded' }] })
  assert.equal(selectPreviousLinuxRelease([[windowsOnly, withoutSums, halfUploaded, wrongDeb, older]], '1.4.0').tag, 'v1.3.0')
})

test('the selection fails when no older release qualifies or the candidate version is malformed', () => {
  assert.throws(() => selectPreviousLinuxRelease([], '1.4.0'), /No published release older than 1\.4\.0/)
  assert.throws(() => selectPreviousLinuxRelease([[fictionalRelease('v1.4.0')]], '1.4.0'), /No published release older than 1\.4\.0/)
  assert.throws(() => selectPreviousLinuxRelease({ releases: [] }, '1.4.0'), /No published release/)
  for (const candidate of ['', 'v1.4.0', '1.4', undefined]) {
    assert.throws(() => selectPreviousLinuxRelease([[fictionalRelease('v1.3.0')]], candidate), /not major\.minor\.patch/)
  }
})

test('the selection script prints only the tag and refuses bad arguments', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'sesame-previous-release-'))
  try {
    const releases = path.join(directory, 'releases.json')
    await writeFile(releases, JSON.stringify([[fictionalRelease('v1.3.0'), fictionalRelease('v1.4.0')]]))
    const run = (...args) => new Promise((resolve) => {
      const child = spawn(process.execPath, [path.join(repository, 'tools', 'previous-linux-release.mjs'), ...args], { stdio: ['ignore', 'pipe', 'pipe'] })
      let stdout = ''
      let stderr = ''
      child.stdout.on('data', (chunk) => { stdout += chunk })
      child.stderr.on('data', (chunk) => { stderr += chunk })
      child.once('close', (code) => resolve({ code, stdout, stderr }))
    })
    assert.deepEqual(await run('--candidate', '1.4.0', '--releases', releases), { code: 0, stdout: 'v1.3.0\n', stderr: '' })
    const none = await run('--candidate', '1.3.0', '--releases', releases)
    assert.equal(none.code, 2)
    assert.equal(none.stdout, '')
    assert.match(none.stderr, /No published release older than 1\.3\.0/)
    const usage = await run('--candidate', '--releases', releases)
    assert.equal(usage.code, 2)
    assert.match(usage.stderr, /Usage/)
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
})

test('the upgrade check needs the previous package to be strictly older than the candidate', () => {
  assert.deepEqual(judgeVersionOrder({ previous: '1.3.0', candidate: '1.4.0', older: true }), { ok: true, value: { previous: '1.3.0', candidate: '1.4.0' } })
  assert.match(judgeVersionOrder({ previous: '1.4.0', candidate: '1.4.0', older: false }).error, /1\.4\.0 is not older than the candidate 1\.4\.0/)
  assert.equal(judgeVersionOrder({ previous: '1.4.0', candidate: '1.4.0', older: 'yes' }).ok, false)
})
