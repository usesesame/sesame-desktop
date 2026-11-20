import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import test from 'node:test'

import { fictionalLogin, judgeApprovedFill, judgeRefusedFill, promptCount, stationOriginPolicy } from './extension-journey.mjs'
import {
  brokerSocketFits,
  createApprover,
  createCallQueue,
  decideApproval,
  isLoopbackOrigin,
  judgeStation,
  parseExtensionPin,
  requiredStationSteps,
  stationTargetDirectory,
  stationTauriConfig,
} from './extension-station.mjs'

const read = (...parts) => readFileSync(join(process.cwd(), ...parts), 'utf8')
const ci = read('.github', 'workflows', 'ci.yml')
const nightly = read('.github', 'workflows', 'extension-nightly.yml')
const stationJob = ci.slice(ci.indexOf('\n  extension-station:'), ci.indexOf('\n  desktop-linux:'))
const origin = 'http://127.0.0.1:41000'
const otherOrigin = 'http://127.0.0.1:41001'
const noPause = () => new Promise((resolveWait) => setImmediate(resolveWait))

function fillEvent(overrides = {}) {
  return {
    approvalId: 'approval-1',
    origin,
    candidates: [{ id: 'login-1', savedOrigin: origin }],
    ...overrides,
  }
}

test('the cargo target folder follows CARGO_TARGET_DIR and falls back to the repository target', () => {
  assert.equal(stationTargetDirectory('/work/desktop', {}), join('/work/desktop', 'src-tauri', 'target'))
  assert.equal(stationTargetDirectory('/work/desktop', { CARGO_TARGET_DIR: '/scratch/target' }), resolve('/scratch/target'))
  assert.equal(stationTargetDirectory('/work/desktop', { CARGO_TARGET_DIR: 'relative' }), resolve('/work/desktop', 'relative'))
})

test('the station config is the test-featured config without sidecars and with its own web interface', () => {
  const wdioConfig = JSON.parse(read('src-tauri', 'tauri.wdio.conf.json'))
  const config = stationTauriConfig({
    wdioConfig,
    unstagedConfig: '{"bundle":{"externalBin":[],"resources":[]}}',
    frontendDist: '/scratch/dist',
  })
  assert.deepEqual(config.build, { frontendDist: '/scratch/dist' })
  assert.deepEqual(config.bundle.externalBin, [])
  assert.deepEqual(config.bundle.resources, [])
  assert.equal(config.bundle.createUpdaterArtifacts, false)
  assert.deepEqual(config.app.security.capabilities, ['main-capability', 'desktop-e2e-capability'])
  assert.equal(config.identifier, wdioConfig.identifier)
  assert.ok(wdioConfig.build.beforeBuildCommand, 'the input must not be changed')
})

test('the extension pin names the extension repository, a release tag and a full commit', () => {
  const pin = parseExtensionPin(read('src-tauri', 'contracts', 'browser', 'extension-pin.json'))
  assert.equal(pin.repository, 'usesesame/sesame-browser-extension')
  assert.match(pin.commit, /^[0-9a-f]{40}$/)
  assert.match(pin.tag, /^v\d+\.\d+\.\d+$/)
})

test('a pin that is not exactly a repository, a release tag and a full commit is refused', () => {
  const good = { repository: 'usesesame/sesame-browser-extension', tag: 'v0.3.1', commit: 'a'.repeat(40) }
  assert.doesNotThrow(() => parseExtensionPin(JSON.stringify(good)))
  for (const bad of [
    { ...good, commit: 'main' },
    { ...good, commit: 'a'.repeat(39) },
    { ...good, tag: 'main' },
    { ...good, tag: 'v0.3' },
    { ...good, repository: 'someone/else' },
    { ...good, olderCommit: 'a'.repeat(40) },
    { repository: good.repository, commit: good.commit },
  ]) {
    assert.throws(() => parseExtensionPin(JSON.stringify(bad)), `${JSON.stringify(bad)} was accepted`)
  }
})

test('bridge calls run one at a time and a failed call does not block the next', async () => {
  let running = 0
  let highest = 0
  const order = []
  const call = createCallQueue(async (command) => {
    running += 1
    highest = Math.max(highest, running)
    await new Promise((resolveWait) => setTimeout(resolveWait, 5))
    running -= 1
    order.push(command)
    if (command === 'broken') throw new Error('broken')
    return { ok: true, value: command }
  })
  const results = await Promise.allSettled([call('one'), call('broken'), call('three')])
  assert.equal(highest, 1)
  assert.deepEqual(order, ['one', 'broken', 'three'])
  assert.equal(results[1].status, 'rejected')
  assert.equal(results[2].value.value, 'three')
})

test('a fill is approved only for an allowed origin and a login saved for exactly that origin', () => {
  const allows = (candidate) => candidate === origin
  assert.deepEqual(decideApproval('fill', fillEvent(), allows), {
    approved: true,
    command: 'resolve_browser_fill',
    args: { approvalId: 'approval-1', loginId: 'login-1' },
  })
  assert.equal(decideApproval('fill', fillEvent({ origin: otherOrigin }), allows).approved, false)
  assert.equal(decideApproval('fill', fillEvent({ candidates: [{ id: 'login-2', savedOrigin: otherOrigin }] }), allows).approved, false)
  assert.equal(decideApproval('fill', fillEvent({ candidates: [] }), allows).approved, false)
})

test('a created or saved login is approved only for an allowed origin', () => {
  const allows = (candidate) => candidate === origin
  assert.deepEqual(decideApproval('create', { approvalId: 'a', origin }, allows).args, { approvalId: 'a', approved: true })
  assert.equal(decideApproval('create', { approvalId: 'a', origin: otherOrigin }, allows).approved, false)
  assert.deepEqual(decideApproval('save', { approvalId: 'a', origin, kind: 'new' }, allows).args, { approvalId: 'a', approved: true, selectedId: null })
  assert.deepEqual(
    decideApproval('save', { approvalId: 'a', origin, kind: 'update', candidates: [{ id: 'login-1' }] }, allows).args,
    { approvalId: 'a', approved: true, selectedId: 'login-1' },
  )
  assert.equal(decideApproval('save', { approvalId: 'a', origin, kind: 'update', candidates: [] }, allows).approved, false)
  assert.equal(decideApproval('save', { approvalId: 'a', origin: otherOrigin, kind: 'new' }, allows).approved, false)
})

function scriptedDesktop({ pending, waits = [0], rejectFirst = 0 }) {
  const calls = []
  let rejected = 0
  const call = async (command, args = {}) => {
    calls.push({ command, args })
    if (command === 'get_pending_browser_fill') return { ok: true, value: pending.value }
    if (command.startsWith('get_pending_')) return { ok: true, value: null }
    if (command === 'get_browser_approval_wait') return { ok: true, value: waits.shift() ?? 0 }
    if (command === 'resolve_browser_fill' && args.loginId !== null) {
      if (rejected < rejectFirst) {
        rejected += 1
        return { ok: false, error: 'Wait a moment after Sesame comes forward, then approve again.' }
      }
      pending.value = null
      return { ok: true }
    }
    pending.value = null
    return { ok: true }
  }
  return { call, calls }
}

async function settleApprover(approver) {
  approver.start()
  await new Promise((resolveWait) => setTimeout(resolveWait, 30))
  await approver.stop()
}

test('the approver waits out the desktop focus delay and keeps trying while it answers too soon', async () => {
  const pauses = []
  const desktop = scriptedDesktop({ pending: { value: fillEvent() }, waits: [300, 0, 0], rejectFirst: 2 })
  const approver = createApprover({ call: desktop.call, intervalMs: 1, pause: (milliseconds) => { pauses.push(milliseconds); return noPause() } })
  approver.allow((candidate) => candidate === origin)
  await settleApprover(approver)
  assert.deepEqual(approver.approvals, [{ kind: 'fill', origin }])
  assert.deepEqual(approver.failures, [])
  assert.ok(pauses.includes(325), 'the approver did not wait for the reported delay')
  assert.equal(desktop.calls.filter((entry) => entry.command === 'resolve_browser_fill').length, 3)
})

test('the approver declines a prompt for an origin it was not told to expect and records it', async () => {
  const desktop = scriptedDesktop({ pending: { value: fillEvent({ origin: otherOrigin, candidates: [{ id: 'login-2', savedOrigin: otherOrigin }] }) } })
  const approver = createApprover({ call: desktop.call, intervalMs: 1, pause: noPause })
  approver.allow((candidate) => candidate === origin)
  await settleApprover(approver)
  assert.deepEqual(approver.approvals, [])
  assert.equal(approver.refusals.length, 1)
  assert.equal(approver.refusals[0].origin, otherOrigin)
  const decline = desktop.calls.find((entry) => entry.command === 'resolve_browser_fill')
  assert.deepEqual(decline.args, { approvalId: 'approval-1', loginId: null })
})

test('the approver records a failure that is not the focus delay and does not retry it', async () => {
  const calls = []
  const call = async (command, args = {}) => {
    calls.push(command)
    if (command === 'get_pending_browser_fill') return { ok: true, value: fillEvent() }
    if (command.startsWith('get_pending_')) return { ok: true, value: null }
    if (command === 'get_browser_approval_wait') return { ok: true, value: 0 }
    return { ok: false, error: `That browser approval is no longer available. ${args.approvalId}` }
  }
  const approver = createApprover({ call, intervalMs: 1, pause: noPause })
  approver.allow((candidate) => candidate === origin)
  await settleApprover(approver)
  assert.equal(approver.failures.length, 1)
  assert.equal(calls.filter((command) => command === 'resolve_browser_fill').length, 1)
})

test('stopping the approver waits for an approval that is still being answered', async () => {
  let release
  const held = new Promise((resolveHeld) => { release = resolveHeld })
  const call = async (command) => {
    if (command === 'get_pending_browser_fill') return { ok: true, value: fillEvent() }
    if (command.startsWith('get_pending_')) return { ok: true, value: null }
    if (command === 'get_browser_approval_wait') return { ok: true, value: 0 }
    await held
    return { ok: false, error: 'That browser approval is no longer available.' }
  }
  const approver = createApprover({ call, intervalMs: 1, pause: noPause })
  approver.allow((candidate) => candidate === origin)
  approver.start()
  await new Promise((resolveWait) => setTimeout(resolveWait, 20))
  assert.deepEqual(approver.failures, [])
  const stopping = approver.stop()
  release()
  await stopping
  assert.equal(approver.failures.length, 1)
})

test('the station stops the approver before it judges the approvals', () => {
  const source = readFileSync('tools/test-extension-native-host.mjs', 'utf8')
  const stop = source.indexOf('await approver.stop()')
  const judged = source.indexOf('const clean = approver.failures.length === 0')
  assert.ok(stop >= 0 && judged > stop, 'the approvals are judged while a prompt may still be answered')
})

test('the approver refuses everything until it is told which origins to expect', async () => {
  const desktop = scriptedDesktop({ pending: { value: fillEvent() } })
  const approver = createApprover({ call: desktop.call, intervalMs: 1, pause: noPause })
  await settleApprover(approver)
  assert.deepEqual(approver.approvals, [])
  assert.equal(approver.refusals.length, 1)
})

test('only loopback http origins on the listed ports are expected', () => {
  assert.equal(isLoopbackOrigin(origin), true)
  assert.equal(isLoopbackOrigin(origin, [41000]), true)
  assert.equal(isLoopbackOrigin(otherOrigin, [41000]), false)
  for (const bad of ['https://127.0.0.1:41000', 'http://localhost:41000', 'http://127.0.0.1:41000.evil.test', 'http://127.0.0.1', 'http://127.0.0.1:41000/path']) {
    assert.equal(isLoopbackOrigin(bad), false, bad)
  }
  assert.equal(stationOriginPolicy([origin])(origin), true)
  assert.equal(stationOriginPolicy([origin])(otherOrigin), false)
})

test('the station passes only when every required step ran and passed', () => {
  const passing = requiredStationSteps.map((name) => ({ name, ok: true }))
  assert.deepEqual(judgeStation(passing), { ok: true, missing: [], failed: [] })
  assert.deepEqual(judgeStation(passing.slice(1)).missing, [requiredStationSteps[0]])
  assert.equal(judgeStation(passing.slice(1)).ok, false)
  const failing = passing.map((step) => (step.name === 'fill.approved' ? { ...step, ok: false } : step))
  assert.deepEqual(judgeStation(failing).failed, ['fill.approved'])
  assert.equal(judgeStation([...passing, { name: 'station.error', ok: false }]).ok, false)
})

test('every journey the station promises is a required step', () => {
  for (const name of ['extension.connect', 'fill.approved', 'fill.other-origin', 'fill.locked', 'approvals.expected']) {
    assert.ok(requiredStationSteps.includes(name), `${name} is not required`)
  }
})

test('a filled page counts only when both fields hold the saved login', () => {
  const good = { offered: true, values: { username: fictionalLogin.username, password: fictionalLogin.password } }
  assert.equal(judgeApprovedFill(good).ok, true)
  assert.equal(judgeApprovedFill({ ...good, offered: false }).ok, false)
  assert.equal(judgeApprovedFill({ ...good, values: { ...good.values, password: `${fictionalLogin.password}x` } }).ok, false)
  assert.equal(judgeApprovedFill({ ...good, values: { ...good.values, username: '' } }).ok, false)
  assert.doesNotMatch(JSON.stringify(judgeApprovedFill({ ...good, values: { ...good.values, password: 'other' } })), new RegExp(fictionalLogin.password))
})

test('a refusal counts only when nothing was filled, no approval was asked for and the popup said no login matched', () => {
  const approver = { approvals: [], refusals: [] }
  const refused = { offered: true, values: { username: '', password: '' }, feedback: 'No login is saved for 127.0.0.1.' }
  assert.equal(judgeRefusedFill(refused, 0, approver, otherOrigin).ok, true)
  assert.equal(judgeRefusedFill({ ...refused, values: { username: '', password: 'filled' } }, 0, approver, otherOrigin).ok, false)
  assert.equal(judgeRefusedFill({ ...refused, feedback: 'Username and password filled.' }, 0, approver, otherOrigin).ok, false)
  const asked = { approvals: [{ kind: 'fill', origin: otherOrigin }], refusals: [] }
  assert.equal(judgeRefusedFill(refused, 0, asked, otherOrigin).ok, false)
  assert.equal(judgeRefusedFill(refused, 1, asked, otherOrigin).ok, true, 'an earlier approval must not count against a later attempt')
  assert.equal(promptCount(asked, origin), 0)
  assert.equal(promptCount(asked, otherOrigin), 1)
})

test('the desktop broker socket must fit the Unix path limit', () => {
  assert.equal(brokerSocketFits('/tmp/sesame-extension-native-host-AbC123/runtime'), true)
  assert.equal(brokerSocketFits(`/tmp/${'x'.repeat(120)}/runtime`), false)
})

test('the harness drives the test-featured build and never the shipped one', () => {
  const harness = read('tools', 'test-extension-native-host.mjs')
  assert.match(harness, /--features', 'wdio,browser-helper-dev,tauri\/custom-protocol'/)
  assert.match(harness, /tauri\.wdio\.conf\.json/)
  assert.match(harness, /VITE_SESAME_WDIO: 'true'/)
  assert.match(harness, /launchApp\(/)
  assert.doesNotMatch(harness, /--release/)
})

test('the harness fails when the extension suite matches no test and when the desktop never asked for an approval', () => {
  const harness = read('tools', 'test-extension-native-host.mjs')
  assert.match(harness, /matched no native-host test/)
  assert.match(harness, /The desktop never asked for an approval/)
})

for (const [name, text] of [['ci.yml extension-station', stationJob], ['extension-nightly.yml', nightly]]) {
  test(`${name} pins every action by full commit and keeps credentials out of checkouts`, () => {
    const uses = [...text.matchAll(/uses: ([^\s]+)/g)].map((match) => match[1])
    assert.ok(uses.length >= 5)
    for (const reference of uses) assert.match(reference, /^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/, `${reference} is not pinned by commit`)
    const checkouts = text.split('actions/checkout@').slice(1)
    assert.ok(checkouts.length >= 2, 'both repositories must be checked out')
    for (const checkout of checkouts) assert.match(checkout.split('\n\n')[0], /persist-credentials: false/)
  })

  test(`${name} has a timeout, builds under a virtual display and uploads evidence only on failure`, () => {
    assert.match(text, /timeout-minutes: \d+/)
    assert.match(text, /xvfb-run -a dbus-run-session -- node tools\/test-extension-native-host\.mjs/)
    assert.match(text, /--extension-directory sesame-browser-extension/)
    assert.match(text, /--evidence-directory extension-station-evidence/)
    assert.match(text, /npx playwright-core install --with-deps chromium/)
    assert.match(text, /if: failure\(\)\n\s+with:\n\s+name: extension-station-evidence/)
    assert.match(text, /path: sesame-browser-extension/)
    assert.doesNotMatch(text, /--release|tauri build/)
  })
}

test('the nightly workflow runs every night and on demand against the extension main branch with read-only access', () => {
  assert.match(nightly, /^on:\n {2}schedule:\n {4}- cron: '\d+ \d+ \* \* \*'\n {2}workflow_dispatch:/m)
  assert.match(nightly, /^permissions:\n {2}contents: read$/m)
  assert.doesNotMatch(nightly, /contents: write|pull-requests: write|secrets\./)
  assert.match(nightly, /repository: usesesame\/sesame-browser-extension\n\s+ref: main\n\s+path: sesame-browser-extension/)
  assert.match(nightly, /group: extension-nightly\n\s+cancel-in-progress: false/)
})

test('the pull request job runs the extension commit that the pin file names', () => {
  assert.ok(stationJob.length > 0, 'ci.yml has no extension-station job')
  assert.ok(stationJob.includes('src-tauri/contracts/browser/extension-pin.json'))
  assert.match(stationJob, /repository: \$\{\{ steps\.extension-pin\.outputs\.repository \}\}/)
  assert.match(stationJob, /ref: \$\{\{ steps\.extension-pin\.outputs\.commit \}\}/)
  assert.match(ci, /^permissions:\n {2}contents: read$/m)
  assert.match(ci, /^on:\n {2}pull_request:/m)
})

test('the workflows and the harness share one command and one evidence folder', () => {
  const evidence = [stationJob, nightly].map((text) => text.match(/--evidence-directory (\S+)/)[1])
  assert.equal(evidence[0], evidence[1])
  const scripts = JSON.parse(read('package.json')).scripts
  assert.equal(scripts['desktop:host:test:linux'], 'node tools/test-extension-native-host.mjs')
})
