import { join, resolve } from 'node:path'

export const extensionRepository = 'usesesame/sesame-browser-extension'

export const requiredStationSteps = [
  'app.launch',
  'browser.registration',
  'vault.create',
  'vault.seed',
  'extension.suite',
  'extension.connect',
  'fill.approved',
  'fill.other-origin',
  'fill.locked',
  'approvals.expected',
]

export function stationTargetDirectory(root, environment) {
  const configured = environment.CARGO_TARGET_DIR
  return configured ? resolve(root, configured) : join(root, 'src-tauri', 'target')
}

export function stationTauriConfig({ wdioConfig, unstagedConfig, frontendDist }) {
  const unstaged = JSON.parse(unstagedConfig)
  const config = structuredClone(wdioConfig)
  delete config.build
  config.bundle = { ...config.bundle, ...unstaged.bundle }
  config.build = { frontendDist }
  return config
}

export function parseExtensionPin(text) {
  const pin = JSON.parse(text)
  const keys = Object.keys(pin).sort()
  if (keys.join() !== ['commit', 'repository', 'tag'].join()) throw new Error('The extension pin must hold exactly a repository, a tag and a commit.')
  if (pin.repository !== extensionRepository) throw new Error(`The extension pin must name ${extensionRepository}.`)
  if (!/^[0-9a-f]{40}$/.test(pin.commit)) throw new Error('The extension pin must be a full commit hash.')
  if (!/^v\d+\.\d+\.\d+$/.test(pin.tag)) throw new Error('The extension pin must name a release tag such as v0.3.1.')
  return pin
}

export function createCallQueue(call) {
  let tail = Promise.resolve()
  return (command, args = {}) => {
    const result = tail.then(() => call(command, args))
    tail = result.catch(() => undefined)
    return result
  }
}

const approvalKinds = [
  { kind: 'fill', pending: 'get_pending_browser_fill' },
  { kind: 'create', pending: 'get_pending_browser_create' },
  { kind: 'save', pending: 'get_pending_browser_save' },
]

export function decideApproval(kind, event, allowsOrigin) {
  if (!allowsOrigin(event.origin)) {
    return { approved: false, reason: `an approval for ${event.origin} was requested` }
  }
  if (kind === 'fill') {
    const candidate = (event.candidates ?? []).find((entry) => entry.savedOrigin === event.origin)
    if (!candidate) return { approved: false, reason: `no saved login matches ${event.origin} exactly` }
    return { approved: true, command: 'resolve_browser_fill', args: { approvalId: event.approvalId, loginId: candidate.id } }
  }
  if (kind === 'create') {
    return { approved: true, command: 'resolve_browser_create', args: { approvalId: event.approvalId, approved: true } }
  }
  const target = event.kind === 'update' ? (event.candidates ?? [])[0] : undefined
  if (event.kind === 'update' && !target) return { approved: false, reason: 'an update was offered with no login to update' }
  return {
    approved: true,
    command: 'resolve_browser_save',
    args: { approvalId: event.approvalId, approved: true, selectedId: target ? target.id : null },
  }
}

function declineArguments(kind, event) {
  if (kind === 'fill') return { command: 'resolve_browser_fill', args: { approvalId: event.approvalId, loginId: null } }
  if (kind === 'create') return { command: 'resolve_browser_create', args: { approvalId: event.approvalId, approved: false } }
  return { command: 'resolve_browser_save', args: { approvalId: event.approvalId, approved: false, selectedId: null } }
}

const tooSoon = /wait a moment/i
const maximumEarlyAttempts = 80

export function createApprover({ call, intervalMs = 150, pause = (milliseconds) => new Promise((resolveWait) => setTimeout(resolveWait, milliseconds)) }) {
  let allowsOrigin = () => false
  let stopped = false
  let loop = null
  const approvals = []
  const refusals = []
  const failures = []
  const early = new Map()
  const finished = new Set()

  async function settle(kind, event) {
    if (finished.has(event.approvalId)) return
    const decision = decideApproval(kind, event, allowsOrigin)
    if (!decision.approved) {
      finished.add(event.approvalId)
      refusals.push({ kind, origin: event.origin, reason: decision.reason })
      const decline = declineArguments(kind, event)
      await call(decline.command, decline.args)
      return
    }
    const wait = await call('get_browser_approval_wait')
    if (wait.ok && wait.value > 0) await pause(Math.min(wait.value, 1000) + 25)
    const outcome = await call(decision.command, decision.args)
    if (outcome.ok) {
      finished.add(event.approvalId)
      approvals.push({ kind, origin: event.origin })
      return
    }
    const attempts = (early.get(event.approvalId) ?? 0) + 1
    early.set(event.approvalId, attempts)
    if (!tooSoon.test(outcome.error ?? '') || attempts >= maximumEarlyAttempts) {
      finished.add(event.approvalId)
      failures.push(`${kind} approval for ${event.origin} failed: ${outcome.error}`)
    }
  }

  async function tick() {
    for (const { kind, pending } of approvalKinds) {
      const outcome = await call(pending)
      if (outcome.ok && outcome.value) await settle(kind, outcome.value)
    }
  }

  async function run() {
    while (!stopped) {
      try {
        await tick()
      } catch (error) {
        failures.push(String(error.message ?? error))
      }
      await pause(intervalMs)
    }
  }

  return {
    allow(predicate) {
      allowsOrigin = predicate
    },
    start() {
      loop = run()
    },
    async stop() {
      stopped = true
      await loop
    },
    approvals,
    refusals,
    failures,
  }
}

export function judgeStation(steps, required = requiredStationSteps) {
  const byName = new Map(steps.map((step) => [step.name, step]))
  const missing = required.filter((name) => !byName.has(name))
  const failed = steps.filter((step) => !step.ok).map((step) => step.name)
  return { ok: missing.length === 0 && failed.length === 0, missing, failed }
}

export function isLoopbackOrigin(origin, ports) {
  const match = /^http:\/\/127\.0\.0\.1:(\d+)$/.exec(origin)
  return Boolean(match) && (ports === undefined || ports.includes(Number(match[1])))
}

export const unixSocketPathLimit = 107

export function brokerSocketFits(runtimeDirectory) {
  return Buffer.byteLength(join(runtimeDirectory, 'sesame', 'browser.sock')) <= unixSocketPathLimit
}
