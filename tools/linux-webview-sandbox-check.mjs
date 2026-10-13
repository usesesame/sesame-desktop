import { spawn, spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, readdirSync, readlinkSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { linuxBrowserEnvironment } from './desktop-e2e-bridge.mjs'

const NAMESPACES = ['mnt', 'pid', 'user', 'net']
const REFUSAL_TEXT = 'the sandbox for its web view is not available'

export function parseStatus(text) {
  const fields = {}
  for (const line of String(text).split('\n')) {
    const separator = line.indexOf(':')
    if (separator > 0) fields[line.slice(0, separator)] = line.slice(separator + 1).trim()
  }
  return fields
}

export function parseEnvironment(bytes) {
  const variables = {}
  for (const entry of String(bytes).split('\0')) {
    const separator = entry.indexOf('=')
    if (separator > 0) variables[entry.slice(0, separator)] = entry.slice(separator + 1)
  }
  return variables
}

export function countAnonymousExecutableMappings(maps) {
  let count = 0
  for (const line of String(maps).split('\n')) {
    const columns = line.trim().split(/\s+/)
    if (columns.length === 5 && columns[1][2] === 'x') count += 1
  }
  return count
}

export function judgeWebProcess(observation, host) {
  const failures = []
  const prefix = `web process ${observation.pid}`
  if (observation.status?.Seccomp !== '2') failures.push(`${prefix} has Seccomp ${observation.status?.Seccomp ?? 'unreadable'}, expected 2`)
  if (observation.status?.NoNewPrivs !== '1') failures.push(`${prefix} has NoNewPrivs ${observation.status?.NoNewPrivs ?? 'unreadable'}, expected 1`)
  for (const name of NAMESPACES) {
    const link = observation.namespaces?.[name]
    if (!link) failures.push(`${prefix} ${name} namespace is unreadable`)
    else if (link === host[name]) failures.push(`${prefix} shares the ${name} namespace with the host`)
  }
  if (observation.environment?.JSC_useJIT !== '0') {
    failures.push(`${prefix} has JSC_useJIT ${observation.environment?.JSC_useJIT ?? 'unreadable'}, expected 0`)
  }
  if (observation.anonymousExecutableMappings !== 0) {
    failures.push(`${prefix} has ${observation.anonymousExecutableMappings ?? 'unreadable'} anonymous executable mappings, expected 0`)
  }
  return failures
}

export function judge({ webProcesses, host, logText }) {
  if (webProcesses.length === 0) {
    return logText.includes(REFUSAL_TEXT)
      ? { state: 'refused', failures: [] }
      : { state: 'no_renderer', failures: ['no web process was found and the app did not report a refusal'] }
  }
  const failures = webProcesses.flatMap((observation) => judgeWebProcess(observation, host))
  return { state: failures.length === 0 ? 'sandboxed' : 'unsandboxed', failures }
}

function read(file) {
  try {
    return readFileSync(file, 'utf8')
  } catch {
    return null
  }
}

function link(file) {
  try {
    return readlinkSync(file)
  } catch {
    return null
  }
}

export function parentOf(pid) {
  const stat = read(`/proc/${pid}/stat`)
  if (!stat) return null
  const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ')
  return Number(fields[1])
}

export function descendantsNamed(rootPid, name) {
  const found = []
  for (const entry of readdirSync('/proc')) {
    if (!/^\d+$/.test(entry)) continue
    const pid = Number(entry)
    const argv = (read(`/proc/${pid}/cmdline`) ?? '').split('\0')
    if (path.basename(argv[0]) !== name) continue
    let ancestor = parentOf(pid)
    for (let depth = 0; ancestor && ancestor > 1 && depth < 16; depth += 1) {
      if (ancestor === rootPid) {
        found.push(pid)
        break
      }
      ancestor = parentOf(ancestor)
    }
  }
  return found
}

function observe(pid) {
  const status = read(`/proc/${pid}/status`)
  const environment = read(`/proc/${pid}/environ`)
  const maps = read(`/proc/${pid}/maps`)
  return {
    pid,
    status: status === null ? null : parseStatus(status),
    namespaces: Object.fromEntries(NAMESPACES.map((name) => [name, link(`/proc/${pid}/ns/${name}`)])),
    environment: environment === null ? null : parseEnvironment(environment),
    anonymousExecutableMappings: maps === null ? null : countAnonymousExecutableMappings(maps),
  }
}

function hostNamespaces() {
  return Object.fromEntries(NAMESPACES.map((name) => [name, link(`/proc/self/ns/${name}`)]))
}

function parseArguments(argv) {
  const options = { seconds: 12, expect: 'sandboxed', dbus: true }
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    if (argument === '--binary') options.binary = argv[++index]
    else if (argument === '--seconds') options.seconds = Number(argv[++index])
    else if (argument === '--expect') options.expect = argv[++index]
    else if (argument === '--no-dbus-session') options.dbus = false
    else throw new Error(`Unknown argument: ${argument}`)
  }
  if (!options.binary) throw new Error('Usage: node tools/linux-webview-sandbox-check.mjs --binary <sesame> [--seconds 12] [--expect sandboxed|refused] [--no-dbus-session]')
  if (!Number.isFinite(options.seconds) || options.seconds < 3) throw new Error('The wait must be at least 3 seconds.')
  if (!['sandboxed', 'refused'].includes(options.expect)) throw new Error('The expected state must be sandboxed or refused.')
  return options
}

async function check(options) {
  if (process.platform !== 'linux') throw new Error('The web view sandbox check runs on Linux only.')
  if (!process.env.DISPLAY && !process.env.WAYLAND_DISPLAY) throw new Error('Set DISPLAY or WAYLAND_DISPLAY to a display the check may open windows on.')
  const root = mkdtempSync(path.join(tmpdir(), 'sesame-webview-sandbox-'))
  const environment = linuxBrowserEnvironment(root)
  const launcher = options.dbus && spawnSync('dbus-run-session', ['--version'], { stdio: 'ignore' }).status === 0
    ? ['dbus-run-session', '--', options.binary, '--minimized']
    : [options.binary, '--minimized']
  const log = []
  const child = spawn(launcher[0], launcher.slice(1), {
    env: { ...process.env, ...environment },
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true,
  })
  child.stdout.on('data', (chunk) => log.push(chunk.toString('utf8')))
  child.stderr.on('data', (chunk) => log.push(chunk.toString('utf8')))
  const deadline = Date.now() + options.seconds * 1000
  let pids = []
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 500))
    pids = descendantsNamed(child.pid, 'WebKitWebProcess')
    if (pids.length >= 2 || child.exitCode !== null) break
  }
  const result = judge({ webProcesses: pids.map(observe), host: hostNamespaces(), logText: log.join('') })
  const alive = child.exitCode === null
  try {
    process.kill(-child.pid, 'SIGTERM')
  } catch {
    child.kill('SIGTERM')
  }
  await new Promise((resolve) => setTimeout(resolve, 1500))
  try {
    process.kill(-child.pid, 'SIGKILL')
  } catch {
    child.kill('SIGKILL')
  }
  rmSync(root, { recursive: true, force: true })
  return { ...result, appAliveAtCheck: alive, webProcesses: pids.length }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const options = parseArguments(process.argv.slice(2))
  const result = await check(options)
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)
  process.exitCode = result.state === options.expect ? 0 : 1
}
