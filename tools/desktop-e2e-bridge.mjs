import { createHash } from 'node:crypto'
import { spawn, execFile } from 'node:child_process'
import { createServer } from 'node:http'
import { promisify } from 'node:util'

export const CONNECTION_TIMEOUT_MS = 90_000
export const COMMAND_TIMEOUT_MS = 300_000

const run = promisify(execFile)

export const sha256 = (value) => createHash('sha256').update(value).digest('hex')

export function platformName() {
  if (process.platform === 'linux') return 'linux'
  if (process.platform === 'win32') return 'windows'
  throw new Error(`The desktop E2E bridge does not support ${process.platform}.`)
}

export function architectureName() {
  if (process.arch === 'x64') return 'x86_64'
  if (process.arch === 'arm64') return 'aarch64'
  throw new Error(`The desktop E2E bridge does not support ${process.arch}.`)
}

export class Bridge {
  constructor(token) {
    this.token = token
    this.command = null
    this.pending = null
    this.connected = false
    this.connectionWaiters = []
  }

  markConnected() {
    if (this.connected) return
    this.connected = true
    for (const resolve of this.connectionWaiters) resolve(true)
    this.connectionWaiters = []
  }

  waitForConnection(timeoutMs = CONNECTION_TIMEOUT_MS) {
    if (this.connected) return Promise.resolve(true)
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve(false), timeoutMs)
      this.connectionWaiters.push((value) => {
        clearTimeout(timer)
        resolve(value)
      })
    })
  }

  nextCommand() {
    this.markConnected()
    const command = this.command
    this.command = null
    return command
  }

  deliver(result) {
    const pending = this.pending
    if (!pending) return
    if (result?.id !== pending.id) return
    this.pending = null
    clearTimeout(pending.timer)
    pending.resolve(result)
  }

  call(command, args, timeoutMs = COMMAND_TIMEOUT_MS) {
    if (this.pending) throw new Error('The desktop E2E bridge received a second command before the first finished.')
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.pending = null
        resolve({ id: 0, ok: false, error: `${command} timed out` })
      }, timeoutMs)
      this.pending = { id: this.commandId ?? 1, timer, resolve }
      this.commandId = (this.commandId ?? 1) + 1
      this.command = { id: this.pending.id, command, args }
    })
  }

  handle(request, response) {
    const pathname = new URL(request.url, 'http://127.0.0.1').pathname
    const cors = () => {
      response.setHeader('Access-Control-Allow-Origin', '*')
      response.setHeader('Access-Control-Allow-Headers', 'Content-Type')
      response.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    }
    if (request.method === 'OPTIONS') {
      cors()
      response.writeHead(204, { 'Content-Length': '0' })
      response.end()
      return
    }
    if (request.method === 'GET' && pathname === `/${this.token}/next`) {
      const command = this.nextCommand()
      if (!command) {
        cors()
        response.writeHead(204, { 'Content-Length': '0' })
        response.end()
        return
      }
      const body = Buffer.from(JSON.stringify(command))
      cors()
      response.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': String(body.length) })
      response.end(body)
      return
    }
    if (request.method === 'POST' && pathname === `/${this.token}/result`) {
      const chunks = []
      request.on('data', (chunk) => chunks.push(chunk))
      request.on('end', () => {
        cors()
        response.writeHead(200, { 'Content-Length': '0' })
        response.end()
        try {
          this.deliver(JSON.parse(Buffer.concat(chunks).toString('utf8')))
        } catch {
          this.deliver(null)
        }
      })
      return
    }
    cors()
    response.writeHead(404, { 'Content-Length': '0' })
    response.end()
  }
}

export async function openBridge(token) {
  const bridge = new Bridge(token)
  const server = createServer((request, response) => bridge.handle(request, response))
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  bridge.port = server.address().port
  bridge.close = () => server.close()
  return bridge
}

export function launchApp({ binary, root, bridge, log }) {
  const child = spawn(binary, [`--sesame-e2e-root=${root}`], {
    env: {
      ...process.env,
      SESAME_DESKTOP_E2E_PORT: String(bridge.port),
      SESAME_DESKTOP_E2E_TOKEN: bridge.token,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: process.platform !== 'win32',
  })
  child.stdout.on('data', (chunk) => log.push(chunk.toString('utf8')))
  child.stderr.on('data', (chunk) => log.push(chunk.toString('utf8')))
  return child
}

export async function stopApp(child) {
  if (!child || child.exitCode !== null) return
  if (process.platform === 'win32') {
    try {
      await run('taskkill', ['/pid', String(child.pid), '/T', '/F'], { windowsHide: true })
    } catch {
      child.kill()
    }
  } else {
    try {
      process.kill(-child.pid, 'SIGTERM')
    } catch {
      child.kill('SIGTERM')
    }
  }
  await new Promise((resolve) => {
    const timer = setTimeout(() => {
      if (child.exitCode === null) child.kill('SIGKILL')
      resolve()
    }, 10_000)
    child.once('exit', () => {
      clearTimeout(timer)
      resolve()
    })
  })
}

export function recordStep(steps, name, result, extra) {
  const step = { name, ok: Boolean(result?.ok) }
  if (result?.ok) step.value = result.value
  else step.error = result?.error ?? 'no result'
  if (extra) Object.assign(step, extra)
  steps.push(step)
  return step
}

export async function summarize(steps) {
  return {
    passed: steps.filter((step) => step.ok).length,
    failed: steps.filter((step) => !step.ok).length,
    steps: steps.map(({ name, ok, error }) => ({ name, ok, ...(error ? { error } : {}) })),
  }
}
