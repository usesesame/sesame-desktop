import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import process from 'node:process'

const root = resolve('.')
const manifest = join(root, 'src-tauri', 'Cargo.toml')
const desktopExe = join(root, 'src-tauri', 'target', 'debug', 'sesame.exe')
const hostExe = join(root, 'src-tauri', 'target', 'debug', 'sesame-browser-host.exe')
const pinnedOrigin = 'chrome-extension://idbkfhhjnniibleeanchljhakfhecnlg'

function frame(value) {
  const json = Buffer.from(JSON.stringify(value), 'utf8')
  const header = Buffer.alloc(4)
  header.writeUInt32LE(json.length, 0)
  return Buffer.concat([header, json])
}

function run(command, args) {
  const result = spawnSync(command, args, { cwd: root, stdio: 'inherit', shell: process.platform === 'win32' })
  if (result.status !== 0) throw new Error(`${command} ${args.join(' ')} failed`)
}

async function probeDesktop() {
  const host = spawn(hostExe, [pinnedOrigin], { stdio: ['pipe', 'pipe', 'pipe'] })
  let stderr = ''
  let timer
  host.stderr.on('data', (chunk) => { stderr += chunk.toString() })
  try {
    return await new Promise((settle, fail) => {
      let buffer = Buffer.alloc(0)
      timer = setTimeout(() => fail(new Error(`native host did not respond over the pipe in time (stderr: ${stderr || '(none)'})`)), 10_000)
      host.once('error', fail)
      host.stdout.on('data', (chunk) => {
        buffer = Buffer.concat([buffer, chunk])
        if (buffer.length < 4) return
        const size = buffer.readUInt32LE(0)
        if (buffer.length < 4 + size) return
        settle(JSON.parse(buffer.subarray(4, 4 + size).toString('utf8')))
      })
      host.once('exit', (code) => fail(new Error(`native host exited (code ${code}) before responding`)))
      host.stdin.write(frame({ version: 1, type: 'capabilities', requestId: 'pipe-check-1' }))
    })
  } finally {
    clearTimeout(timer)
    host.stdin.end()
    if (host.exitCode === null && !host.killed) host.kill()
  }
}

async function main() {
  if (process.platform !== 'win32') {
    console.log('The browser native-host pipe is Windows-only. Skipping.')
    return
  }

  console.log('Building sesame and sesame-browser-host as true directory siblings...')
  run('cargo', ['build', '--manifest-path', manifest, '--bin', 'sesame'])
  run('cargo', ['build', '--manifest-path', manifest, '--features', 'browser-helper-dev', '--bin', 'sesame-browser-host'])
  if (!existsSync(desktopExe)) throw new Error(`Desktop binary not found at ${desktopExe}`)
  if (!existsSync(hostExe)) throw new Error(`Browser host binary not found at ${hostExe}`)

  const testRoot = mkdtempSync(join(tmpdir(), 'sesame-pipe-check-'))
  const desktop = spawn(desktopExe, [], {
    env: { ...process.env, LOCALAPPDATA: testRoot, SESAME_DESKTOP_E2E_ROOT: testRoot },
    stdio: 'ignore',
  })

  try {
    let response
    for (let attempt = 0; attempt < 12; attempt += 1) {
      response = await probeDesktop()
      if (response.type === 'capabilities' && response.desktopAvailable === true) break
      await new Promise((resolveWait) => setTimeout(resolveWait, 500))
    }

    if (response?.type !== 'capabilities' || response.desktopAvailable !== true) {
      throw new Error(`unexpected response from the desktop broker: ${JSON.stringify(response)}`)
    }
    console.log('The browser native host completed an authenticated exchange with the live desktop broker:', response)
  } finally {
    try { process.kill(desktop.pid) } catch { void 0 }
    rmSync(testRoot, { recursive: true, force: true })
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1 })
