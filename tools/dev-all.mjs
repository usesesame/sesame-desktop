import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { resolve } from 'node:path'

const root = resolve(import.meta.dirname, '..')
const color = process.stdout.isTTY

function paint(code, text) {
  return color ? `[${code}m${text}[0m` : text
}

const viteBin = resolve(root, 'node_modules', 'vite', 'bin', 'vite.js')
const tauriCli = resolve(root, 'node_modules', '@tauri-apps', 'cli', 'tauri.js')
for (const [label, path] of [['vite', viteBin], ['the Tauri CLI', tauriCli]]) {
  if (!existsSync(path)) {
    console.error(`Could not find ${label}. Run \`npm ci\` first.`)
    process.exit(1)
  }
}

const processes = [
  {
    label: 'website',
    ansi: '36',
    command: process.execPath,
    args: [viteBin, '--config', 'website/vite.config.ts'],
  },
  {
    label: 'admin',
    ansi: '35',
    command: process.execPath,
    args: [viteBin, '--config', 'admin/vite.config.ts'],
  },
  {
    label: 'account',
    ansi: '34',
    command: process.execPath,
    args: [viteBin, '--config', 'account/vite.config.ts'],
  },
  {
    label: 'api',
    ansi: '33',
    command: process.execPath,
    args: [resolve(root, 'backend', 'scripts', 'dev.mjs')],
  },
  {
    label: 'desktop',
    ansi: '32',
    command: process.execPath,
    args: [tauriCli, 'dev'],
  },
]

const maxLabelLength = Math.max(...processes.map((entry) => entry.label.length))

function prefixedWriter(label, ansi, stream) {
  const tag = paint(ansi, `[${label.padEnd(maxLabelLength)}]`)
  let buffered = ''
  return (chunk) => {
    buffered += chunk.toString()
    const lines = buffered.split('\n')
    buffered = lines.pop() ?? ''
    for (const line of lines) stream.write(`${tag} ${line}\n`)
  }
}

console.log('Starting website, account portal, admin, API, and desktop together. Ctrl+C stops all five.\n')

const children = processes.map((entry) => {
  const child = spawn(entry.command, entry.args, { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] })
  const writeOut = prefixedWriter(entry.label, entry.ansi, process.stdout)
  const writeErr = prefixedWriter(entry.label, entry.ansi, process.stderr)
  child.stdout.on('data', writeOut)
  child.stderr.on('data', writeErr)
  child.on('error', (error) => {
    console.error(`${paint(entry.ansi, `[${entry.label}]`)} could not start: ${error.message}`)
  })
  child.on('exit', (code, signal) => {
    if (shuttingDown) return
    const how = signal ? `signal ${signal}` : `code ${code}`
    console.log(`${paint(entry.ansi, `[${entry.label}]`)} stopped (${how}).`)
  })
  return child
})

let shuttingDown = false
function shutdown(signal) {
  if (shuttingDown) return
  shuttingDown = true
  console.log(`\nStopping website, account portal, admin, API, and desktop (${signal})…`)
  for (const child of children) child.kill(signal)
}

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => shutdown(signal))
}
