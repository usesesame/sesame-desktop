import { spawn } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { REAL_SERVER_TESTS, startRealSyncServer } from './start-real-sync-server.mjs'

const root = dirname(dirname(fileURLToPath(import.meta.url)))

export function exactlyOneTestPassed(output) {
  return /test result: ok\. 1 passed; 0 failed;/.test(output)
}

export function parseArguments(args) {
  if (args.length !== 2 || args[0] !== '--server' || args[1].startsWith('--')) {
    throw new Error('Usage: node tools/run-real-sync-station.mjs --server <path to a sesame-server source tree>')
  }
  return { server: resolve(args[1]) }
}

export function testEnvironment(inherited, credentials, test) {
  const kept = Object.fromEntries(Object.entries(inherited).filter(([name]) => !name.startsWith('SESAME_SYNC_E2E_')))
  const tokens = credentials.tests[test]
  return {
    ...kept,
    SESAME_SYNC_E2E_URL: credentials.url,
    SESAME_SYNC_E2E_KEY: credentials.key,
    SESAME_SYNC_E2E_TOKEN_A: tokens.a,
    SESAME_SYNC_E2E_TOKEN_B: tokens.b,
  }
}

export function cargoArguments(test) {
  return ['test', '--manifest-path', join('src-tauri', 'Cargo.toml'), '--locked', '-p', 'sesame-app', '--lib', test, '--', '--ignored']
}

function runCargo(test, env) {
  return new Promise((resolveRun, reject) => {
    const child = spawn('cargo', cargoArguments(test), { cwd: root, env, stdio: ['ignore', 'pipe', 'pipe'] })
    let output = ''
    const forward = (stream) => (chunk) => {
      output += chunk
      stream.write(chunk)
    }
    child.stdout.on('data', forward(process.stdout))
    child.stderr.on('data', forward(process.stderr))
    child.once('error', reject)
    child.once('exit', (code) => {
      const settle = () => resolveRun({ code, output })
      const late = setTimeout(settle, 2000)
      child.once('close', () => {
        clearTimeout(late)
        settle()
      })
    })
  })
}

async function main() {
  const { server } = parseArguments(process.argv.slice(2))
  const station = await startRealSyncServer({ serverRoot: server })
  const failed = []
  try {
    for (const test of REAL_SERVER_TESTS) {
      const { code, output } = await runCargo(test, testEnvironment(process.env, station.credentials, test))
      if (code !== 0 || !exactlyOneTestPassed(output)) failed.push(test)
    }
  } finally {
    await station.stop()
  }
  if (failed.length > 0) {
    process.stderr.write(`These tests did not pass exactly once against the real server: ${failed.join(', ')}\n`)
    process.exit(1)
  }
  process.stdout.write(`All ${REAL_SERVER_TESTS.length} tests passed once each against the real server.\n`)
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error.stack ?? error}\n`)
    process.exit(1)
  })
}
