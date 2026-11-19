import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const verifier = join(root, 'tools', 'verify-desktop-boundary.mjs')
const workflow = readFileSync(join(root, '.github', 'workflows', 'boundary.yml'), 'utf8')

const matrixEntries = workflow
  .slice(workflow.indexOf('        script:\n'), workflow.indexOf('    steps:'))
  .split('\n')
  .filter((line) => line.startsWith('          - '))
  .map((line) => line.slice('          - '.length))

const verifyStep = workflow.slice(workflow.indexOf('- name: Verify the desktop boundary'))
const verifyArguments = verifyStep.match(/run: npm run desktop:boundary:verify -- (.+)/)?.[1]

function withFakeNpm(body) {
  const scratch = mkdtempSync(join(tmpdir(), 'sesame-boundary-contract-'))
  const log = join(scratch, 'npm.log')
  const fakeNpm = join(scratch, 'fake-npm.mjs')
  const copies = join(scratch, 'copies')
  writeFileSync(fakeNpm, "import { appendFileSync } from 'node:fs'\nappendFileSync(process.env.FICTIONAL_NPM_LOG, `${process.argv.slice(2).join(' ')}\\n`)\n")
  mkdirSync(copies)
  try {
    body({
      leftoverCopies: () => readdirSync(copies),
      commands: () => (readdirSync(scratch).includes('npm.log') ? readFileSync(log, 'utf8').trim().split('\n') : []),
      environment: { ...process.env, npm_execpath: fakeNpm, FICTIONAL_NPM_LOG: log, TMPDIR: copies },
    })
  } finally {
    rmSync(scratch, { recursive: true, force: true })
  }
}

function runVerifier(argumentsLine, environment) {
  return spawnSync('bash', ['-c', `node "${verifier}" --run ${argumentsLine}`], { cwd: root, env: environment, encoding: 'utf8' })
}

test('every boundary matrix entry reaches the verifier whole and the verifier runs every name in it', () => {
  assert.ok(verifyArguments, 'the boundary workflow no longer runs the verifier')
  assert.ok(matrixEntries.some((entry) => entry.includes(' ')), 'the boundary matrix has no entry with several scripts')
  for (const entry of matrixEntries) {
    withFakeNpm(({ commands, leftoverCopies, environment }) => {
      const result = runVerifier(verifyArguments.replaceAll('${{ matrix.script }}', entry), { ...environment, BOUNDARY_SCRIPTS: entry })
      assert.equal(result.status, 0, `${entry}: ${result.stderr}`)
      assert.deepEqual(commands(), ['ci', ...entry.split(' ').map((name) => `run ${name}`)], entry)
      assert.deepEqual(leftoverCopies(), [], `${entry} left its copy behind`)
    })
  }
})

test('a script list that the shell split into several arguments fails before anything runs', () => {
  withFakeNpm(({ commands, leftoverCopies, environment }) => {
    const result = runVerifier('--script desktop:build desktop:lint:rust', environment)
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /Unexpected arguments: desktop:lint:rust/)
    assert.deepEqual(commands(), [])
    assert.deepEqual(leftoverCopies(), [])
  })
})

test('stray arguments without a script flag are refused', () => {
  withFakeNpm(({ commands, environment }) => {
    const result = runVerifier('desktop:build', environment)
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /Unexpected arguments: desktop:build/)
    assert.deepEqual(commands(), [])
  })
})

test('a script name outside the desktop scripts is refused', () => {
  withFakeNpm(({ commands, environment }) => {
    const result = runVerifier('--script "desktop:build release:publish"', environment)
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /--script needs desktop npm script names/)
    assert.deepEqual(commands(), [])
  })
})
