import assert from 'node:assert/strict'
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const read = (...parts) => readFileSync(join(root, ...parts), 'utf8')

const workflows = readdirSync(join(root, '.github', 'workflows'))
  .filter((name) => /\.(ya?ml)$/.test(name))
  .map((name) => join('.github', 'workflows', name))
  .sort()

const topLevelPermissions = (body) => {
  const start = body.match(/^permissions:\s*$/m)
  assert.ok(start, 'the workflow declares no top-level permissions block')
  const rest = body.slice(start.index + start[0].length)
  const end = rest.search(/^[^\s#]/m)
  return end >= 0 ? rest.slice(0, end) : rest
}

const jobBlock = (body, job) => {
  const start = body.indexOf(`\n  ${job}:\n`)
  assert.ok(start >= 0, `the ${job} job is missing from the workflow`)
  const rest = body.slice(start + 1)
  const afterFirst = rest.indexOf('\n') + 1
  const next = rest.slice(afterFirst).match(/^ {2}[a-z0-9_-]+:$/m)
  return next ? rest.slice(0, afterFirst + next.index) : rest
}

test('every workflow declares permissions and pins every third-party action', () => {
  assert.ok(workflows.length >= 4, `expected this repository's workflows, found ${workflows.length}`)

  const missingPermissions = []
  const unpinned = []
  for (const workflow of workflows) {
    const body = read(workflow)
    if (!/^permissions:\s*$/m.test(body)) missingPermissions.push(workflow)
    for (const [, action] of body.matchAll(/uses:\s*([^\s#]+)/g)) {
      if (action.startsWith('./')) continue
      if (!/@[0-9a-f]{40}$/.test(action)) unpinned.push(`${workflow}: ${action}`)
    }
  }
  assert.deepEqual(missingPermissions, [], `these workflows inherit their permissions:\n  ${missingPermissions.join('\n  ')}`)
  assert.deepEqual(unpinned, [], `a moved tag would change what these runs execute:\n  ${unpinned.join('\n  ')}`)
})

test('a workflow that writes says so at the job that writes', () => {
  for (const workflow of workflows) {
    const body = read(workflow)
    const entries = [...topLevelPermissions(body).matchAll(/^\s+([a-z-]+):\s*([a-z-]+)\s*$/gm)]
      .map(([, key, value]) => `${key}: ${value}`)
    assert.deepEqual(
      entries,
      ['contents: read'],
      `${workflow} should default to exactly contents: read at the top and widen per job`,
    )
  }
  for (const [workflow, signingJob] of [
    ['release-early-access.yml', 'build-and-attest'],
    ['release-linux-early-access.yml', 'build-and-test'],
  ]) {
    const body = read('.github', 'workflows', workflow)
    const job = jobBlock(body, signingJob)
    assert.match(job, /^\s+id-token:\s*write\s*$/m, `${workflow} signs keylessly in ${signingJob} and needs an OIDC token there`)
    assert.match(job, /^\s+environment:\s*release-build\s*$/m, `${workflow} should build ${signingJob} behind its protected environment`)
    const publishBlock = jobBlock(body, signingJob === 'build-and-attest' ? 'publish-candidate' : 'publish')
    assert.match(
      publishBlock,
      /^\s+environment:\s*release-publish\s*$/m,
      `${workflow} should publish behind its protected environment`,
    )
  }
})

test('every job a workflow depends on exists in that workflow', () => {
  for (const workflow of workflows) {
    const body = read(workflow)
    const names = new Set([...body.matchAll(/^ {2}([a-z0-9_-]+):$/gm)].map(([, name]) => name))
    for (const [, list] of body.matchAll(/^\s+needs:\s*(.+)$/gm)) {
      for (const name of list.replaceAll('[', ' ').replaceAll(']', ' ').split(',')) {
        const job = name.trim()
        if (!job) continue
        assert.ok(names.has(job), `${workflow} requires job ${job}, which the workflow does not define`)
      }
    }
  }
})

test('review routing names paths that exist in this repository', () => {
  const owners = read('.github', 'CODEOWNERS')
  assert.match(owners, /^\*\s+@/m, 'the repository has no default owner')
  for (const control of ['/.github/', '/package.json']) {
    assert.ok(owners.includes(control), `the repository does not route ${control}`)
  }
  for (const control of ['/package-lock.json', '/src-tauri/Cargo.lock']) {
    assert.ok(owners.includes(control), `the repository does not route ${control}`)
  }
  for (const [, routed] of owners.matchAll(/^(\/[^\s#]+)/gm)) {
    assert.ok(
      existsSync(join(root, routed.slice(1))),
      `CODEOWNERS routes ${routed}, which does not exist in this repository`,
    )
  }
})

test('every dependency ecosystem this repository uses is updated', () => {
  const body = read('.github', 'dependabot.yml')
  for (const ecosystem of ['npm', 'cargo', 'github-actions']) {
    assert.match(body, new RegExp(`package-ecosystem: ${ecosystem}\\b`), `dependabot does not update ${ecosystem}`)
  }
})

test('the security policy tells a reporter where to send a vulnerability', () => {
  const path = join('.github', 'SECURITY.md')
  assert.ok(statSync(join(root, path)).isFile())
  const body = read(path)
  assert.match(body, /Do not open a public issue/i, 'the policy does not say to report privately')
  assert.match(body, /Report a vulnerability/, 'the policy does not name the private reporting route')
  assert.match(body, /## Scope/, 'the policy has no scope, so a reporter cannot tell what counts')
  assert.match(body, /vault/i, 'the policy is not scoped to this product')
})
