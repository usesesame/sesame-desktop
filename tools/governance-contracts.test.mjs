import assert from 'node:assert/strict'
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const read = (...parts) => readFileSync(join(root, ...parts), 'utf8')

const PRODUCTS = [
  { repository: 'usesesame/sesame-desktop', path: '.', github: '.github' },
  { repository: 'usesesame/sesame-browser-extension', path: 'extensions/sesame', github: 'extensions/sesame/.github' },
  { repository: 'usesesame/sesame-server', path: 'backend', github: 'backend/.github' },
  { repository: 'usesesame/sesame-website', path: 'website', github: 'website/.github' },
]
const PORTALS = ['admin', 'account']

function workflowsIn(directory) {
  const path = join(root, directory, 'workflows')
  if (!existsSync(path)) return []
  return readdirSync(path).filter((name) => name.endsWith('.yml')).map((name) => join(directory, 'workflows', name))
}

const allWorkflows = [
  ...PRODUCTS.flatMap(({ github }) => workflowsIn(github)),
  ...PORTALS.flatMap((portal) => workflowsIn(`${portal}/.github`)),
]

test('every workflow declares permissions and pins every third-party action', () => {
  assert.ok(allWorkflows.length >= 8, `expected every product to have workflows, found ${allWorkflows.length}`)

  const missingPermissions = []
  const unpinned = []
  for (const workflow of allWorkflows) {
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
  for (const workflow of allWorkflows) {
    const body = read(workflow)
    const header = body.slice(0, body.indexOf('\njobs:'))
    const declared = /^permissions:\s*\n\s+contents: read\s*$/m.test(header)
    assert.ok(
      declared,
      `${workflow} should default to contents: read at the top and widen per job`,
    )
  }
  const release = read('.github', 'workflows', 'release-early-access.yml')
  assert.match(release, /id-token: write/, 'keyless signing needs an OIDC token')
  assert.match(release, /environment: release-build/)
  assert.match(release, /environment: release-publish/)
})

test('every product routes review for its own sensitive paths', () => {
  for (const { repository, path, github } of [...PRODUCTS, ...PORTALS.map((p) => ({ repository: `portal:${p}`, path: p, github: `${p}/.github` }))]) {
    const owners = join(root, github, 'CODEOWNERS')
    assert.ok(existsSync(owners), `${repository} has no review routing`)
    const body = readFileSync(owners, 'utf8')
    assert.match(body, /^\*\s+@/m, `${repository} has no default owner`)

    for (const control of ['/.github/', '/package.json']) {
      assert.ok(body.includes(control), `${repository} does not route ${control}`)
    }

    for (const [, routed] of body.matchAll(/^(\/[^\s#]+)/gm)) {
      const target = join(root, path, routed.slice(1))
      assert.ok(existsSync(target), `${repository} routes ${routed}, which does not exist`)
    }
  }
})

test('a lockfile change is routed everywhere it exists', () => {
  const desktop = read('.github', 'CODEOWNERS')
  for (const lockfile of ['/package-lock.json', '/src-tauri/Cargo.lock', '/backend/go.sum']) {
    assert.ok(desktop.includes(lockfile), `the monorepo does not route ${lockfile}`)
  }
  for (const product of ['website', 'admin', 'account', 'extensions/sesame']) {
    const owners = read(product, '.github', 'CODEOWNERS')
    assert.ok(owners.includes('/package-lock.json'), `${product} does not route its lockfile`)
  }
  assert.ok(read('backend', '.github', 'CODEOWNERS').includes('/go.sum'), 'the server does not route go.sum')
})

test('every dependency ecosystem a product uses is updated', () => {
  const expected = [
    ['.github', ['npm', 'cargo', 'gomod', 'github-actions']],
    ['extensions/sesame/.github', ['npm', 'github-actions']],
    ['backend/.github', ['gomod', 'npm', 'docker', 'github-actions']],
    ['website/.github', ['npm', 'github-actions']],
    ['admin/.github', ['npm', 'github-actions']],
    ['account/.github', ['npm', 'github-actions']],
  ]
  for (const [directory, ecosystems] of expected) {
    const body = read(directory, 'dependabot.yml')
    for (const ecosystem of ecosystems) {
      assert.match(body, new RegExp(`package-ecosystem: ${ecosystem}\\b`), `${directory} does not update ${ecosystem}`)
    }
    assert.match(body, /package-ecosystem: github-actions/, `${directory} would freeze its pinned actions`)
  }
})

test('every repository tells a reporter where to send a vulnerability', () => {
  const policies = [
    ['.github/SECURITY.md', /vault/i],
    ['extensions/sesame/SECURITY.md', /extension/i],
    ['backend/SECURITY.md', /vault-blind/i],
    ['website/SECURITY.md', /static/i],
  ]
  for (const [path, scoped] of policies) {
    const body = read(path)
    assert.ok(statSync(join(root, path)).isFile())
    assert.match(body, /Do not open a public issue/i, `${path} does not say to report privately`)
    assert.match(body, /Report a vulnerability/, `${path} does not name the private reporting route`)
    assert.match(body, /## Scope/, `${path} has no scope, so a reporter cannot tell what counts`)
    assert.match(body, scoped, `${path} is not scoped to its own product`)
  }
})

test('no required status check names a job no workflow provides', () => {
  const migration = [
    '| `sesame-desktop` | `desktop` |',
    '| `sesame-browser-extension` | `check` |',
    '| `sesame-server` | `server` |',
    '| `sesame-website` | `static-only`, `website` |',
  ].join('\n')
  const jobsOf = (workflow) => [...read(workflow).matchAll(/^ {2}([a-z0-9_-]+):$/gm)].map(([, name]) => name)
  const declared = {
    'sesame-desktop': jobsOf(join('.github', 'workflows', 'future-desktop.yml')),
    'sesame-browser-extension': jobsOf(join('extensions', 'sesame', '.github', 'workflows', 'ci.yml')),
    'sesame-server': jobsOf(join('backend', '.github', 'workflows', 'ci.yml')),
    'sesame-website': jobsOf(join('website', '.github', 'workflows', 'ci.yml')),
  }
  const rows = [...migration.matchAll(/^\| `(sesame-[a-z-]+)` \| (.+?) \|$/gm)]
  assert.equal(rows.length, 4, 'the migration record should list required checks for all four repositories')
  for (const [, repository, checks] of rows) {
    for (const check of checks.split(',').map((value) => value.trim().replace(/`/g, ''))) {
      assert.ok(
        declared[repository].includes(check),
        `${repository} requires a check named ${check}, which no workflow job provides`,
      )
    }
  }
})
