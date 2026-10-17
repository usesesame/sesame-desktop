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

const runScriptBlocks = (body) => {
  const lines = body.split('\n')
  const scripts = []
  for (let index = 0; index < lines.length; index += 1) {
    const match = lines[index].match(/^(\s*)run:\s*(.*)$/)
    if (!match) continue
    const [, indentation, value] = match
    if (!/^[>|][+-]?\s*$/.test(value)) {
      scripts.push(value)
      continue
    }
    const content = []
    while (index + 1 < lines.length) {
      const line = lines[index + 1]
      if (line.trim() !== '' && line.match(/^\s*/)[0].length <= indentation.length) break
      content.push(line)
      index += 1
    }
    scripts.push(content.join('\n'))
  }
  return scripts
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
  for (const [workflow, signingJob, publishJob] of [
    ['release-early-access.yml', 'sign-and-attest', 'publish-candidate'],
    ['release-linux-early-access.yml', 'sign-and-attest', 'publish'],
  ]) {
    const body = read('.github', 'workflows', workflow)
    const job = jobBlock(body, signingJob)
    assert.match(job, /^\s+id-token:\s*write\s*$/m, `${workflow} signs keylessly in ${signingJob} and needs an OIDC token there`)
    assert.match(job, /^\s+environment:\s*release-build\s*$/m, `${workflow} should build ${signingJob} behind its protected environment`)
    const publishBlock = jobBlock(body, publishJob)
    assert.match(
      publishBlock,
      /^\s+environment:\s*release-publish\s*$/m,
      `${workflow} should publish behind its protected environment`,
    )
  }
})

test('the Windows release build resolves the public keys without a signing key or OIDC identity', () => {
  const body = read('.github', 'workflows', 'release-early-access.yml')
  const build = jobBlock(body, 'build')
  assert.match(
    build,
    /^\s+environment:\s*release-build\s*$/m,
    'the release build takes the candidate public key from release-build and must carry no private key',
  )
  assert.doesNotMatch(build, /id-token/, 'the release build must not be able to mint an OIDC token')
  for (const secret of ['TAURI_SIGNING_PRIVATE_KEY', 'TAURI_SIGNING_PRIVATE_KEY_PASSWORD', 'SESAME_RELEASE_CANDIDATE_SIGNING_KEY']) {
    assert.doesNotMatch(build, new RegExp(secret), `${secret} must not be available to the release build`)
  }
  const sign = jobBlock(body, 'sign-and-attest')
  assert.match(sign, /^\s+id-token:\s*write\s*$/m, 'the signing job needs an OIDC token for keyless Sigstore')
  assert.match(sign, /^\s+environment:\s*release-build\s*$/m, 'the signing job must run behind its protected environment')
})

test('the Linux release build resolves the capability key without a signing key or OIDC identity', () => {
  const body = read('.github', 'workflows', 'release-linux-early-access.yml')
  const build = jobBlock(body, 'build-and-test')
  assert.doesNotMatch(build, /^\s+environment:\s*release-build\s*$/m, 'the Linux release build must not run behind the signing environment')
  assert.doesNotMatch(build, /id-token/, 'the Linux release build must not be able to mint an OIDC token')
  assert.doesNotMatch(build, /SESAME_RELEASE_CANDIDATE_SIGNING_KEY/, 'the candidate signing key must not be available to the Linux release build')
  const sign = jobBlock(body, 'sign-and-attest')
  assert.match(sign, /^\s+id-token:\s*write\s*$/m, 'the Linux signing job needs an OIDC token for keyless Sigstore')
  assert.match(sign, /^\s+environment:\s*release-build\s*$/m, 'the Linux signing job must run behind its protected environment')
})

test('release build outputs reach the signing jobs as data, never as script text', () => {
  const body = read('.github', 'workflows', 'release-early-access.yml')
  for (const script of runScriptBlocks(body)) {
    assert.doesNotMatch(script, /needs\.build\.outputs/, 'a build job output is pasted into a run script')
    assert.doesNotMatch(script, /steps\.installer\.outputs\.path/, 'the installer path is pasted into a run script')
  }
  const sign = jobBlock(body, 'sign-and-attest')
  assert.match(sign, /^\s+EXPECTED_INSTALLER:\s*\$\{\{\s*needs\.build\.outputs\.installer\s*\}\}\s*$/m, 'the expected installer name must arrive as environment data')
  assert.match(sign, /^\s+EXPECTED_SHA256:\s*\$\{\{\s*needs\.build\.outputs\.installer-sha256\s*\}\}\s*$/m, 'the expected installer digest must arrive as environment data')
  assert.match(sign, /^\s+INSTALLER_PATH:\s*\$\{\{\s*steps\.installer\.outputs\.path\s*\}\}\s*$/m, 'the signing step must read its path from the environment')
  assert.doesNotMatch(sign, /build-output/, 'the signing job must not reach into the build job output directory')
  assert.doesNotMatch(sign, /verify-updater-artifact/, 'the signing job must not run a verifier compiled by the build job')
  assert.doesNotMatch(sign, /SESAME_RELEASE_CANDIDATE_SIGNING_KEY/, 'the candidate signing key must stay out of the updater signing job')
  const receipt = jobBlock(body, 'candidate-receipt')
  assert.match(receipt, /^\s+needs:\s*\[sign-and-attest, verify-fresh\]\s*$/m, 'the candidate receipt must run after independent verification and must be able to read the manifest from the signing job')
  assert.match(receipt, /^\s+environment:\s*release-build\s*$/m, 'the candidate receipt runs behind the protected release environment')
  assert.match(receipt, /^\s+permissions:\s*\n\s+contents:\s*read\s*$/m, 'the candidate receipt only reads repository contents')
  assert.doesNotMatch(receipt, /id-token/, 'the candidate receipt must not mint an OIDC token')
  assert.match(receipt, /SESAME_RELEASE_CANDIDATE_SIGNING_KEY/, 'the candidate receipt holds the candidate signing key')
  assert.doesNotMatch(receipt, /cargo|desktop:host:stage|rust-toolchain/, 'the candidate receipt must not compile or stage build tools')
  assert.match(receipt, /needs\.verify-fresh\.outputs\.candidate-sha256/, 'the receipt must compare the prepared candidate against the independent job digest')
  assert.match(receipt, /create-updater-artifacts\.mjs --sign/, 'the receipt must sign prepared data only')
  assert.doesNotMatch(receipt, /SESAME_UPDATER_VERIFY_BIN|verify-updater-artifact/, 'the receipt must not execute a compiled verifier')
  const verify = jobBlock(body, 'verify-fresh')
  assert.match(verify, /name: sesame-candidate-input-/, 'independent verification must publish prepared candidate data')
  assert.doesNotMatch(verify, /SESAME_RELEASE_CANDIDATE_SIGNING_KEY|TAURI_SIGNING_PRIVATE_KEY/, 'the verifier build must not have private signing keys')
  assert.match(receipt, /name:\s*sesame-candidate-\$\{\{ github\.ref_name \}\}\n\s+path:\s*candidate-receipt\s*$/m, 'the candidate receipt uploads the candidate files from their own directory')
  const publish = jobBlock(body, 'publish-candidate')
  assert.match(publish, /needs:[^\n]*candidate-receipt/, 'publish waits for the candidate receipt')
  assert.match(publish, /name:\s*sesame-candidate-\$\{\{ github\.ref_name \}\}\n\s+path:\s*release-handoff\s*$/m, 'publish merges the candidate files into the handoff directory')
})

test('the Linux workflow passes plain manifest filenames to the handoff tools', () => {
  const body = read('.github', 'workflows', 'release-linux-early-access.yml')
  const calls = body.split('\n').filter((line) => /tools\/(verify-linux-handoff|verify-linux-release-evidence|create-linux-release-candidate|create-linux-sigstore-evidence)\.mjs\s+release-handoff/.test(line))
  assert.ok(calls.length >= 1, 'the workflow must call a handoff tool on one line')
  for (const line of calls) assert.match(line, /"\$\(basename /, `a handoff tool needs a bare filename: ${line.trim()}`)
})

test('a release a maintainer already published does not fail the stays-unpublished check', () => {
  const cases = [
    ['release-linux-early-access.yml', '\n  publish:\n', 'Prove the release stays unpublished'],
    ['release-early-access.yml', '\n  publish-candidate:\n', 'Prove the release stays unpublished until signing'],
  ]
  for (const [file, jobStart, stepName] of cases) {
    const body = read('.github', 'workflows', file)
    const job = body.slice(body.indexOf(jobStart))
    assert.match(job, /name: Record when this job started\n\s+run: echo "JOB_STARTED_AT=\$\(date -u [^\n]*>> "\$GITHUB_ENV"/, `${file} must record the job start before it publishes`)
    const step = job.slice(job.indexOf(`name: ${stepName}`))
    const block = step.slice(0, step.indexOf('\n      - name:', 10))
    assert.match(block, /--json isDraft,publishedAt/, `${file} must read when the release was published`)
    assert.match(block, /"\$published_at" < "\$JOB_STARTED_AT"\s*\]\]; then[\s\S]*?exit 0/, `${file} must pass when the release was published before this job started`)
    assert.match(block, /This job published the release[^\n]*>&2\n\s+exit 1/, `${file} must still fail when this job published the release`)
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


test('private signing jobs cannot compile application code or stage sidecars', () => {
  for (const workflow of workflows) {
    const body = read(workflow)
    for (const [, name] of body.matchAll(/^ {2}([a-z0-9_-]+):$/gm)) {
      const job = jobBlock(body, name)
      if (!/secrets\.(?:SESAME_RELEASE_CANDIDATE_SIGNING_KEY|TAURI_SIGNING_PRIVATE_KEY)\s*\}\}/.test(job)) continue
      for (const script of runScriptBlocks(job)) {
        assert.doesNotMatch(script, /cargo\s+(?:build|test|run|install)|desktop:host:stage|tauri\s+build|desktop:ci|release:check/, `${workflow} ${name} compiles code beside a signing key`)
      }
    }
  }
})
