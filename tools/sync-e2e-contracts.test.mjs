import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

const pin = JSON.parse(readFileSync('src-tauri/contracts/sync/server-pin.json', 'utf8'))
const workflow = readFileSync('.github/workflows/ci.yml', 'utf8')
const job = workflow.slice(workflow.indexOf('\n  linux-rust:'), workflow.indexOf('\n  linux-bundles:'))

test('the Sync server pin names one repository and full commits', () => {
  assert.deepEqual(Object.keys(pin).sort(), ['commit', 'olderCommit', 'repository'])
  assert.equal(pin.repository, 'usesesame/sesame-server')
  assert.match(pin.commit, /^[0-9a-f]{40}$/, 'the pin must be a full commit hash and never a branch or a tag')
  assert.match(pin.olderCommit, /^[0-9a-f]{40}$/, 'the older pin must be a full commit hash')
  assert.notEqual(pin.olderCommit, pin.commit)
})

test('the linux-rust job builds the pinned test server and runs the real round trip', () => {
  assert.ok(job.includes('src-tauri/contracts/sync/server-pin.json'), 'the job no longer reads the pin file')
  assert.match(job, /repository: \$\{\{ steps\.sync-server-pin\.outputs\.repository \}\}/)
  assert.match(job, /ref: \$\{\{ steps\.sync-server-pin\.outputs\.commit \}\}/)
  assert.match(job, /path: sesame-server/)
  assert.match(job, /persist-credentials: false/, 'the server checkout must not keep the job token')
  assert.match(job, /go-version-file: sesame-server\/go\.mod/)
  assert.match(job, /go build -tags synctestserver /)
  assert.match(job, /SESAME_SYNC_E2E_URL/)
  assert.match(job, /SESAME_SYNC_E2E_KEY/)
  assert.match(job, /--ignored/)
  assert.match(job, /the_rust_client_and_engine_round_trip_against_the_real_service/)
})

test('the round trip step fails when no test ran', () => {
  assert.match(job, /test result: ok\. 1 passed/, 'a run that filtered the test out must not count as a pass')
})

test('the test server is stopped when the step ends', () => {
  assert.match(job, /trap .*kill/, 'the background server must be stopped by a trap')
})

test('the linux-rust job also runs the app against a service that predates the hybrid device key', () => {
  assert.match(job, /ref: \$\{\{ steps\.sync-server-pin\.outputs\.older \}\}/)
  assert.match(job, /path: sesame-server-older/)
  assert.match(job, /SESAME_SYNC_E2E_OLD_URL/)
  assert.match(job, /SESAME_SYNC_E2E_OLD_KEY/)
  assert.match(job, /a_hybrid_device_is_told_when_the_service_does_not_accept_its_key_yet/)
  assert.match(job, /a_hybrid_approver_pairs_an_older_device_only_when_the_person_allows_it/)
  assert.match(job, /devices_with_the_older_key_replace_it_and_the_vault_key_rotates_through_the_real_service/)
  assert.equal(job.match(/test result: ok\. 1 passed/g)?.length, 4, 'each of the four runs must prove that exactly one test passed')
})

test('both test servers are stopped when the step ends', () => {
  assert.match(job, /trap 'kill "\$server" "\$older"/)
})

const nightly = readFileSync('.github/workflows/sync-server-nightly.yml', 'utf8')

test('the linux-rust job also runs the app against the real self-host server built from the pinned commit', () => {
  const step = job.slice(job.indexOf('- name: Prove Sync against the real self-host server'))
  assert.ok(step.includes('timeout-minutes: 20'), 'the real server step needs a timeout')
  assert.match(step, /run: node tools\/run-real-sync-station\.mjs --server sesame-server\n/)
  assert.ok(job.indexOf('path: sesame-server\n') < job.indexOf('run-real-sync-station.mjs'), 'the pinned checkout must come before the real server step')
  assert.ok(job.indexOf('go-version-file: sesame-server/go.mod') < job.indexOf('run-real-sync-station.mjs'), 'Go must be set up before the real server step')
  assert.equal(job.match(/run-real-sync-station\.mjs/g)?.length, 1)
})

test('the real server step lets the runner count passes and keeps the four in-memory counts', () => {
  const runner = readFileSync('tools/run-real-sync-station.mjs', 'utf8')
  assert.match(runner, /test result: ok\\\. 1 passed; 0 failed;/)
  assert.match(runner, /code !== 0 \|\| !exactlyOneTestPassed\(output\)/)
  assert.equal(job.match(/test result: ok\. 1 passed/g)?.length, 4)
})

test('the nightly workflow runs on a schedule and by hand with read only access', () => {
  assert.match(nightly, /^on:\n {2}schedule:\n {4}- cron: '[0-9]+ [0-9]+ \* \* \*'\n {2}workflow_dispatch:\n/m)
  assert.match(nightly, /^permissions:\n {2}contents: read\n/m)
  assert.ok(!/\bwrite\b/.test(nightly), 'the nightly workflow must not ask for write access')
  assert.ok(!/pull_request|push:/.test(nightly), 'the nightly workflow must not run on pull requests or pushes')
  assert.equal(nightly.match(/timeout-minutes: \d+/g)?.length, 2, 'each nightly job needs a timeout')
})

test('every action in the nightly workflow is pinned to a full commit', () => {
  const uses = [...nightly.matchAll(/uses: (\S+)/g)].map((match) => match[1])
  assert.ok(uses.length >= 6)
  for (const reference of uses) assert.match(reference, /@[0-9a-f]{40}$/, reference)
})

test('the nightly workflow builds the real server from server main and runs the same station', () => {
  const real = nightly.slice(nightly.indexOf('  real-server-main:'))
  assert.match(real, /repository: usesesame\/sesame-server\n\s+ref: main\n\s+path: sesame-server\n\s+persist-credentials: false/)
  assert.match(real, /go-version-file: sesame-server\/go\.mod/)
  assert.match(real, /run: node tools\/run-real-sync-station\.mjs --server sesame-server\n/)
  assert.match(real, /git -C sesame-server log -1/, 'the run must name the server commit it tested')
})

test('the nightly workflow fails when the pinned server commit is stale', () => {
  const freshness = nightly.slice(nightly.indexOf('  pin-freshness:'), nightly.indexOf('  real-server-main:'))
  assert.match(freshness, /run: node tools\/check-sync-server-pin\.mjs\n/)
  assert.match(freshness, /GITHUB_TOKEN: \$\{\{ github\.token \}\}/)
})
