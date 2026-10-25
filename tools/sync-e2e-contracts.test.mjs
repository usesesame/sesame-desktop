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
