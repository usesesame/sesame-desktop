import assert from 'node:assert/strict'
import { createPublicKey, verify } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { FRESHNESS_LABEL, freshnessPayload, generateFreshnessKey, signFreshness } from './update-freshness.mjs'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const spki = (publicKey) => createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(publicKey, 'base64url')]), format: 'der', type: 'spki' })

test('the payload is three lines, the label, the version and the time', () => {
  assert.equal(FRESHNESS_LABEL, 'sesame-update-freshness-v1')
  assert.equal(freshnessPayload('0.4.4', 1_800_000_000), 'sesame-update-freshness-v1\n0.4.4\n1800000000')
})

test('a signed statement verifies under the public key and names its key id', () => {
  const key = generateFreshnessKey()
  const statement = signFreshness({ seed: key.seed, keyId: 'fictional-freshness-key', version: '0.4.4', issuedAt: 1_800_000_000 })
  assert.deepEqual(Object.keys(statement).sort(), ['payload', 'signature', 'signingKeyId'])
  assert.equal(statement.signingKeyId, 'fictional-freshness-key')
  assert.equal(verify(null, Buffer.from(statement.payload), spki(key.publicKey), Buffer.from(statement.signature, 'base64url')), true)
  statement.payload = freshnessPayload('0.4.5', 1_800_000_000)
  assert.equal(verify(null, Buffer.from(statement.payload), spki(key.publicKey), Buffer.from(statement.signature, 'base64url')), false)
})

test('a version that is not a plain release and a time that is not a whole number are refused', () => {
  const key = generateFreshnessKey()
  for (const version of ['0.4', '0.4.4-beta.1', 'v0.4.4', '0.04.4', '']) {
    assert.throws(() => signFreshness({ seed: key.seed, keyId: 'k', version, issuedAt: 1 }), /version/, version)
  }
  for (const issuedAt of [-1, 1.5, '1', Number.NaN, 2 ** 60]) {
    assert.throws(() => signFreshness({ seed: key.seed, keyId: 'k', version: '0.4.4', issuedAt }), /time/, String(issuedAt))
  }
  assert.throws(() => signFreshness({ seed: 'short', keyId: 'k', version: '0.4.4', issuedAt: 1 }), /seed/)
  assert.throws(() => signFreshness({ seed: key.seed, keyId: '', version: '0.4.4', issuedAt: 1 }), /key id/)
})

test('the committed fixture was made by this tool and the Rust side verifies the same bytes', () => {
  const fixture = JSON.parse(readFileSync(join(root, 'src-tauri', 'tests', 'fixtures', 'update-freshness', 'statement.json'), 'utf8'))
  assert.equal(fixture.statement.payload, freshnessPayload('0.4.4', 1_800_000_000))
  assert.equal(verify(null, Buffer.from(fixture.statement.payload), spki(fixture.publicKey), Buffer.from(fixture.statement.signature, 'base64url')), true)
  const again = signFreshness({ seed: fixture.fictionalSeed, keyId: fixture.statement.signingKeyId, version: '0.4.4', issuedAt: 1_800_000_000 })
  assert.deepEqual(again, fixture.statement)
})

const read = (...parts) => readFileSync(join(root, ...parts), 'utf8')

test('the scheduled job holds the key only in its environment, pins its actions and guards the latest release', () => {
  const workflow = read('.github', 'workflows', 'update-freshness.yml')
  assert.match(workflow, /environment: freshness/)
  assert.match(workflow, /SESAME_UPDATE_FRESHNESS_SIGNING_KEY: \$\{\{ secrets\.SESAME_UPDATE_FRESHNESS_SIGNING_KEY \}\}/)
  assert.equal([...workflow.matchAll(/SESAME_UPDATE_FRESHNESS_SIGNING_KEY/g)].length, 2, 'the key name appears only in the one signing step')
  for (const line of workflow.split('\n').filter((entry) => entry.includes('uses:'))) {
    assert.match(line, /@[0-9a-f]{40} # v/, `${line.trim()} must pin a commit`)
  }
  assert.ok(workflow.includes('permissions:\n  contents: read\n'), 'the workflow default is read only')
  assert.match(workflow, /isPrerelease,isDraft/)
  assert.match(workflow, /must exist and be a published pre-release/)
  assert.ok(workflow.indexOf('Require the freshness release to be a pre-release') < workflow.indexOf('Replace the statement on the freshness release'), 'the pre-release check comes before the upload')
  assert.doesNotMatch(workflow, /echo[^\n]*SIGNING_KEY|set -x|run:[^\n]*\$\{\{ secrets/, 'the key is never printed or placed on a command line')
  assert.doesNotMatch(workflow, /gh release create/, 'the job never creates a tag, which the tag ruleset reserves')
})

test('the Windows build forwards the freshness settings and the app treats a missing one as off', () => {
  const release = read('.github', 'workflows', 'release-early-access.yml')
  assert.match(release, /SESAME_UPDATE_FRESHNESS_URL: https:\/\/github\.com\/\$\{\{ github\.repository \}\}\/releases\/download\/freshness\/freshness\.json/)
  assert.match(release, /SESAME_UPDATE_FRESHNESS_PUBLIC_KEY: \$\{\{ vars\.SESAME_UPDATE_FRESHNESS_PUBLIC_KEY \}\}/)
  assert.match(release, /SESAME_UPDATE_FRESHNESS_KEY_ID: \$\{\{ vars\.SESAME_UPDATE_FRESHNESS_KEY_ID \}\}/)
  const required = release.match(/\$required = ([^\n]*)/)?.[1] ?? ''
  assert.doesNotMatch(required, /FRESHNESS/, 'a build without the key still ships, with the check off')
  const build = read('src-tauri', 'build.rs')
  for (const name of ['SESAME_UPDATE_FRESHNESS_URL', 'SESAME_UPDATE_FRESHNESS_PUBLIC_KEY', 'SESAME_UPDATE_FRESHNESS_KEY_ID']) {
    assert.match(build, new RegExp(`rerun-if-env-changed=${name}`))
  }
  const updates = read('src-tauri', 'src', 'adapters', 'network', 'public_updates.rs')
  assert.match(updates, /pub\(crate\) fn freshness_trust\(\) -> Option</)
})

test('the freshness code only informs and never installs or lowers a floor', () => {
  const source = read('src-tauri', 'src', 'adapters', 'network', 'update_freshness.rs').split('#[cfg(test)]')[0]
  assert.doesNotMatch(source, /download_and_install|install_update|raise_floor|record_manifest_floor|create_dir/)
  const updater = read('src-tauri', 'src', 'commands', 'updater.rs')
  const fn = updater.match(/pub async fn check_desktop_update[\s\S]*?\n}\n/)?.[0] ?? ''
  assert.match(fn, /update_freshness::current/)
})
