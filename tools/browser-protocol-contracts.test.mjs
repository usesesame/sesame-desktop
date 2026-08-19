import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import test from 'node:test'

// The extension checks its vendored copy from its own side; this asserts the
// half only this repository can see.
const root = process.cwd()
const canonical = join(root, 'src-tauri', 'contracts', 'browser', 'v1')

function json(path) {
  return JSON.parse(readFileSync(path, 'utf8'))
}

test('the published contract matches the implementation that serves it', () => {
  const contract = json(join(canonical, 'contract.json'))
  const vectors = json(join(canonical, 'vectors.json'))
  const rust = readFileSync(join(root, 'src-tauri', 'src', 'browser_protocol.rs'), 'utf8')

  assert.equal(contract.protocolVersion, 1)
  assert.equal(contract.compatibility.minimumHostProtocolVersion, 1)
  assert.equal(contract.compatibility.currentHostProtocolVersion, 1)
  assert.equal(vectors.protocolVersion, contract.protocolVersion)
  assert.equal(vectors.fictionalDataOnly, true)
  assert.match(rust, /pub const PROTOCOL_VERSION: u8 = 1;/)
  assert.match(rust, /pub const MAX_CREDENTIAL_FIELD_BYTES: usize = 4096;/)
})

test('the host implementation names no consumer of its protocol', () => {
  const rust = readFileSync(join(root, 'src-tauri', 'src', 'browser_protocol.rs'), 'utf8')
  assert.doesNotMatch(rust, /extensions[\\/]sesame|sesame-browser-extension/)
})

test('browser identity response contract is nested and regression-vectored', () => {
  const schema = json(join(canonical, 'response.schema.json'))
  const vectors = json(join(canonical, 'vectors.json'))
  const identity = schema.$defs.identity
  assert.deepEqual(identity.required, ['version', 'type', 'requestId', 'identity'])
  assert.equal(identity.additionalProperties, false)
  assert.ok(
    vectors.responseCases.some(
      (entry) => entry.hostValid === true && entry.message.type === 'identity' && entry.message.identity,
    ),
  )
  assert.ok(
    vectors.responseCases.some(
      (entry) => entry.hostValid === false && entry.message.type === 'identity' && entry.message.email,
    ),
  )
})
