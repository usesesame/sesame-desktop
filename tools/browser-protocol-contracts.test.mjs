import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import test from 'node:test'

const root = process.cwd()
const canonical = join(root, 'src-tauri', 'contracts', 'browser', 'v1')
const vendored = join(root, 'extensions', 'sesame', 'contracts', 'browser', 'v1')
const contractFiles = [
  'contract.json',
  'request.schema.json',
  'response.schema.json',
  'vectors.json',
]

function bytes(path) {
  return readFileSync(path)
}

function json(path) {
  return JSON.parse(readFileSync(path, 'utf8'))
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

test('browser protocol vendor is an exact digest-bound canonical snapshot', () => {
  const source = json(join(vendored, 'SOURCE.json'))
  assert.equal(source.contractTag, 'browser-protocol-v1')
  assert.match(source.implementationSourceCommit, /^[0-9a-f]{40}$/)
  assert.deepEqual(Object.keys(source.files).sort(), [...contractFiles].sort())

  for (const name of contractFiles) {
    const canonicalBytes = bytes(join(canonical, name))
    const vendoredBytes = bytes(join(vendored, name))
    assert.deepEqual(vendoredBytes, canonicalBytes, `${name} must be byte-identical`)
    assert.equal(sha256(vendoredBytes), source.files[name], `${name} source digest`)
  }
})

test('browser protocol metadata stays aligned with both implementations', () => {
  const contract = json(join(canonical, 'contract.json'))
  const vectors = json(join(canonical, 'vectors.json'))
  const rust = readFileSync(join(root, 'src-tauri', 'src', 'browser_protocol.rs'), 'utf8')
  const typescript = readFileSync(
    join(root, 'extensions', 'sesame', 'src', 'protocol', 'native.ts'),
    'utf8',
  )

  assert.equal(contract.protocolVersion, 1)
  assert.equal(contract.compatibility.minimumHostProtocolVersion, 1)
  assert.equal(contract.compatibility.currentHostProtocolVersion, 1)
  assert.equal(vectors.protocolVersion, contract.protocolVersion)
  assert.equal(vectors.fictionalDataOnly, true)
  assert.match(rust, /pub const PROTOCOL_VERSION: u8 = 1;/)
  assert.match(typescript, /export const PROTOCOL_VERSION = 1/)
  assert.match(rust, /pub const MAX_CREDENTIAL_FIELD_BYTES: usize = 4096;/)
  assert.match(typescript, /export const MAX_CREDENTIAL_FIELD = 4096/)
  assert.doesNotMatch(rust, /extensions[\\/]sesame/)
  assert.doesNotMatch(typescript, /src-tauri|browser_protocol\.rs/)
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
