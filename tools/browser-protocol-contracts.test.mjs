import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import test from 'node:test'

// The extension checks its vendored copy from its own side; this asserts the
// half only this repository can see.
const root = process.cwd()
const canonical = join(root, 'src-tauri', 'contracts', 'browser', 'v1')
const cardCanonical = join(root, 'src-tauri', 'contracts', 'browser', 'v2')

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

test('card protocol v2 is HTTPS-only, card-only, and regression-vectored', () => {
  const contract = json(join(cardCanonical, 'contract.json'))
  const requestSchema = json(join(cardCanonical, 'request.schema.json'))
  const responseSchema = json(join(cardCanonical, 'response.schema.json'))
  const vectors = json(join(cardCanonical, 'vectors.json'))
  const rust = readFileSync(join(root, 'src-tauri', 'src', 'browser_protocol.rs'), 'utf8')

  assert.equal(contract.protocolVersion, 2)
  assert.deepEqual(contract.requestTypes, ['card'])
  assert.equal(contract.compatibility.minimumHostProtocolVersion, 2)
  assert.equal(contract.compatibility.currentHostProtocolVersion, 2)
  assert.deepEqual(contract.cardFieldKeys, [
    'cardholderName',
    'number',
    'expiryMonth',
    'expiryYear',
    'securityCode',
  ])
  assert.equal(requestSchema.properties.origin.pattern, '^https://[^/]+$')
  assert.ok(contract.responseTypes.includes('error'))

  const cardResponse = responseSchema.oneOf.find((branch) => branch.properties.type.const === 'card')
  assert.deepEqual(cardResponse.required, ['version', 'type', 'requestId', 'card'])
  assert.equal(cardResponse.additionalProperties, false)
  assert.equal(cardResponse.properties.card.additionalProperties, false)
  assert.deepEqual(Object.keys(cardResponse.properties.card.properties), contract.cardFieldKeys)
  assert.equal(vectors.protocolVersion, contract.protocolVersion)
  assert.equal(vectors.fictionalDataOnly, true)
  assert.ok(
    vectors.requestCases.some(
      (entry) => entry.valid === false && entry.name.includes('repeated fields'),
    ),
  )
  assert.ok(
    vectors.responseCases.some(
      (entry) => entry.hostValid === false && entry.name.includes('extra field'),
    ),
  )
  assert.match(rust, /pub const CARD_PROTOCOL_VERSION: u8 = 2;/)
  assert.match(rust, /origin\.starts_with\("https:\/\/"\)/)
})
