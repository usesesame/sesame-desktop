import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import test from 'node:test'

// The extension checks its vendored copy from its own side; this asserts the
// half only this repository can see.
const root = process.cwd()
const canonical = join(root, 'src-tauri', 'contracts', 'browser', 'v1')
const cardCanonical = join(root, 'src-tauri', 'contracts', 'browser', 'v2')
const fillMatchCanonical = join(root, 'src-tauri', 'contracts', 'browser', 'v3')
const totpCanonical = join(root, 'src-tauri', 'contracts', 'browser', 'v4')
const lookalikeCanonical = join(root, 'src-tauri', 'contracts', 'browser', 'v5')

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

test('only the current contract version of each message type is accepted', () => {
  const rust = readFileSync(join(root, 'src-tauri', 'src', 'browser_protocol.rs'), 'utf8')
  const v5 = json(join(lookalikeCanonical, 'contract.json'))
  const matrix = {
    capabilities: 1,
    activate: 1,
    identity: 1,
    save: 1,
    card: 2,
    totp: 4,
    fill: 5,
  }

  assert.deepEqual(v5.messageVersions, matrix)
  assert.match(rust, /"fill" => version == LOOKALIKE_PROTOCOL_VERSION/)
  assert.match(rust, /"totp" => version == TOTP_PROTOCOL_VERSION/)
  assert.match(rust, /"card" => version == CARD_PROTOCOL_VERSION/)
  assert.match(
    rust,
    /"save" \| "identity" \| "capabilities" \| "activate" => version == PROTOCOL_VERSION/,
  )
  assert.match(rust, /supported_protocol_version\(&self\.message_type, self\.version\)/)

  const directories = { 1: 'v1', 2: 'v2', 4: 'v4', 5: 'v5' }
  for (const [messageType, version] of Object.entries(matrix)) {
    if (messageType === 'fill') continue
    const contract = json(join(root, 'src-tauri', 'contracts', 'browser', directories[version], 'contract.json'))
    assert.ok(
      contract.requestTypes.includes(messageType),
      `${messageType} is not declared on protocol ${version}`,
    )
  }
  assert.deepEqual(json(join(canonical, 'contract.json')).requestTypes, [
    'capabilities',
    'activate',
    'identity',
    'save',
  ])
  assert.equal(
    json(join(cardCanonical, 'contract.json')).compatibility.currentHostProtocolVersion,
    2,
  )
  assert.equal(
    json(join(totpCanonical, 'contract.json')).compatibility.currentHostProtocolVersion,
    4,
  )
  for (const directory of ['v1', 'v2', 'v3', 'v4', 'v5']) {
    const vectors = json(join(root, 'src-tauri', 'contracts', 'browser', directory, 'vectors.json'))
    for (const entry of vectors.requestCases) {
      if (entry.valid) {
        assert.equal(
          entry.message.version,
          matrix[entry.message.type],
          `${directory} accepted ${entry.name} on the wrong version`,
        )
      }
    }
  }
})

test('capabilities answer desktop availability only', () => {
  const schema = json(join(canonical, 'response.schema.json'))
  const capabilities = schema.$defs.capabilities
  assert.deepEqual(capabilities.required, [
    'version',
    'type',
    'requestId',
    'installed',
    'desktopAvailable',
  ])
  assert.deepEqual(Object.keys(capabilities.properties), capabilities.required)
  assert.equal(capabilities.additionalProperties, false)

  const rust = readFileSync(join(root, 'src-tauri', 'src', 'browser_protocol.rs'), 'utf8')
  assert.match(rust, /pub fn capabilities\(request_id: &str, desktop_available: bool\)/)
  assert.match(
    rust,
    /self\.installed == Some\(true\)\s*&& self\.desktop_available\.is_some\(\)\s*&& self\.locked\.is_none\(\)\s*&& self\.fill_available\.is_none\(\)/,
  )

  const fill = readFileSync(join(root, 'src-tauri', 'src', 'browser_fill.rs'), 'utf8')
  assert.doesNotMatch(fill, /capabilities\s*\([^)]*locked/)

  const preApprovalSlices = [
    ['browser_fill.rs', fill, 'fn fill_response'],
    ['browser_fill.rs', fill, 'fn save_response'],
    ['browser_fill.rs', fill, 'fn card_response'],
    [
      'browser_fill_identity_approval.rs',
      readFileSync(join(root, 'src-tauri', 'src', 'browser_fill_identity_approval.rs'), 'utf8'),
      'fn identity_response',
    ],
    [
      'browser_fill_totp_approval.rs',
      readFileSync(join(root, 'src-tauri', 'src', 'browser_fill_totp_approval.rs'), 'utf8'),
      'fn totp_response',
    ],
  ]
  for (const [file, source, functionName] of preApprovalSlices) {
    const start = source.indexOf(functionName)
    const end = source.indexOf('fill_state.begin(', start)
    assert.ok(start >= 0 && end > start, `${file} does not declare ${functionName}`)
    assert.doesNotMatch(
      source.slice(start, end),
      /"locked"|"multipleMatches"/,
      `${functionName} answers before approval with a distinguishable reason`,
    )
  }
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

test('fill match protocol v3 reports the enforced rule and is regression-vectored', () => {
  const contract = json(join(fillMatchCanonical, 'contract.json'))
  const requestSchema = json(join(fillMatchCanonical, 'request.schema.json'))
  const responseSchema = json(join(fillMatchCanonical, 'response.schema.json'))
  const vectors = json(join(fillMatchCanonical, 'vectors.json'))
  const v1ResponseSchema = json(join(canonical, 'response.schema.json'))
  const rust = readFileSync(join(root, 'src-tauri', 'src', 'browser_protocol.rs'), 'utf8')

  assert.equal(contract.protocolVersion, 3)
  assert.deepEqual(contract.requestTypes, ['fill'])
  assert.deepEqual(contract.matchKinds, ['exact', 'wwwAlias'])
  assert.equal(contract.supersededByProtocolVersion, 5)
  assert.equal(contract.compatibility.minimumHostProtocolVersion, 5)
  assert.equal(contract.compatibility.currentHostProtocolVersion, 5)
  assert.equal(requestSchema.properties.version.const, 3)
  assert.equal(requestSchema.properties.type.const, 'fill')
  assert.deepEqual(responseSchema.$defs.matchKind.enum, contract.matchKinds)

  for (const name of ['fillBoth', 'fillUsername', 'fillPassword']) {
    assert.ok(responseSchema.$defs[name].required.includes('matchKind'), `${name} requires matchKind`)
  }
  assert.equal(v1ResponseSchema.$defs.fillBoth.required.includes('matchKind'), false)

  assert.equal(vectors.protocolVersion, contract.protocolVersion)
  assert.equal(vectors.fictionalDataOnly, true)
  for (const kind of contract.matchKinds) {
    assert.ok(
      vectors.responseCases.some(
        (entry) => entry.hostValid === true && entry.message.matchKind === kind,
      ),
      `no accepted vector reports ${kind}`,
    )
  }
  assert.ok(
    vectors.responseCases.some(
      (entry) => entry.hostValid === false && entry.message.matchKind === 'parentDomain',
    ),
  )
  assert.ok(
    vectors.responseCases.some(
      (entry) => entry.hostValid === false && entry.message.version === 1,
    ),
  )
  assert.match(rust, /pub const FILL_MATCH_PROTOCOL_VERSION: u8 = 3;/)
  assert.match(rust, /fn valid_match_kind\(value: &str\) -> bool/)
  assert.match(rust, /"exact" \| "wwwAlias"/)
})

test('lookalike protocol v5 warns with a bounded stored host and is regression-vectored', () => {
  const contract = json(join(lookalikeCanonical, 'contract.json'))
  const requestSchema = json(join(lookalikeCanonical, 'request.schema.json'))
  const responseSchema = json(join(lookalikeCanonical, 'response.schema.json'))
  const vectors = json(join(lookalikeCanonical, 'vectors.json'))
  const v3RequestSchema = json(join(fillMatchCanonical, 'request.schema.json'))
  const v3ResponseSchema = json(join(fillMatchCanonical, 'response.schema.json'))
  const rust = readFileSync(join(root, 'src-tauri', 'src', 'browser_protocol.rs'), 'utf8')

  assert.equal(contract.tag, 'browser-protocol-v5')
  assert.equal(contract.protocolVersion, 5)
  assert.deepEqual(contract.requestTypes, ['fill'])
  assert.deepEqual(contract.matchKinds, ['exact', 'wwwAlias'])
  assert.equal(contract.compatibility.minimumHostProtocolVersion, 5)
  assert.equal(contract.compatibility.currentHostProtocolVersion, 5)
  assert.equal(contract.compatibility.minimumExtensionProtocolVersion, 5)
  assert.equal(contract.compatibility.currentExtensionProtocolVersion, 5)
  assert.equal(requestSchema.properties.version.const, 5)
  assert.equal(requestSchema.properties.type.const, 'fill')
  assert.equal(requestSchema.additionalProperties, false)
  assert.deepEqual(requestSchema.required, ['version', 'type', 'requestId', 'origin'])
  assert.equal(requestSchema.properties.origin.maxLength, contract.limits.originBytes)
  assert.equal(v3RequestSchema.properties.version.const, 3)

  assert.deepEqual(
    responseSchema.oneOf.map((branch) => branch.$ref),
    [
      '#/$defs/fillBoth',
      '#/$defs/fillUsername',
      '#/$defs/fillPassword',
      '#/$defs/fillUnavailable',
      '#/$defs/lookalikeUnavailable',
      '#/$defs/error',
    ],
  )
  for (const name of ['fillBoth', 'fillUsername', 'fillPassword']) {
    assert.ok(responseSchema.$defs[name].required.includes('matchKind'), `${name} requires matchKind`)
    assert.equal(responseSchema.$defs[name].properties.version.const, 5)
  }
  assert.deepEqual(responseSchema.$defs.lookalikeUnavailable.required, [
    'version',
    'type',
    'requestId',
    'reason',
    'lookalike',
  ])
  assert.equal(responseSchema.$defs.lookalikeUnavailable.properties.reason.const, 'lookalike')
  assert.equal(responseSchema.$defs.lookalikeUnavailable.additionalProperties, false)
  assert.equal(responseSchema.$defs.lookalikeHost.minLength, 1)
  assert.equal(responseSchema.$defs.lookalikeHost.maxLength, contract.limits.lookalikeHostChars)
  assert.equal(responseSchema.$defs.fillUnavailable.properties.reason.$ref, '#/$defs/reason')
  assert.equal(responseSchema.$defs.reason.enum.includes('lookalike'), false)
  assert.deepEqual(
    [...responseSchema.$defs.reason.enum, 'lookalike'].sort(),
    contract.unavailableReasons.slice().sort(),
  )
  assert.equal(v3ResponseSchema.$defs.reason.enum.includes('lookalike'), false)

  assert.equal(vectors.protocolVersion, contract.protocolVersion)
  assert.equal(vectors.fictionalDataOnly, true)
  assert.ok(
    vectors.requestCases.some((entry) => entry.valid === false && entry.message.version === 4),
    'no vector refuses a fill request on protocol four',
  )
  assert.ok(
    vectors.responseCases.some(
      (entry) =>
        entry.hostValid === true &&
        entry.message.reason === 'lookalike' &&
        entry.message.lookalike === 'apple.com',
    ),
    'no accepted vector reports the stored lookalike host',
  )
  assert.ok(
    vectors.responseCases.some(
      (entry) =>
        entry.hostValid === false &&
        entry.message.reason === 'lookalike' &&
        entry.message.lookalike === undefined,
    ),
    'no vector refuses a lookalike reason without the host',
  )
  assert.ok(
    vectors.responseCases.some(
      (entry) =>
        entry.hostValid === false &&
        entry.message.lookalike !== undefined &&
        entry.message.lookalike.length > contract.limits.lookalikeHostChars,
    ),
    'no vector refuses an over-bound lookalike host',
  )
  assert.ok(
    vectors.responseCases.some((entry) => entry.hostValid === false && entry.message.version === 3),
    'no vector refuses the lookalike reason on protocol three',
  )
  assert.match(rust, /pub const LOOKALIKE_PROTOCOL_VERSION: u8 = 5;/)
  assert.match(rust, /fn valid_lookalike_host\(value: &str\) -> bool/)
  assert.match(rust, /"multipleMatches"\s*\|\s*"lookalike"/)
})

test('totp protocol v4 derives a code only after an origin approval', () => {
  const contract = json(join(totpCanonical, 'contract.json'))
  const requestSchema = json(join(totpCanonical, 'request.schema.json'))
  const responseSchema = json(join(totpCanonical, 'response.schema.json'))
  const vectors = json(join(totpCanonical, 'vectors.json'))
  const v3RequestSchema = json(join(fillMatchCanonical, 'request.schema.json'))
  const rust = readFileSync(join(root, 'src-tauri', 'src', 'browser_protocol.rs'), 'utf8')

  assert.equal(contract.tag, 'browser-protocol-v4')
  assert.equal(contract.protocolVersion, 4)
  assert.deepEqual(contract.requestTypes, ['totp'])
  assert.equal(contract.compatibility.minimumHostProtocolVersion, 4)
  assert.equal(contract.compatibility.currentHostProtocolVersion, 4)
  assert.equal(contract.compatibility.minimumExtensionProtocolVersion, 4)
  assert.equal(contract.compatibility.currentExtensionProtocolVersion, 4)
  assert.equal(requestSchema.properties.version.const, 4)
  assert.equal(requestSchema.properties.type.const, 'totp')
  assert.equal(requestSchema.additionalProperties, false)
  assert.deepEqual(requestSchema.required, ['version', 'type', 'requestId', 'origin'])
  assert.equal(requestSchema.properties.origin.maxLength, contract.limits.originBytes)
  assert.equal(v3RequestSchema.properties.version.const, 3)

  assert.deepEqual(
    responseSchema.oneOf.map((branch) => branch.$ref),
    ['#/$defs/totp', '#/$defs/totpUnavailable', '#/$defs/error'],
  )
  assert.deepEqual(responseSchema.$defs.totp.required, ['version', 'type', 'requestId', 'code', 'remainingSeconds'])
  assert.equal(responseSchema.$defs.totp.additionalProperties, false)
  assert.equal(responseSchema.$defs.totp.properties.code.pattern, '^[0-9]{1,9}$')
  assert.equal(responseSchema.$defs.totp.properties.remainingSeconds.minimum, 1)
  assert.equal(responseSchema.$defs.totp.properties.remainingSeconds.maximum, 3600)
  assert.deepEqual(responseSchema.$defs.reason.enum, contract.unavailableReasons)
  assert.equal(responseSchema.$defs.totpUnavailable.additionalProperties, false)

  assert.equal(vectors.protocolVersion, contract.protocolVersion)
  assert.equal(vectors.fictionalDataOnly, true)
  assert.ok(
    vectors.requestCases.some((entry) => entry.valid === false && entry.message.version === 3),
    'no vector refuses a totp request on protocol three',
  )
  assert.ok(
    vectors.requestCases.some((entry) => entry.valid === false && entry.message.type === 'fill'),
    'no vector refuses a non-totp request on protocol four',
  )
  assert.ok(
    vectors.responseCases.some(
      (entry) => entry.hostValid === true && entry.message.type === 'totp' && /^[0-9]{1,9}$/.test(entry.message.code),
    ),
    'no accepted vector carries a digits-only code',
  )
  assert.ok(
    vectors.responseCases.some((entry) => entry.hostValid === true && entry.message.type === 'totp-unavailable'),
    'no accepted vector reports totp-unavailable',
  )
  assert.ok(
    vectors.responseCases.some((entry) => entry.hostValid === false),
    'no rejected response vector',
  )
  assert.match(rust, /pub const TOTP_PROTOCOL_VERSION: u8 = 4;/)
  assert.match(rust, /fn valid_totp_code\(value: &str\) -> bool/)
  assert.match(rust, /self\.message_type != "totp" && !no_code/)
})
