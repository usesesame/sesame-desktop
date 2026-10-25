import { createPrivateKey, createPublicKey, generateKeyPairSync, sign } from 'node:crypto'
import { appendFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

export const FRESHNESS_LABEL = 'sesame-update-freshness-v1'
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const SPKI_PREFIX_LENGTH = 12

export function freshnessPayload(version, issuedAt) {
  return [FRESHNESS_LABEL, version, String(issuedAt)].join('\n')
}

export function generateFreshnessKey() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  const seed = privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(PKCS8_PREFIX.length)
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(SPKI_PREFIX_LENGTH)
  return { seed: Buffer.from(seed).toString('base64url'), publicKey: Buffer.from(raw).toString('base64url') }
}

export function signFreshness({ seed, keyId, version, issuedAt }) {
  const seedBytes = Buffer.from(String(seed), 'base64url')
  if (seedBytes.length !== 32) throw new Error('The freshness signing seed must be 32 bytes of base64url.')
  if (typeof keyId !== 'string' || keyId.trim() === '' || /\s/.test(keyId)) throw new Error('A freshness key id is required and holds no whitespace.')
  if (typeof version !== 'string' || !/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(version)) throw new Error('The freshness version must be a plain release such as 0.4.4.')
  if (!Number.isSafeInteger(issuedAt) || issuedAt < 0 || issuedAt > 4_102_444_800) throw new Error('The freshness time must be a whole number of seconds.')
  const payload = freshnessPayload(version, issuedAt)
  const key = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seedBytes]), format: 'der', type: 'pkcs8' })
  return { payload, signingKeyId: keyId, signature: sign(null, Buffer.from(payload), key).toString('base64url') }
}

export function publicKeyOf(seed) {
  const key = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seed, 'base64url')]), format: 'der', type: 'pkcs8' })
  return Buffer.from(createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(SPKI_PREFIX_LENGTH)).toString('base64url')
}

function option(name) {
  const index = process.argv.indexOf(`--${name}`)
  return index === -1 ? undefined : process.argv[index + 1]
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const command = process.argv[2]
  if (command === 'keygen') {
    const key = generateFreshnessKey()
    process.stdout.write(`SESAME_UPDATE_FRESHNESS_PUBLIC_KEY=${key.publicKey}\nSESAME_UPDATE_FRESHNESS_SIGNING_KEY=${key.seed}\n`)
    process.stderr.write('Store the signing key only in the freshness environment of the repository and print it nowhere else.\n')
  } else if (command === 'sign') {
    const seed = process.env.SESAME_UPDATE_FRESHNESS_SIGNING_KEY
    const statement = signFreshness({
      seed,
      keyId: process.env.SESAME_UPDATE_FRESHNESS_KEY_ID,
      version: option('version'),
      issuedAt: Number(option('issued-at') ?? Math.floor(Date.now() / 1000)),
    })
    const out = option('out')
    if (!out) throw new Error('Usage: node tools/update-freshness.mjs sign --version <x.y.z> --out <file> [--issued-at <seconds>]')
    writeFileSync(out, `${JSON.stringify(statement, null, 2)}\n`)
    if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `Signed a freshness statement for ${statement.payload.split('\n')[1]}.\n`)
  } else {
    throw new Error('Usage: node tools/update-freshness.mjs <keygen|sign>')
  }
}
