import { createHash } from 'node:crypto'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'

const root = path.resolve(import.meta.dirname, '..')
const destination = path.join(root, 'release-evidence')
const read = (file) => readFile(path.join(root, file), 'utf8')
const digest = (value) => createHash('sha256').update(value).digest('hex')
const npmLock = await read('package-lock.json')
const cargoLock = await read('src-tauri/Cargo.lock')
const goSum = await read('backend/go.sum')
const manifest = JSON.parse(await read('package.json'))

await mkdir(destination, { recursive: true })
const components = [
  ...Object.entries(JSON.parse(npmLock).packages ?? {}).filter(([name]) => name.startsWith('node_modules/')).map(([name, entry]) => ({ type: 'library', name: name.slice('node_modules/'.length), version: entry.version, purl: `pkg:npm/${name.slice('node_modules/'.length)}@${entry.version}` })),
  ...[...cargoLock.matchAll(/name = "([^"]+)"\nversion = "([^"]+)"/g)].map(([, name, version]) => ({ type: 'library', name, version, purl: `pkg:cargo/${name}@${version}` })),
  ...[...new Set([...goSum.matchAll(/^([^\s]+) v([^\s]+)/gm)].map(([, name, version]) => `${name}@${version}`))].map((value) => { const [name, version] = value.split('@'); return { type: 'library', name, version, purl: `pkg:golang/${name}@${version}` } }),
]
const bom = { bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: `urn:uuid:${digest(`${npmLock}${cargoLock}${goSum}`).slice(0, 32)}`, version: 1, metadata: { component: { type: 'application', name: manifest.name, version: manifest.version } }, components }
const provenance = { version: 1, source: { commit: process.env.GITHUB_SHA ?? 'local-uncommitted', npmLockSha256: digest(npmLock), cargoLockSha256: digest(cargoLock), goSumSha256: digest(goSum) }, sbomSha256: digest(JSON.stringify(bom)), protectedValuesIncluded: false }
await writeFile(path.join(destination, `sesame-${manifest.version}.cdx.json`), `${JSON.stringify(bom, null, 2)}\n`)
await writeFile(path.join(destination, `sesame-${manifest.version}.provenance.json`), `${JSON.stringify(provenance, null, 2)}\n`)
console.log(`Wrote ${components.length} locked components to release-evidence/`)
