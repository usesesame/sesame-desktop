import { createHash } from 'node:crypto'
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises'
import path from 'node:path'

const root = path.resolve(import.meta.dirname, '..')
const destination = process.env.SESAME_SBOM_OUTPUT_DIR
  ? path.resolve(process.env.SESAME_SBOM_OUTPUT_DIR)
  : path.join(root, 'release-evidence')
const read = (file) => readFile(path.join(root, file), 'utf8')
const digest = (value) => createHash('sha256').update(value).digest('hex')
const npmLock = await read('package-lock.json')
const cargoLock = await read('src-tauri/Cargo.lock')
// The Go module lives in the server repository. When this runs there the Go
// components belong in the bill of materials; in the desktop repository there
// is no go.sum to read and the npm and cargo locks are the whole graph.
const goSum = await read('backend/go.sum').catch(() => '')
const manifest = JSON.parse(await read('package.json'))

const npmHash = (integrity) => {
  const match = typeof integrity === 'string' ? integrity.match(/^sha512-([A-Za-z0-9+/=]+)$/) : null
  return match ? { alg: 'SHA-512', content: Buffer.from(match[1], 'base64').toString('hex') } : null
}

const npmComponents = Object.entries(JSON.parse(npmLock).packages ?? {})
  .filter(([name]) => name.includes('node_modules/'))
  .map(([name, entry]) => {
    const packageName = name.slice(name.lastIndexOf('node_modules/') + 'node_modules/'.length)
    const component = {
      type: 'library',
      name: packageName,
      version: entry.version,
      purl: `pkg:npm/${packageName}@${entry.version}`,
      scope: entry.dev ? 'excluded' : 'required',
    }
    const hash = npmHash(entry.integrity)
    if (hash) component.hashes = [hash]
    return component
  })

const cargoComponents = cargoLock
  .split('[[package]]')
  .slice(1)
  .map((block) => {
    const field = (name) => block.match(new RegExp(`^${name} = "([^"]+)"`, 'm'))?.[1]
    const name = field('name')
    const version = field('version')
    const source = field('source')
    const checksum = field('checksum')
    const component = { type: 'library', name, version, purl: `pkg:cargo/${name}@${version}` }
    if (checksum) component.hashes = [{ alg: 'SHA-256', content: checksum }]
    if (!source) component.properties = [{ name: 'sesame:source', value: 'path' }]
    return component
  })

const vendorTreeDigest = async (directory) => {
  const files = []
  const walk = async (current) => {
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name)
      if (entry.isDirectory()) await walk(full)
      else files.push(full)
    }
  }
  await walk(directory)
  files.sort()
  const hash = createHash('sha256')
  for (const file of files) {
    hash.update(path.relative(root, file))
    hash.update('\0')
    hash.update(await readFile(file))
    hash.update('\0')
  }
  return hash.digest('hex')
}

const vendorTree = await vendorTreeDigest(path.join(root, 'src-tauri', 'vendor', 'glib'))
for (const component of cargoComponents) {
  if (component.name === 'glib' && component.properties) {
    component.properties.push({ name: 'sesame:vendor-tree-sha256', value: vendorTree })
  }
}

await mkdir(destination, { recursive: true })
const components = [
  ...npmComponents,
  ...cargoComponents,
  ...(goSum
    ? [
        ...new Set(
          [...goSum.matchAll(/^([^\s]+) v([^\s]+)/gm)].map(([, name, version]) => `${name}@${version}`),
        ),
      ].map((value) => {
        const [name, version] = value.split('@')
        return { type: 'library', name, version, purl: `pkg:golang/${name}@${version}` }
      })
    : []),
]
const bom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  serialNumber: `urn:uuid:${digest(`${npmLock}${cargoLock}${goSum}`).slice(0, 32)}`,
  version: 1,
  metadata: { component: { type: 'application', name: manifest.name, version: manifest.version } },
  components,
}
const provenance = {
  version: 1,
  source: {
    commit: process.env.GITHUB_SHA ?? 'local-uncommitted',
    npmLockSha256: digest(npmLock),
    cargoLockSha256: digest(cargoLock),
    vendorTreeSha256: vendorTree,
    ...(goSum ? { goSumSha256: digest(goSum) } : {}),
  },
  sbomSha256: digest(JSON.stringify(bom)),
  protectedValuesIncluded: false,
}
await writeFile(path.join(destination, `sesame-${manifest.version}.cdx.json`), `${JSON.stringify(bom, null, 2)}\n`)
await writeFile(path.join(destination, `sesame-${manifest.version}.provenance.json`), `${JSON.stringify(provenance, null, 2)}\n`)
console.log(`Wrote ${components.length} locked components to release-evidence/`)
