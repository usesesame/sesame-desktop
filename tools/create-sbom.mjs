import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { packageNameFromModuleId, readShippedPackages } from './shipped-packages.mjs'

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

const shippedPackagesFile = process.env.SESAME_SHIPPED_PACKAGES
  ? path.resolve(process.env.SESAME_SHIPPED_PACKAGES)
  : path.join(root, 'dist', 'shipped-npm-packages.json')

export const npmComponents = (lock, shippedPackages) =>
  Object.entries(lock.packages ?? {})
    .filter(([name]) => name.includes('node_modules/'))
    .map(([name, entry]) => {
      const installedName = packageNameFromModuleId(name)
      const packageName = entry.name ?? installedName
      const shipped = shippedPackages.has(packageName) || shippedPackages.has(installedName)
      const component = {
        type: 'library',
        name: packageName,
        version: entry.version,
        purl: `pkg:npm/${packageName}@${entry.version}`,
        scope: entry.dev && !shipped ? 'excluded' : 'required',
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

export const neverCompiledProperty = { name: 'sesame:cargo-build', value: 'never-compiled' }

export const compiledCrates = (treeOutput) =>
  new Set(
    treeOutput
      .split('\n')
      .map((line) => line.match(/^(\S+) v(\S+)/))
      .filter(Boolean)
      .map(([, name, version]) => `${name}@${version}`),
  )

const cargoTree = () =>
  execFileSync(
    'cargo',
    [
      'tree',
      '--manifest-path',
      path.join(root, 'src-tauri', 'Cargo.toml'),
      '--locked',
      '--workspace',
      '--all-features',
      '--target',
      'all',
      '--edges',
      'normal,build,dev',
      '--prefix',
      'none',
      '--format',
      '{p}',
    ],
    { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'inherit'] },
  )

export const markNeverCompiled = (components, compiled) => {
  const unbuiltMembers = components.filter(
    (component) =>
      component.properties?.some((property) => property.name === 'sesame:source') &&
      !compiled.has(`${component.name}@${component.version}`),
  )
  if (compiled.size === 0 || unbuiltMembers.length > 0) {
    throw new Error('cargo tree did not list the workspace crates, so the built crates cannot be told apart.')
  }
  for (const component of components) {
    if (compiled.has(`${component.name}@${component.version}`)) continue
    component.scope = 'excluded'
    component.properties = [...(component.properties ?? []), neverCompiledProperty]
  }
}

export const dependencyRoleProperty = 'sesame:cargo-dependency'
export const pulledInByProperty = 'sesame:cargo-pulled-in-by'

export const cargoDependencyRoles = (metadata) => {
  const packages = new Map((metadata?.packages ?? []).map((pkg) => [pkg.id, pkg]))
  const nodes = new Map((metadata?.resolve?.nodes ?? []).map((node) => [node.id, node]))
  const members = (metadata?.workspace_members ?? []).filter((id) => packages.has(id) && nodes.has(id))
  if (members.length === 0) {
    throw new Error('cargo metadata did not list the workspace crates, so direct dependencies cannot be told apart.')
  }
  const direct = new Set(members)
  for (const id of members) for (const dependency of nodes.get(id).deps ?? []) direct.add(dependency.pkg)
  const pulledInBy = new Map()
  for (const start of direct) {
    if (members.includes(start) || !packages.has(start)) continue
    const seen = new Set([start])
    const queue = [start]
    while (queue.length > 0) {
      for (const dependency of nodes.get(queue.shift())?.deps ?? []) {
        if (seen.has(dependency.pkg)) continue
        seen.add(dependency.pkg)
        queue.push(dependency.pkg)
        if (direct.has(dependency.pkg)) continue
        if (!pulledInBy.has(dependency.pkg)) pulledInBy.set(dependency.pkg, new Set())
        pulledInBy.get(dependency.pkg).add(packages.get(start).name)
      }
    }
  }
  const roles = new Map()
  for (const [id, pkg] of packages) {
    if (!nodes.has(id)) continue
    const key = `${pkg.name}@${pkg.version}`
    const known = roles.get(key) ?? { direct: false, pulledInBy: new Set() }
    const parents = pulledInBy.get(id) ?? new Set()
    roles.set(key, {
      direct: known.direct || direct.has(id) || parents.size === 0,
      pulledInBy: new Set([...known.pulledInBy, ...parents]),
    })
  }
  return roles
}

export const markDependencyRoles = (components, roles) => {
  const unlisted = components.filter(
    (component) =>
      component.properties?.some((property) => property.name === 'sesame:source') &&
      !roles.has(`${component.name}@${component.version}`),
  )
  if (roles.size === 0 || unlisted.length > 0) {
    throw new Error('cargo metadata did not list the workspace crates, so direct dependencies cannot be told apart.')
  }
  for (const component of components) {
    const role = roles.get(`${component.name}@${component.version}`)
    const transitive = role !== undefined && !role.direct && role.pulledInBy.size > 0
    component.properties = [
      ...(component.properties ?? []),
      { name: dependencyRoleProperty, value: transitive ? 'transitive' : 'direct' },
      ...(transitive ? [{ name: pulledInByProperty, value: [...role.pulledInBy].sort().join(', ') }] : []),
    ]
  }
}

const cargoMetadata = () =>
  JSON.parse(
    execFileSync(
      'cargo',
      [
        'metadata',
        '--manifest-path',
        path.join(root, 'src-tauri', 'Cargo.toml'),
        '--locked',
        '--all-features',
        '--format-version',
        '1',
      ],
      { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, stdio: ['ignore', 'pipe', 'inherit'] },
    ),
  )

export const vendorTreeDigest = async (directory, base = root) => {
  const files = []
  const walk = async (current) => {
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name)
      if (entry.isDirectory()) await walk(full)
      else files.push(full)
    }
  }
  await walk(directory)
  const relativeFiles = files
    .map((file) => path.relative(base, file).split(path.sep).join('/'))
    .sort()
  const hash = createHash('sha256')
  for (const relative of relativeFiles) {
    hash.update(relative)
    hash.update('\0')
    hash.update(await readFile(path.join(base, relative)))
    hash.update('\0')
  }
  return hash.digest('hex')
}

const vendoredSource = (component) =>
  (component.properties ?? []).some((property) => property.name === 'sesame:source' && property.value === 'path')

export const markVendoredGlib = (components, vendorTree) => {
  for (const component of components) {
    if (component.name === 'glib' && vendoredSource(component)) {
      component.properties.push({ name: 'sesame:vendor-tree-sha256', value: vendorTree })
    }
  }
}

const main = async () => {
  const shippedPackages = await readShippedPackages(shippedPackagesFile)
  const vendorTree = await vendorTreeDigest(path.join(root, 'src-tauri', 'vendor', 'glib'))
  markNeverCompiled(cargoComponents, compiledCrates(cargoTree()))
  markDependencyRoles(cargoComponents, cargoDependencyRoles(cargoMetadata()))
  markVendoredGlib(cargoComponents, vendorTree)

  await mkdir(destination, { recursive: true })
  const components = [
    ...npmComponents(JSON.parse(npmLock), shippedPackages),
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
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main()
}
