import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'

const run = promisify(execFile)
const root = path.resolve(import.meta.dirname, '..')
const sharedObjectPattern = /\.so(\.[0-9]+)*$/

export const defaultInventoryPath = (base = root) => {
  const version = JSON.parse(readFileSync(path.join(base, 'package.json'), 'utf8')).version
  const directory = process.env.SESAME_SBOM_OUTPUT_DIR
    ? path.resolve(process.env.SESAME_SBOM_OUTPUT_DIR)
    : path.join(base, 'release-evidence')
  return path.join(directory, `sesame-${version}-appimage.cdx.json`)
}

const uint = (bytes, offset, size, littleEndian) => {
  const view = new DataView(bytes.buffer, bytes.byteOffset + offset, size)
  if (size === 2) return view.getUint16(0, littleEndian)
  if (size === 4) return view.getUint32(0, littleEndian)
  return Number(view.getBigUint64(0, littleEndian))
}

export const isElfSharedObject = (bytes) => {
  if (bytes.length < 20 || bytes[0] !== 0x7f || bytes.toString('latin1', 1, 4) !== 'ELF') return false
  return uint(bytes, 16, 2, bytes[5] === 1) === 3
}

const fdoPackagingMetadata = 0xcafe1a7e

export const parseNoteRecords = (buffer) => {
  const records = []
  let offset = 0
  while (offset + 12 <= buffer.length) {
    const nameSize = buffer.readUInt32LE(offset)
    const descSize = buffer.readUInt32LE(offset + 4)
    const type = buffer.readUInt32LE(offset + 8)
    const nameStart = offset + 12
    const descStart = nameStart + Math.ceil(nameSize / 4) * 4
    const next = descStart + Math.ceil(descSize / 4) * 4
    if (next > buffer.length) break
    records.push({
      owner: buffer.toString('utf8', nameStart, nameStart + nameSize).replace(/\0+$/, ''),
      type,
      desc: buffer.toString('utf8', descStart, descStart + descSize),
    })
    offset = next
  }
  return records
}

const cString = (buffer, offset) => {
  const end = buffer.indexOf(0, offset)
  return buffer.toString('utf8', offset, end === -1 ? buffer.length : end)
}

export const readPackagingNote = (bytes) => {
  if (!isElfSharedObject(bytes)) return null
  const littleEndian = bytes[5] === 1
  const is64 = bytes[4] === 2
  const sectionOffset = is64 ? uint(bytes, 40, 8, littleEndian) : uint(bytes, 32, 4, littleEndian)
  const sectionSize = is64 ? uint(bytes, 58, 2, littleEndian) : uint(bytes, 46, 2, littleEndian)
  const sectionCount = is64 ? uint(bytes, 60, 2, littleEndian) : uint(bytes, 48, 2, littleEndian)
  const namesIndex = is64 ? uint(bytes, 62, 2, littleEndian) : uint(bytes, 50, 2, littleEndian)
  if (sectionOffset === 0 || sectionSize === 0 || sectionCount === 0 || namesIndex >= sectionCount) return null
  const section = (index) => {
    const base = sectionOffset + index * sectionSize
    return {
      name: uint(bytes, base, 4, littleEndian),
      offset: is64 ? uint(bytes, base + 24, 8, littleEndian) : uint(bytes, base + 16, 4, littleEndian),
      size: is64 ? uint(bytes, base + 32, 8, littleEndian) : uint(bytes, base + 20, 4, littleEndian),
    }
  }
  const names = section(namesIndex)
  const strings = bytes.subarray(names.offset, names.offset + names.size)
  for (let index = 0; index < sectionCount; index += 1) {
    const candidate = section(index)
    if (cString(strings, candidate.name) !== '.note.package') continue
    for (const record of parseNoteRecords(bytes.subarray(candidate.offset, candidate.offset + candidate.size))) {
      if (record.owner !== 'FDO' || record.type !== fdoPackagingMetadata) continue
      try {
        const metadata = JSON.parse(record.desc.replace(/\0+$/, ''))
        if (metadata?.type === 'deb' && typeof metadata.name === 'string' && typeof metadata.version === 'string') {
          return { name: metadata.name, version: metadata.version }
        }
      } catch {
        return null
      }
    }
    return null
  }
  return null
}

const libraryTokens = (library) => {
  const base = library.replace(/\.so(\.[0-9]+)*$/, '')
  const tokens = new Set([base, base.replace(/^lib/, ''), base.replace(/-\d+(\.\d+)*$/, '')])
  return [...tokens]
    .filter((token) => token.length >= 3)
    .sort((a, b) => b.length - a.length)
    .map((token) => token.toLowerCase())
}

export const readLibraryIdentity = (bytes, library) => {
  const tokens = libraryTokens(library)
  const candidates = new Map()
  for (const match of bytes.toString('latin1').matchAll(/[\x20-\x7e]{4,}/g)) {
    const value = match[0]
    const lower = value.toLowerCase()
    const token = tokens.find((candidate) => lower.includes(candidate))
    if (!token) continue
    for (const version of value.matchAll(/\d{1,4}\.\d{1,4}(?:\.\d{1,4})?(?:[+~][A-Za-z0-9.+~-]+)?/g)) {
      const key = `${token}@${version[0]}`
      candidates.set(key, (candidates.get(key) ?? 0) + 1)
    }
  }
  if (candidates.size === 0) return null
  const [best] = [...candidates.entries()].sort((a, b) => b[1] - a[1] || b[0].length - a[0].length)
  const separator = best[0].indexOf('@')
  return { name: best[0].slice(0, separator), version: best[0].slice(separator + 1) }
}

export const collectBundledLibraries = async (tree) => {
  const records = new Map()
  const walk = async (directory) => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const full = path.join(directory, entry.name)
      const info = await stat(full).catch(() => null)
      if (!info) continue
      if (info.isDirectory()) {
        await walk(full)
        continue
      }
      if (!sharedObjectPattern.test(entry.name)) continue
      const target = await realpath(full).catch(() => null)
      if (!target) continue
      const record = records.get(target) ?? { realPath: target, names: new Set() }
      record.names.add(entry.name)
      records.set(target, record)
    }
  }
  await walk(tree)
  const libraries = []
  for (const record of records.values()) {
    const bytes = await readFile(record.realPath)
    if (!isElfSharedObject(bytes)) continue
    const names = [...record.names].sort((a, b) => a.length - b.length || a.localeCompare(b))
    libraries.push({ realPath: record.realPath, names, library: names[0] })
  }
  return libraries.sort((a, b) => a.library.localeCompare(b.library))
}

const dpkgQuery = async (args) => {
  const { stdout } = await run('dpkg-query', args, { maxBuffer: 16 * 1024 * 1024 })
  return stdout
}

export const createDpkgResolver = ({ query = dpkgQuery } = {}) => {
  let available = true
  return async (names) => {
    if (!available) return null
    for (const name of names) {
      let search
      try {
        search = await query(['-S', `*/${name}`])
      } catch (error) {
        if (error?.code === 'ENOENT') {
          available = false
          return null
        }
        continue
      }
      const packages = [
        ...new Set(
          search
            .split('\n')
            .map((line) => line.slice(0, line.indexOf(': ')))
            .filter((value) => value.length > 0),
        ),
      ]
      const identities = new Set()
      for (const packageName of packages) {
        const source = await query(['-W', '-f=${source:Package}\t${source:Version}\n', packageName]).catch(() => '')
        const [sourceName, sourceVersion] = source.trim().split('\t')
        if (sourceName && sourceVersion) identities.add(`${sourceName}@${sourceVersion}`)
      }
      if (identities.size === 1) {
        const [identity] = identities
        const separator = identity.lastIndexOf('@')
        return { name: identity.slice(0, separator), version: identity.slice(separator + 1) }
      }
    }
    return null
  }
}

export const buildInventory = async (tree, { resolvePackage = createDpkgResolver() } = {}) => {
  const libraries = await collectBundledLibraries(tree)
  const components = new Map()
  const unresolved = []
  const byIdentity = { note: 0, dpkg: 0, library: 0 }
  for (const library of libraries) {
    const bytes = await readFile(library.realPath)
    let identity = readPackagingNote(bytes)
    let source = identity ? 'note' : null
    if (!identity) {
      identity = await resolvePackage(library.names)
      if (identity) source = 'dpkg'
    }
    if (!identity) {
      identity = readLibraryIdentity(bytes, library.library)
      if (identity) source = 'library'
    }
    if (!identity) {
      unresolved.push(library.library)
      continue
    }
    byIdentity[source] += 1
    const key = `${identity.name}@${identity.version}`
    const existing = components.get(key)
    if (existing) {
      existing.properties.push({ name: 'sesame:bundled-library', value: library.library })
      if (existing.identity === 'library' && source !== 'library') existing.identity = source
      continue
    }
    components.set(key, {
      type: 'library',
      name: identity.name,
      version: identity.version,
      purl: `pkg:deb/ubuntu/${identity.name}@${identity.version}`,
      identity: source,
      properties: [{ name: 'sesame:bundled-library', value: library.library }],
    })
  }
  const list = [...components.values()]
    .map(({ identity, ...component }) => ({
      ...component,
      properties: [...component.properties, { name: 'sesame:identity', value: identity }],
    }))
    .sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version))
  return { libraries: libraries.length, components: list, unresolved, byIdentity }
}

export const buildBom = ({ name, version, components }) => ({
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  serialNumber: `urn:uuid:${createHash('sha256').update(JSON.stringify(components)).digest('hex').slice(0, 32)}`,
  version: 1,
  metadata: {
    component: { type: 'application', name, version },
    properties: [{ name: 'sesame:inventory', value: 'appimage-bundled-libraries' }],
  },
  components,
})

const parseArguments = (argv) => {
  const options = {}
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--appimage') options.appimage = argv[++index]
    else if (argv[index] === '--tree') options.tree = argv[++index]
    else if (argv[index] === '--out') options.out = argv[++index]
    else throw new Error(`Unknown argument: ${argv[index]}`)
  }
  if (options.appimage && options.tree) throw new Error('Pass either --appimage or --tree, not both.')
  if (!options.appimage && !options.tree) {
    throw new Error('Usage: node tools/create-appimage-sbom.mjs --appimage <AppImage> | --tree <extracted-directory> [--out <sbom.json>]')
  }
  return options
}

const main = async () => {
  const options = parseArguments(process.argv.slice(2))
  const manifest = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'))
  const out = path.resolve(options.out ?? defaultInventoryPath())
  let tree = options.tree ? path.resolve(options.tree) : null
  let workspace = null
  if (options.appimage) {
    workspace = await mkdtemp(path.join(tmpdir(), 'sesame-appimage-inventory-'))
    await run(path.resolve(options.appimage), ['--appimage-extract'], { cwd: workspace, maxBuffer: 64 * 1024 * 1024 })
    tree = path.join(workspace, 'squashfs-root')
  }
  try {
    const inventory = await buildInventory(tree)
    await mkdir(path.dirname(out), { recursive: true })
    await writeFile(out, `${JSON.stringify(buildBom({ name: manifest.name, version: manifest.version, components: inventory.components }), null, 2)}\n`)
    process.stdout.write(`Inventoried ${inventory.libraries} bundled shared objects into ${inventory.components.length} components at ${out}\n`)
    process.stdout.write(`Identity sources: package notes ${inventory.byIdentity.note}, dpkg ${inventory.byIdentity.dpkg}, library strings ${inventory.byIdentity.library}.\n`)
    if (inventory.unresolved.length > 0) {
      process.stderr.write(`Libraries with no readable version:\n${inventory.unresolved.map((name) => `  ${name}`).join('\n')}\n`)
      process.exitCode = 1
      return
    }
    if (inventory.byIdentity.library > 0) {
      process.stdout.write(`${inventory.byIdentity.library} libraries use library-derived identities that OSV may not index. Run on the Ubuntu build host for exact package identities.\n`)
    }
  } finally {
    if (workspace) await rm(workspace, { recursive: true, force: true })
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main()
}
