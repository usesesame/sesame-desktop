import { createHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import path from 'node:path'

const nodeModules = 'node_modules/'
const repositoryRoot = path.resolve(import.meta.dirname, '..')
const sha256 = /^[0-9a-f]{64}$/

export const buildConfigFiles = ['package.json', 'package-lock.json', 'vite.config.ts', 'svelte.config.js']

export const packageNameFromModuleId = (id) => {
  const normalized = id.split('\\').join('/')
  const marker = normalized.lastIndexOf(nodeModules)
  if (marker === -1) return null
  const segments = normalized.slice(marker + nodeModules.length).split('/').filter(Boolean)
  if (segments.length === 0) return null
  if (segments[0].startsWith('@') && segments.length > 1) return `${segments[0]}/${segments[1]}`
  return segments[0]
}

const fileDigest = (file) => createHash('sha256').update(readFileSync(file)).digest('hex')

const inputPath = (base, id) => {
  if (id.startsWith('\0')) return null
  const file = id.split('?')[0]
  if (!path.isAbsolute(file) || packageNameFromModuleId(file)) return null
  return path.relative(base, file).split(path.sep).join('/')
}

export const shippedInventory = (moduleIds, base = repositoryRoot) => {
  const packages = new Set()
  const inputs = new Set(buildConfigFiles.filter((file) => existsSync(path.join(base, file))))
  for (const id of moduleIds) {
    const name = packageNameFromModuleId(id)
    if (name) packages.add(name)
    const input = inputPath(base, id)
    if (input) inputs.add(input)
  }
  return {
    packages: [...packages].sort(),
    inputs: [...inputs].sort().map((file) => ({ path: file, sha256: fileDigest(path.join(base, file)) })),
  }
}

const insideBase = (file) =>
  typeof file === 'string' &&
  file.length > 0 &&
  !path.isAbsolute(file) &&
  !file.includes('\\') &&
  file.split('/').every((segment) => segment !== '' && segment !== '.' && segment !== '..')

const currentDigest = (base, file) => {
  try {
    return fileDigest(path.join(base, file))
  } catch {
    return null
  }
}

export const readShippedPackages = async (file, base = repositoryRoot) => {
  let contents
  try {
    contents = await readFile(file, 'utf8')
  } catch (error) {
    throw new Error(
      `Missing ${file}: run "npm run desktop:build" before "npm run supply-chain:sbom".`,
      { cause: error },
    )
  }
  const inventory = JSON.parse(contents)
  const names = inventory?.packages
  const inputs = inventory?.inputs
  if (!Array.isArray(names) || names.some((name) => typeof name !== 'string')) {
    throw new Error(`${file} must list the npm package names the build bundled.`)
  }
  if (
    !Array.isArray(inputs) ||
    inputs.some((input) => !insideBase(input?.path) || typeof input.sha256 !== 'string' || !sha256.test(input.sha256)) ||
    !inputs.some((input) => input.path === 'package-lock.json')
  ) {
    throw new Error(`${file} must list the build inputs it came from: run "npm run desktop:build" again.`)
  }
  const changed = inputs.find((input) => currentDigest(base, input.path) !== input.sha256)
  if (changed) {
    throw new Error(`${file} came from a build of other inputs, ${changed.path} has changed: run "npm run desktop:build" again.`)
  }
  return new Set(names)
}
