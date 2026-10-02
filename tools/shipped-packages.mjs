import { readFile } from 'node:fs/promises'

const nodeModules = 'node_modules/'

export const packageNameFromModuleId = (id) => {
  const normalized = id.split('\\').join('/')
  const marker = normalized.lastIndexOf(nodeModules)
  if (marker === -1) return null
  const segments = normalized.slice(marker + nodeModules.length).split('/').filter(Boolean)
  if (segments.length === 0) return null
  if (segments[0].startsWith('@') && segments.length > 1) return `${segments[0]}/${segments[1]}`
  return segments[0]
}

export const readShippedPackages = async (file) => {
  let contents
  try {
    contents = await readFile(file, 'utf8')
  } catch (error) {
    throw new Error(
      `Missing ${file}: run "npm run desktop:build" before "npm run supply-chain:sbom".`,
      { cause: error },
    )
  }
  const names = JSON.parse(contents)
  if (!Array.isArray(names) || names.some((name) => typeof name !== 'string')) {
    throw new Error(`${file} must contain a JSON array of npm package names.`)
  }
  return new Set(names)
}
