// Walks the filesystem because `git ls-files` returns nothing in a repository with no commits, which made every contract built on it pass while inspecting zero files.

import { readdirSync } from 'node:fs'
import { dirname, join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = dirname(dirname(fileURLToPath(import.meta.url)))

const IGNORED_DIRECTORIES = new Set([
  '.git', 'node_modules', 'dist', 'target', 'coverage', 'test-results',
  '.ssr', '.svelte-kit', 'build', '.cache', '.gocache',
  '.tmp', 'isolated-target', 'release-artifacts', 'release-evidence',
  'store-packages', '.host-compat', '.phase4-target',
])

export function repositoryFiles(pattern = '*') {
  const found = []
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (!IGNORED_DIRECTORIES.has(entry.name)) walk(join(directory, entry.name))
        continue
      }
      found.push(relative(root, join(directory, entry.name)).split(sep).join('/'))
    }
  }
  walk(root)

  if (pattern === '*') return found.sort()
  if (pattern.startsWith('*.')) {
    const extension = pattern.slice(1)
    return found.filter((file) => file.endsWith(extension)).sort()
  }
  const cleaned = pattern.replace(/^\*\/?/, '').replace(/\/\*$/, '')
  return found.filter((file) => file.includes(cleaned)).sort()
}

export function requireFiles(pattern, minimum = 1) {
  const files = repositoryFiles(pattern)
  if (files.length < minimum) {
    throw new Error(`expected at least ${minimum} file(s) matching ${pattern}, found ${files.length}`)
  }
  return files
}
