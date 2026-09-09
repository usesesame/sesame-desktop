import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const manifests = ['src-tauri/Cargo.toml', 'src-tauri/sesame-core/Cargo.toml']
const admissionFile = 'src-tauri/dependency-admission.json'

const SECTION = /^\[([^\]]+)\]\s*$/
const DEPENDENCY_SECTION = /(^|\.)dependencies$/
const ENTRY = /^([A-Za-z0-9_-]+)\s*=\s*(.+?)\s*$/
const VERSION_IN_TABLE = /version\s*=\s*"([^"]+)"/
const VERSION_STRING = /^"([^"]+)"/

export function parseDirectDependencies(manifestText) {
  const dependencies = new Map()
  let section = ''
  for (const rawLine of manifestText.split('\n')) {
    const line = rawLine.split('#')[0].trim()
    if (!line) continue
    const header = line.match(SECTION)
    if (header) {
      section = header[1]
      continue
    }
    if (!DEPENDENCY_SECTION.test(section)) continue
    const entry = line.match(ENTRY)
    if (!entry) continue
    const [, name, value] = entry
    if (/^\{/.test(value)) {
      const workspace = /\bworkspace\s*=\s*true\b/.test(value)
      const version = value.match(VERSION_IN_TABLE)?.[1] ?? null
      dependencies.set(name, { version: workspace ? 'workspace' : version, path: /\bpath\s*=/.test(value) })
    } else {
      dependencies.set(name, { version: value.match(VERSION_STRING)?.[1] ?? null, path: false })
    }
  }
  return dependencies
}

export function checkAdmission(manifests, admission) {
  if (admission?.schemaVersion !== 1 || !Array.isArray(admission?.packages)) {
    throw new Error('The dependency admission file must carry schemaVersion 1 and a packages array.')
  }
  const admitted = new Map()
  for (const entry of admission.packages) {
    if (typeof entry?.name !== 'string' || !entry.name) throw new Error(`An admission entry is missing a package name.`)
    if (admitted.has(entry.name)) throw new Error(`Package ${entry.name} is admitted more than once.`)
    if (typeof entry?.version !== 'string' || !entry.version) throw new Error(`Admission for ${entry.name} is missing a version.`)
    admitted.set(entry.name, entry)
  }
  const unadmitted = []
  const stale = []
  const mismatched = []
  for (const [file, text] of manifests) {
    for (const [name, requirement] of parseDirectDependencies(text)) {
      if (requirement.version === 'workspace' || requirement.path) continue
      const entry = admitted.get(name)
      if (!entry) {
        unadmitted.push(`${file}: ${name} ${requirement.version ?? '(no version)'}`)
      } else if (requirement.version && !satisfied(requirement.version, entry.version)) {
        mismatched.push(`${file}: ${name} requires ${requirement.version} but admission records ${entry.version}`)
      }
    }
  }
  for (const name of admitted.keys()) {
    if (![...manifests.values()].some((text) => parseDirectDependencies(text).has(name))) {
      stale.push(name)
    }
  }
  return { unadmitted, stale, mismatched }
}

function satisfied(requirement, admitted) {
  if (admitted === '*') return true
  const numbers = (value) => value.split(/[.<>=^~\s,-]+/).filter((part) => /^\d+$/.test(part)).map(Number)
  const [required, allowed] = [numbers(requirement), numbers(admitted)]
  for (let index = 0; index < Math.max(required.length, allowed.length); index += 1) {
    const left = required[index] ?? 0
    const right = allowed[index] ?? 0
    if (left !== right) return left < right
  }
  return true
}

export function checkWorkspace({ manifestRoot = repoRoot, files = manifests, admissionPath = admissionFile } = {}) {
  const manifests = new Map(files.map((file) => [file, readFileSync(join(manifestRoot, file), 'utf8')]))
  const admission = JSON.parse(readFileSync(join(manifestRoot, admissionPath), 'utf8'))
  return checkAdmission(manifests, admission)
}

function main() {
  const result = checkWorkspace()
  const problems = [...result.unadmitted, ...result.mismatched, ...result.stale.map((name) => `${name} is admitted but no manifest uses it`)]
  if (problems.length > 0) {
    process.stderr.write(`Dependency admission failed:\n${problems.map((line) => `  ${line}`).join('\n')}\n`)
    process.stderr.write('Record every direct dependency in src-tauri/dependency-admission.json with a reason, and remove stale admissions. New production dependencies need owner approval first.\n')
    process.exitCode = 1
    return
  }
  process.stdout.write('Dependency admission: every direct dependency is recorded.\n')
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main()
}
