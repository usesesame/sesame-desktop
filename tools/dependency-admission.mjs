import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const admissionFile = 'src-tauri/dependency-admission.json'
const cargoLockFile = 'src-tauri/Cargo.lock'
const cargoManifest = 'src-tauri/Cargo.toml'
const npmLockFile = 'package-lock.json'
const npmRegistryHost = 'registry.npmjs.org'
const cratesIoSources = new Set([
  'registry+https://github.com/rust-lang/crates.io-index',
  'registry+https://index.crates.io/',
])
const admissionSources = new Set(['crates.io', 'npm', 'path'])
const admittedVersion = /^\d+(\.\d+){0,2}$/

export function parseCargoLock(text) {
  const packages = []
  let current = null
  for (const line of text.split('\n')) {
    if (line.trim() === '[[package]]') {
      current = {}
      packages.push(current)
      continue
    }
    if (!current) continue
    const field = line.match(/^([A-Za-z0-9_]+) = "([^"]*)"$/)
    if (field) current[field[1]] = field[2]
  }
  return packages
}

function packageNameFromKey(key) {
  const marker = key.lastIndexOf('node_modules/')
  return marker === -1 ? key : key.slice(marker + 'node_modules/'.length)
}

export function parsePackageLock(text) {
  const lock = JSON.parse(text)
  const root = lock?.packages?.['']
  if (
    typeof lock?.lockfileVersion !== 'number' ||
    lock.lockfileVersion < 2 ||
    typeof lock?.packages !== 'object' ||
    lock.packages === null ||
    typeof root !== 'object' ||
    root === null
  ) {
    throw new Error(`${npmLockFile} must be a lockfileVersion 2 or newer lock with a packages map.`)
  }
  const packages = []
  for (const [key, entry] of Object.entries(lock.packages)) {
    if (key === '') continue
    packages.push({
      name: packageNameFromKey(key),
      version: typeof entry?.version === 'string' ? entry.version : null,
      resolved: typeof entry?.resolved === 'string' ? entry.resolved : null,
      integrity: typeof entry?.integrity === 'string' ? entry.integrity : null,
    })
  }
  const direct = []
  for (const name of Object.keys({ ...root.dependencies, ...root.devDependencies })) {
    const entry = lock.packages[`node_modules/${name}`]
    direct.push({ name, version: typeof entry?.version === 'string' ? entry.version : null })
  }
  return { packages, direct }
}

export function directDependenciesFromMetadata(metadata) {
  const packagesById = new Map((metadata.packages ?? []).map((pkg) => [pkg.id, pkg]))
  const workspaceMembers = new Set(metadata.workspace_members ?? [])
  const direct = new Map()
  for (const node of metadata.resolve?.nodes ?? []) {
    if (!workspaceMembers.has(node.id)) continue
    for (const dep of node.deps ?? []) {
      if (workspaceMembers.has(dep.pkg)) continue
      const pkg = packagesById.get(dep.pkg)
      if (!pkg) continue
      direct.set(`${pkg.name}\u0000${pkg.version}\u0000${pkg.source ?? ''}`, {
        name: pkg.name,
        version: pkg.version,
        source: pkg.source ?? null,
      })
    }
  }
  return [...direct.values()]
}

export function matchesVersion(version, admitted) {
  if (admitted === '*') return true
  const locked = version.split(/[-+]/)[0].split('.').map(Number)
  const required = admitted.split('.').map(Number)
  return required.every((part, index) => locked[index] === part)
}

function validateAdmission(admission) {
  if (admission?.schemaVersion !== 1 || !Array.isArray(admission?.packages)) {
    throw new Error('The dependency admission file must carry schemaVersion 1 and a packages array.')
  }
  const seen = new Set()
  return admission.packages.map((entry) => {
    if (typeof entry?.name !== 'string' || !entry.name) {
      throw new Error('An admission entry is missing a package name.')
    }
    const source = entry.source ?? 'crates.io'
    if (!admissionSources.has(source)) {
      throw new Error(`Admission for ${entry.name} names an unsupported source: ${source}`)
    }
    if (typeof entry?.version !== 'string' || (entry.version !== '*' && !admittedVersion.test(entry.version))) {
      throw new Error(`Admission for ${entry.name} needs a version such as "2", "2.1", "2.1.3", or "*".`)
    }
    if (typeof entry?.reason !== 'string' || !entry.reason.trim()) {
      throw new Error(`Admission for ${entry.name} is missing a reason.`)
    }
    const key = `${source}\u0000${entry.name}`
    if (seen.has(key)) throw new Error(`Package ${entry.name} is admitted more than once for ${source}.`)
    seen.add(key)
    return { name: entry.name, version: entry.version, source }
  })
}

function registryUrl(resolved) {
  if (typeof resolved !== 'string') return null
  try {
    return new URL(resolved)
  } catch {
    return null
  }
}

export function checkAdmission({ cargoLock, npmLock, metadata, admission }) {
  const entries = validateAdmission(admission)
  const cargoPackages = parseCargoLock(cargoLock)
  const npm = parsePackageLock(npmLock)
  const directCargo = directDependenciesFromMetadata(metadata)
  const admitted = new Map([...admissionSources].map((source) => [source, new Map()]))
  for (const entry of entries) admitted.get(entry.source).set(entry.name, entry)

  const foreignSources = []
  const missingChecksums = []
  const missingIntegrity = []
  const unadmitted = []
  const mismatched = []
  const stale = []

  const metadataPackages = new Map((metadata.packages ?? []).map((pkg) => [pkg.id, pkg]))
  const workspaceMembers = new Set(
    (metadata.workspace_members ?? []).map((id) => {
      const pkg = metadataPackages.get(id)
      return pkg ? `${pkg.name}@${pkg.version}` : id
    }),
  )

  for (const pkg of cargoPackages) {
    if (!pkg.source) {
      if (workspaceMembers.has(`${pkg.name}@${pkg.version}`)) continue
      const entry = admitted.get('path').get(pkg.name)
      if (!entry) {
        foreignSources.push(`${cargoLockFile}: ${pkg.name} ${pkg.version} has no registry source and no admitted path entry`)
      } else if (!matchesVersion(pkg.version, entry.version)) {
        mismatched.push(`${cargoLockFile}: ${pkg.name} ${pkg.version} does not match the admitted path version ${entry.version}`)
      }
      continue
    }
    if (!cratesIoSources.has(pkg.source)) {
      foreignSources.push(`${cargoLockFile}: ${pkg.name} ${pkg.version} comes from ${pkg.source}`)
      continue
    }
    if (!pkg.checksum) missingChecksums.push(`${cargoLockFile}: ${pkg.name} ${pkg.version} has no checksum`)
  }

  for (const dep of directCargo) {
    if (!dep.source || !cratesIoSources.has(dep.source)) continue
    const entry = admitted.get('crates.io').get(dep.name)
    if (!entry) {
      unadmitted.push(`${cargoManifest}: ${dep.name} ${dep.version} is not recorded in ${admissionFile}`)
    } else if (!matchesVersion(dep.version, entry.version)) {
      mismatched.push(`${dep.name} is admitted at ${entry.version} but ${cargoLockFile} resolves ${dep.version}`)
    }
  }

  for (const pkg of npm.packages) {
    const url = registryUrl(pkg.resolved)
    if (!url || url.protocol !== 'https:' || url.host !== npmRegistryHost) {
      foreignSources.push(`${npmLockFile}: ${pkg.name} ${pkg.version ?? ''} resolves to ${pkg.resolved ?? 'no registry URL'}`)
      continue
    }
    if (!pkg.integrity) missingIntegrity.push(`${npmLockFile}: ${pkg.name} ${pkg.version ?? ''} has no integrity hash`)
  }

  for (const dep of npm.direct) {
    const entry = admitted.get('npm').get(dep.name)
    if (!entry) {
      unadmitted.push(`package.json: ${dep.name} is not recorded in ${admissionFile}`)
      continue
    }
    if (!dep.version) {
      unadmitted.push(`${npmLockFile}: ${dep.name} is declared but has no locked version`)
      continue
    }
    if (!matchesVersion(dep.version, entry.version)) {
      mismatched.push(`${dep.name} is admitted at ${entry.version} but ${npmLockFile} resolves ${dep.version}`)
    }
  }

  for (const entry of entries) {
    let used = false
    if (entry.source === 'npm') used = npm.direct.some((dep) => dep.name === entry.name)
    else if (entry.source === 'path') used = cargoPackages.some((pkg) => !pkg.source && pkg.name === entry.name)
    else used = directCargo.some((dep) => dep.name === entry.name && dep.source && cratesIoSources.has(dep.source))
    if (!used) stale.push(`${entry.name} is admitted for ${entry.source} but nothing in the lockfiles uses it`)
  }

  return { foreignSources, missingChecksums, missingIntegrity, unadmitted, mismatched, stale }
}

export function readCargoMetadata(manifestRoot) {
  try {
    const output = execFileSync(
      'cargo',
      ['metadata', '--locked', '--manifest-path', cargoManifest, '--format-version', '1'],
      { cwd: manifestRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 64 * 1024 * 1024 },
    )
    return JSON.parse(output)
  } catch (error) {
    const detail = typeof error?.stderr === 'string' && error.stderr.trim() ? error.stderr.trim() : error.message
    if (typeof error?.status === 'number') {
      throw new Error(`${cargoLockFile} does not resolve: cargo metadata --locked failed\n${detail}`, { cause: error })
    }
    throw new Error(`cargo metadata --locked could not run: ${detail}`, { cause: error })
  }
}

export function checkWorkspace({ manifestRoot = repoRoot, metadata = null } = {}) {
  const admission = JSON.parse(readFileSync(join(manifestRoot, admissionFile), 'utf8'))
  const cargoLock = readFileSync(join(manifestRoot, cargoLockFile), 'utf8')
  const npmLock = readFileSync(join(manifestRoot, npmLockFile), 'utf8')
  return checkAdmission({
    cargoLock,
    npmLock,
    metadata: metadata ?? readCargoMetadata(manifestRoot),
    admission,
  })
}

function main() {
  try {
    const result = checkWorkspace()
    const problems = [
      ...result.foreignSources,
      ...result.missingChecksums,
      ...result.missingIntegrity,
      ...result.unadmitted,
      ...result.mismatched,
      ...result.stale,
    ]
    if (problems.length > 0) {
      process.stderr.write(`Dependency admission failed:\n${problems.map((line) => `  ${line}`).join('\n')}\n`)
      process.stderr.write('Every locked package must come from crates.io or registry.npmjs.org, carry a checksum or integrity hash, and every direct dependency must be recorded in src-tauri/dependency-admission.json with a reason. New dependencies need owner approval first.\n')
      process.exitCode = 1
      return
    }
    process.stdout.write('Dependency admission: every locked package is from an allowed registry, and every direct dependency is recorded.\n')
  } catch (error) {
    process.stderr.write(`Dependency admission failed:\n  ${error.message}\n`)
    process.exitCode = 1
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main()
}
