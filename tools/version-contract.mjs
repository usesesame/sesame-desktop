import { readFile, writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const mode = process.argv[2]
if (mode !== 'sync' && mode !== 'check') {
  console.error('Usage: node tools/version-contract.mjs <sync|check>')
  process.exit(2)
}

const workspace = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

const files = {
  package: path.join(workspace, 'package.json'),
  cargo: path.join(workspace, 'src-tauri', 'Cargo.toml'),
  tauri: path.join(workspace, 'src-tauri', 'tauri.conf.json'),
}

const semverPattern = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/

async function readJson(file, label) {
  try {
    return JSON.parse(await readFile(file, 'utf8'))
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${error.message}`, { cause: error })
  }
}

function requireVersion(value, label) {
  if (typeof value !== 'string' || !semverPattern.test(value)) {
    throw new Error(`${label} must contain a SemVer version.`)
  }
  return value
}

function replaceExactlyOnce(source, pattern, replacement, label) {
  const matches = source.match(pattern)
  if (!matches || matches.length !== 1) {
    throw new Error(`Could not find exactly one ${label} version declaration.`)
  }
  return source.replace(pattern, replacement)
}

async function desktopTargets(version) {
  const [cargo, tauri] = await Promise.all([
    readFile(files.cargo, 'utf8'),
    readFile(files.tauri, 'utf8'),
  ])

  const packageHeader = /^\[package\]\s*$/m.exec(cargo)
  if (!packageHeader) {
    throw new Error('src-tauri/Cargo.toml must contain a [package] section.')
  }
  const packageSectionStart = packageHeader.index
  const afterPackageHeader = packageSectionStart + packageHeader[0].length
  const nextSection = /^\[/m.exec(cargo.slice(afterPackageHeader))
  const packageSectionEnd = nextSection
    ? afterPackageHeader + nextSection.index
    : cargo.length
  const cargoPackage = cargo.slice(packageSectionStart, packageSectionEnd)
  const updatedCargoPackage = replaceExactlyOnce(
    cargoPackage,
    /^version\s*=\s*"[^"]+"$/gm,
    `version = "${version}"`,
    'Cargo package',
  )

  return [
    {
      label: 'src-tauri/Cargo.toml',
      file: files.cargo,
      current: cargo,
      expected: cargo.slice(0, packageSectionStart) + updatedCargoPackage + cargo.slice(packageSectionEnd),
    },
    {
      label: 'src-tauri/tauri.conf.json',
      file: files.tauri,
      current: tauri,
      expected: replaceExactlyOnce(
        tauri,
        /^ {2}"version": "[^"]+",$/gm,
        `  "version": "${version}",`,
        'Tauri',
      ),
    },
  ]
}

async function main() {
  const rootPackage = await readJson(files.package, 'package.json')

  const desktopVersion = requireVersion(rootPackage.version, 'package.json')
  const targets = await desktopTargets(desktopVersion)
  const stale = targets.filter((target) => target.current !== target.expected)

  if (mode === 'check' && stale.length > 0) {
    throw new Error(
      `Desktop version ${desktopVersion} is not synchronized in: ${stale.map((target) => target.label).join(', ')}. ` +
        'Run npm run version:sync.',
    )
  }

  if (mode === 'sync') {
    await Promise.all(
      stale.map((target) => writeFile(target.file, target.expected, 'utf8')),
    )
    console.log(
      stale.length === 0
        ? `Desktop version ${desktopVersion} is already synchronized.`
        : `Synchronized desktop version ${desktopVersion} in ${stale.length} file(s).`,
    )
  } else {
    console.log(`Desktop version ${desktopVersion} is consistent.`)
  }

  console.log('The browser extension has an independent version contract.')
  console.log('The API deployment version is independent and is not changed by this command.')
}

main().catch((error) => {
  console.error(`Version contract failed: ${error.message}`)
  process.exitCode = 1
})
