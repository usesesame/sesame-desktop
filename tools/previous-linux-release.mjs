import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'

import { compareVersions } from './release-set.mjs'

export const PREVIOUS_SUMS_ASSET = 'SHA256SUMS-linux'

export function previousDebName(version) {
  return `Sesame_${version}_amd64.deb`
}

function uploadedAssetNames(release) {
  return (Array.isArray(release.assets) ? release.assets : [])
    .filter((asset) => asset?.state === 'uploaded')
    .map((asset) => asset.name)
}

export function selectPreviousLinuxRelease(pages, candidateVersion) {
  if (typeof candidateVersion !== 'string' || !/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(candidateVersion)) {
    throw new Error(`The candidate version ${candidateVersion} is not major.minor.patch.`)
  }
  const releases = Array.isArray(pages) ? pages.flat() : []
  const eligible = []
  for (const release of releases) {
    if (release?.draft !== false || release?.prerelease !== false) continue
    const match = /^v(\d+\.\d+\.\d+)$/.exec(release.tag_name ?? '')
    if (!match || compareVersions(match[1], candidateVersion) >= 0) continue
    const names = uploadedAssetNames(release)
    const deb = previousDebName(match[1])
    if (names.filter((name) => name === deb).length !== 1 || !names.includes(PREVIOUS_SUMS_ASSET)) continue
    eligible.push({ tag: release.tag_name, version: match[1], deb })
  }
  if (eligible.length === 0) {
    throw new Error(`No published release older than ${candidateVersion} carries both ${previousDebName('<version>')} and ${PREVIOUS_SUMS_ASSET}.`)
  }
  return eligible.sort((left, right) => compareVersions(right.version, left.version))[0]
}

function parseArguments(argv) {
  const options = {}
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    const value = argv[index + 1]
    if ((argument !== '--candidate' && argument !== '--releases') || value === undefined || value.startsWith('--')) {
      throw new Error('Usage: node tools/previous-linux-release.mjs --candidate <version> --releases <gh api --paginate --slurp output>')
    }
    options[argument.slice(2)] = value
    index += 1
  }
  if (!options.candidate || !options.releases) {
    throw new Error('Usage: node tools/previous-linux-release.mjs --candidate <version> --releases <gh api --paginate --slurp output>')
  }
  return options
}

async function main() {
  const options = parseArguments(process.argv.slice(2))
  const pages = JSON.parse(await readFile(options.releases, 'utf8'))
  const selected = selectPreviousLinuxRelease(pages, options.candidate)
  process.stdout.write(`${selected.tag}\n`)
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`)
    process.exit(2)
  })
}
