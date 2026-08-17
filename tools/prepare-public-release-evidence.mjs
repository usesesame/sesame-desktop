import { copyFile, mkdir, readFile, readdir } from 'node:fs/promises'
import path from 'node:path'

const [sourceInput, destinationInput, manifestFilename] = process.argv.slice(2)
if (!sourceInput || !destinationInput || !manifestFilename) throw new Error('Usage: node tools/prepare-public-release-evidence.mjs <verified-directory> <public-directory> <manifest-filename>')
const source = path.resolve(sourceInput)
const destination = path.resolve(destinationInput)
const manifest = JSON.parse(await readFile(path.join(source, manifestFilename), 'utf8'))
const allow = new Set([
  manifestFilename,
  `${manifestFilename}.sigstore.json`,
  `${manifest.artifact.filename}.sigstore.json`,
  manifest.sbom.filename,
  'SHA256SUMS',
  'sigstore-evidence.json',
  'verify-sesame-release.ps1',
])
const existing = new Set(await readdir(source))
for (const required of allow) if (!existing.has(required)) throw new Error(`Public release evidence is missing ${required}.`)
await mkdir(destination, { recursive: false })
for (const filename of allow) await copyFile(path.join(source, filename), path.join(destination, filename))
process.stdout.write(`Prepared ${allow.size} public evidence files without the installer, updater signature, or source tree.\n`)
