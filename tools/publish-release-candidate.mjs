import { execFile } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { promisify } from 'node:util'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const artifactArgs = process.argv.slice(2)
if (artifactArgs.length < 3 || artifactArgs.length > 4) {
  throw new Error('Usage: npm run release:publish -- <artifact> <tauri-signature> <sigstore-evidence.json> [authenticode-evidence.json]')
}

const workspace = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const architecture = process.env.SESAME_RELEASE_ARCHITECTURE
if (architecture !== 'x86_64' && architecture !== 'aarch64') {
  throw new Error('SESAME_RELEASE_ARCHITECTURE must be x86_64 or aarch64.')
}
const manifest = JSON.parse(await readFile(path.join(workspace, 'package.json'), 'utf8'))
const candidatePath = path.join(workspace, 'release-artifacts', `sesame-${manifest.version}-windows-${architecture}.candidate.json`)
const run = promisify(execFile)

await run(process.execPath, ['tools/create-updater-artifacts.mjs', ...artifactArgs], { cwd: workspace, env: process.env })
await run(process.execPath, ['tools/submit-release-candidate.mjs', candidatePath], { cwd: workspace, env: process.env })
console.log(`Published verified release candidate: ${candidatePath}`)
