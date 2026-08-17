import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { copyFile, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

const run = promisify(execFile)
const workspace = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const artifactsRoot = resolve(workspace, 'release-artifacts')
const outputArgument = process.argv[2]
if (!outputArgument) {
  throw new Error('Usage: node tools/prepare-installer-vm-pair.mjs <release-artifacts/output-directory>')
}
const output = resolve(workspace, outputArgument)
const outputLocation = relative(artifactsRoot, output)
if (!outputLocation || outputLocation === '..' || outputLocation.startsWith(`..${sep}`)) {
  throw new Error('The installer VM pair output must be a new directory under release-artifacts/.')
}

const tauriCLI = join(workspace, 'node_modules', '@tauri-apps', 'cli', 'tauri.js')
const bundleDirectory = join(workspace, 'src-tauri', 'target', 'release', 'bundle', 'nsis')
let completed = false

async function build(extraConfig) {
  const args = [tauriCLI, 'build', '--bundles', 'nsis', '--no-sign']
  if (extraConfig) args.push('--config', extraConfig)
  await run(process.execPath, args, {
    cwd: workspace,
    env: process.env,
    maxBuffer: 32 * 1024 * 1024,
  })
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

await mkdir(output, { recursive: false })
try {
  const higherOverlay = join(output, 'tauri.lifecycle-higher.json')
  await writeFile(
    higherOverlay,
    `${JSON.stringify({ version: '0.1.1', bundle: { createUpdaterArtifacts: false } }, null, 2)}\n`,
  )

  await build()
  const baselineName = 'Sesame_0.1.0_x64-setup.exe'
  await copyFile(join(bundleDirectory, baselineName), join(output, baselineName))

  await build(higherOverlay)
  const higherName = 'Sesame_0.1.1_x64-setup.exe'
  await copyFile(join(bundleDirectory, higherName), join(output, higherName))

  const lines = []
  for (const name of [baselineName, higherName]) {
    const bytes = await readFile(join(output, name))
    lines.push(`${sha256(bytes)}  ${name}`)
  }
  await writeFile(join(output, 'SHA256SUMS.txt'), `${lines.join('\n')}\n`)
  completed = true
  console.log(`Created REL-003 installer VM pair: ${output}`)
} finally {
  if (!completed) await rm(output, { recursive: true, force: true })
}
