import { createHash } from 'node:crypto'
import { execFile } from 'node:child_process'
import { chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'

const run = promisify(execFile)

export const verifiedCliVersion = '2.11.4'

export const pinnedBundleTools = {
  x86_64: [
    {
      name: 'AppRun-x86_64',
      url: 'https://github.com/tauri-apps/binary-releases/releases/download/apprun-old/AppRun-x86_64',
      sha256: 'f30140a43a0a59e46db21bdefdf749b9e9f2c6946e92afabbacf98b8ae73fb4f',
    },
    {
      name: 'linuxdeploy-x86_64.AppImage',
      url: 'https://github.com/tauri-apps/binary-releases/releases/download/linuxdeploy/linuxdeploy-x86_64.AppImage',
      sha256: 'e762bea85c8eb0d4b3508d46e5c1f037f717d0f9303ae3b4aafc8b04991fa1ef',
    },
    {
      name: 'linuxdeploy-plugin-gtk.sh',
      url: 'https://raw.githubusercontent.com/tauri-apps/linuxdeploy-plugin-gtk/dda522bce37387f1b853d9095713bfaa924c8423/linuxdeploy-plugin-gtk.sh',
      sha256: '7804c9eef13e59bf2783aad9882ef9db8f3f3f9e8d631874b1d348d550a3693f',
    },
    {
      name: 'linuxdeploy-plugin-gstreamer.sh',
      url: 'https://raw.githubusercontent.com/tauri-apps/linuxdeploy-plugin-gstreamer/2a2e67491c32995a3f279ad0ecbe77abd512b42a/linuxdeploy-plugin-gstreamer.sh',
      sha256: 'c107b49d84edbffc6ab226ed1007e0626a4f7aa2c3a36b7782bef62351d49e94',
    },
    {
      name: 'linuxdeploy-plugin-appimage.AppImage',
      url: 'https://github.com/linuxdeploy/linuxdeploy-plugin-appimage/releases/download/continuous/linuxdeploy-plugin-appimage-x86_64.AppImage',
      sha256: '0441769ab38009504d2678c38cd7e526955388dd30a215b4a20afaa5471652f2',
    },
  ],
}

export function toolPins(architecture) {
  const pins = pinnedBundleTools[architecture]
  if (!pins) throw new Error(`No pinned Linux bundling tools for ${architecture}.`)
  return pins
}

export function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function parseArguments(argv) {
  const options = {}
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    if (argument === '--tools-dir') options.toolsDir = argv[++index]
    else if (argument === '--repo') options.repo = argv[++index]
    else throw new Error(`Unknown argument: ${argument}`)
  }
  return options
}

async function localToolsDirectory(repo) {
  const { stdout } = await run('cargo', ['metadata', '--no-deps', '--format-version', '1', '--manifest-path', path.join(repo, 'src-tauri', 'Cargo.toml')], { maxBuffer: 32 * 1024 * 1024 })
  const metadata = JSON.parse(stdout)
  if (typeof metadata.target_directory !== 'string') throw new Error('cargo metadata did not report a target directory.')
  return path.join(metadata.target_directory, '.tauri')
}

async function fetchTool(tool) {
  const response = await fetch(tool.url, { redirect: 'follow' })
  if (!response.ok) throw new Error(`Could not download ${tool.name}: HTTP ${response.status}.`)
  return Buffer.from(await response.arrayBuffer())
}

export async function installPinnedTool(tool, toolsDir) {
  const target = path.join(toolsDir, tool.name)
  const existing = await readFile(target).catch(() => null)
  if (existing && digest(existing) === tool.sha256) return { name: tool.name, path: target, downloaded: false }
  const bytes = await fetchTool(tool)
  const actual = digest(bytes)
  if (actual !== tool.sha256) {
    throw new Error(`${tool.name} does not match its pinned SHA-256: expected ${tool.sha256}, received ${actual}.`)
  }
  const temporary = `${target}.download`
  await writeFile(temporary, bytes)
  await chmod(temporary, 0o755)
  await rename(temporary, target)
  return { name: tool.name, path: target, downloaded: true, bytes: bytes.length }
}

async function main() {
  const options = parseArguments(process.argv.slice(2))
  const repo = path.resolve(options.repo ?? path.join(path.dirname(fileURLToPath(import.meta.url)), '..'))
  const architecture = process.arch === 'x64' ? 'x86_64' : process.arch === 'arm64' ? 'aarch64' : process.arch
  const toolsDir = options.toolsDir ? path.resolve(options.toolsDir) : await localToolsDirectory(repo)
  const pins = toolPins(architecture)
  await mkdir(toolsDir, { recursive: true })
  for (const tool of pins) {
    const result = await installPinnedTool(tool, toolsDir)
    process.stdout.write(`${result.name}: ${result.downloaded ? 'downloaded and verified' : 'cached and verified'}.\n`)
  }
}

const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
if (invokedDirectly) {
  main().catch((error) => {
    process.stderr.write(`${error.message ?? error}\n`)
    process.exitCode = 2
  })
}
