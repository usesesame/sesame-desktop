import { chmod, mkdtemp, readdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises'
import { execFile } from 'node:child_process'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { promisify } from 'node:util'

const run = promisify(execFile)

export const hostProvidedLibraryPatterns = [
  /^libwayland-client\.so\./,
  /^libwayland-cursor\.so\./,
]

export function planStrippedLibraries(fileNames) {
  return fileNames.filter((name) => hostProvidedLibraryPatterns.some((pattern) => pattern.test(name)))
}

function parseSquashfsSuperblock(summary) {
  const compression = summary.match(/Compression (zstd|xz|gzip|lz4|bzip2|lzo)/)
  const blockSize = summary.match(/Block size (\d+)/)
  if (!compression || !blockSize) throw new Error('Could not read the AppImage squashfs compression.')
  return { compression: compression[1], blockSize: Number(blockSize[1]) }
}

async function squashfsOffset(appimagePath) {
  const { stdout } = await run(appimagePath, ['--appimage-offset'])
  const offset = Number(stdout.trim())
  if (!Number.isSafeInteger(offset) || offset <= 0) {
    throw new Error(`${appimagePath}: --appimage-offset did not report a squashfs offset.`)
  }
  return offset
}

export async function stripAppImageHostLibraries(appImagePath) {
  const appImage = path.resolve(appImagePath)
  const offset = await squashfsOffset(appImage)
  const appImageBytes = await readFile(appImage)
  const payload = appImageBytes.subarray(offset)
  const workspace = await mkdtemp(path.join(tmpdir(), 'strip-appimage-'))
  try {
    const payloadPath = path.join(workspace, 'original.squashfs')
    await writeFile(payloadPath, payload)
    const { stdout: summary } = await run('unsquashfs', ['-s', payloadPath])
    const superblock = parseSquashfsSuperblock(summary)
    const tree = path.join(workspace, 'tree')
    await run('unsquashfs', ['-d', tree, payloadPath], { maxBuffer: 1024 * 1024 * 1024 })
    const libDirectory = path.join(tree, 'usr', 'lib')
    const libNames = await readdir(libDirectory).catch(() => [])
    const planned = planStrippedLibraries(libNames)
    if (planned.length === 0) {
      return { appImage, stripped: [], unchanged: true }
    }
    for (const name of planned) {
      await rm(path.join(libDirectory, name), { force: true })
    }
    const rebuiltSquashfs = path.join(workspace, 'rebuilt.squashfs')
    await run('mksquashfs', [
      tree,
      rebuiltSquashfs,
      '-comp', superblock.compression,
      '-b', String(superblock.blockSize),
      '-noappend',
      '-root-owned',
      '-no-recovery',
      '-quiet',
    ])
    const { stdout: listing } = await run('unsquashfs', ['-ls', rebuiltSquashfs])
    for (const name of planned) {
      if (listing.includes(name)) throw new Error(`The rebuilt AppImage still contains ${name}.`)
    }
    const finalBytes = Buffer.concat([appImageBytes.subarray(0, offset), await readFile(rebuiltSquashfs)])
    const rebuilt = path.join(workspace, 'rebuilt.AppImage')
    await writeFile(rebuilt, finalBytes)
    await chmod(rebuilt, 0o755)
    const rebuiltOffset = await squashfsOffset(rebuilt)
    if (rebuiltOffset !== offset) {
      throw new Error(`The rebuilt squashfs offset ${rebuiltOffset} does not match the runtime offset ${offset}.`)
    }
    const replacement = path.join(path.dirname(appImage), `.stripped-${path.basename(appImage)}`)
    await writeFile(replacement, finalBytes)
    await chmod(replacement, 0o755)
    await rename(replacement, appImage)
    const size = await stat(appImage)
    return { appImage, stripped: planned, unchanged: false, bytes: size.size }
  } finally {
    await rm(workspace, { recursive: true, force: true })
  }
}

async function main() {
  const inputs = process.argv.slice(2)
  if (inputs.length === 0) {
    throw new Error('Usage: node tools/strip-appimage-host-libs.mjs <appimage> [<appimage>...]')
  }
  for (const input of inputs) {
    const result = await stripAppImageHostLibraries(input)
    if (result.unchanged) {
      console.log(`${result.appImage}: no host-provided Wayland libraries are bundled; left unchanged.`)
      continue
    }
    console.log(`${result.appImage}: removed bundled ${result.stripped.join(', ')} (${result.bytes} bytes).`)
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  await main().catch((error) => {
    console.error(String(error?.message ?? error))
    process.exit(1)
  })
}
