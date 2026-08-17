import { execFileSync } from 'node:child_process'
import { cp, lstat, mkdir, mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const boundary = JSON.parse(await readFile(path.join(root, 'desktop-boundary.json'), 'utf8'))
const destination = await mkdtemp(path.join(tmpdir(), 'sesame-desktop-boundary-'))
const runGate = process.argv.includes('--run')

function gitFiles(paths) {
  const output = execFileSync(
    'git',
    ['ls-files', '-z', '--cached', '--others', '--exclude-standard', '--', ...paths],
    { cwd: root, encoding: 'utf8' },
  )
  return output.split('\0').filter(Boolean)
}

try {
  const declared = [...boundary.directories, ...boundary.files]
  const files = gitFiles(declared)
  if (files.length === 0) throw new Error('The desktop boundary selected no files.')

  for (const relative of files) {
    const source = path.resolve(root, relative)
    if (source !== root && !source.startsWith(`${root}${path.sep}`)) {
      throw new Error(`Desktop boundary path escaped the workspace: ${relative}`)
    }
    if ((await lstat(source)).isSymbolicLink()) {
      throw new Error(`Desktop boundary contains a symbolic link: ${relative}`)
    }
    const target = path.join(destination, relative)
    await mkdir(path.dirname(target), { recursive: true })
    await cp(source, target)
  }

  console.log(`Copied ${files.length} desktop-owned files into ${destination}`)
  if (runGate) {
    const env = {
      ...process.env,
      CARGO_TARGET_DIR: path.join(tmpdir(), 'sesame-desktop-boundary-target'),
      SESAME_API_BASE_URL: 'https://api.test.invalid',
      VITE_SESAME_SITE_ORIGIN: 'https://website.test.invalid',
    }
    const npmExecPath = process.env.npm_execpath
    if (!npmExecPath) throw new Error('Run this verifier through npm so it can reuse the locked npm CLI.')
    execFileSync(process.execPath, [npmExecPath, 'ci'], { cwd: destination, env, stdio: 'inherit' })
    execFileSync(process.execPath, [npmExecPath, 'run', 'desktop:ci'], { cwd: destination, env, stdio: 'inherit' })
    console.log('Standalone desktop boundary passed its owned CI command.')
  }
} finally {
  await rm(destination, { recursive: true, force: true })
}
