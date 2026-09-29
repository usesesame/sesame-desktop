import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const crateURL = 'https://static.crates.io/crates/glib/glib-0.18.5.crate'
const crateSHA256 = '233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5'
const patchPath = join(root, 'src-tauri', 'vendor', 'glib.patch')
const vendorPath = join(root, 'src-tauri', 'vendor', 'glib')

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')

const work = mkdtempSync(join(tmpdir(), 'sesame-glib-'))
try {
  const cratePath = join(work, 'glib-0.18.5.crate')
  const cached = process.env.SESAME_GLIB_CRATE
  if (cached) {
    copyFileSync(cached, cratePath)
  } else {
    const response = await fetch(crateURL)
    if (!response.ok) throw new Error(`Could not download the glib crate: HTTP ${response.status}`)
    writeFileSync(cratePath, Buffer.from(await response.arrayBuffer()))
  }
  const actual = sha256(readFileSync(cratePath))
  if (actual !== crateSHA256) {
    throw new Error(`The glib crate digest changed: expected ${crateSHA256}, got ${actual}`)
  }
  const upstream = join(work, 'glib-0.18.5')
  execFileSync('tar', ['-xzf', cratePath, '-C', work])
  if (!existsSync(upstream)) throw new Error('The glib crate did not contain glib-0.18.5')
  execFileSync('patch', ['-p1', '-d', upstream, '-i', patchPath], { stdio: 'pipe' })
  try {
    execFileSync('diff', ['-r', '--exclude=.cargo-ok', upstream, vendorPath], { stdio: 'pipe' })
  } catch (error) {
    const detail = error.stdout?.toString().trim() || error.stderr?.toString().trim() || 'unknown difference'
    throw new Error(`The vendored glib tree is not the pinned crate plus the checked-in patch:\n${detail}`, { cause: error })
  }
  console.log('The vendored glib tree matches glib 0.18.5 plus the checked-in patch.')
} finally {
  rmSync(work, { recursive: true, force: true })
}
