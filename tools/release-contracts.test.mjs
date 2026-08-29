import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import test from 'node:test'

const root = process.cwd()
const read = (...parts) => readFileSync(join(root, ...parts), 'utf8')

const GATED_RELEASES = ['export_backup', 'export_vault_csv', 'export_recovery_kit']

test('every deliberate release command requires presence in Rust', () => {
  const source = read('src-tauri', 'src', 'commands', 'backups.rs')
  for (const command of GATED_RELEASES) {
    const start = source.indexOf(`pub fn ${command}(`)
    assert.ok(start >= 0, `${command} does not exist`)
    const next = source.indexOf('\n#[tauri::command]', start)
    const body = source.slice(start, next === -1 ? source.length : next)
    assert.match(
      body,
      /require_release_presence\(&state, &presence\)/,
      `${command} releases vault contents without requiring presence`,
    )
  }
})

test('the release sentinel and the grant command agree across the seam', () => {
  const presence = read('src-tauri', 'src', 'release.rs')
  assert.match(presence, /PRESENCE_REQUIRED: &str = "presenceRequired"/)
  assert.match(presence, /PRESENCE_TTL: Duration = Duration::from_secs\(\d+\)/)

  const vault = read('src', 'lib', 'vault.ts')
  assert.match(vault, /PRESENCE_REQUIRED = 'presenceRequired'/)
  assert.match(vault, /invoke\('grant_presence', \{ secret \}\)/)

  const registered = read('src-tauri', 'src', 'lib.rs')
  assert.match(registered, /commands::grant_presence,/)
  assert.match(registered, /\.manage\(release::ReleasePresence::default\(\)\)/)

  const permissions = read('src-tauri', 'permissions', 'desktop.toml')
  assert.match(permissions, /"grant_presence"/)
})

test('release verification re-authenticates instead of trusting the session', () => {
  const presence = read('src-tauri', 'src', 'release.rs')
  assert.match(presence, /derive_key\(/)
  assert.match(presence, /bytes_match\(/)
  assert.doesNotMatch(presence, /secret == |password == |\.key ==/)
})
