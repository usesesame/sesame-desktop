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

test('the login card never carries the password across the seam', () => {
  const card = read('src', 'lib', 'generated', 'LoginCard.ts')
  assert.match(card, /hasPassword: boolean/)
  assert.doesNotMatch(card, /password: string/)
  const snapshot = read('src-tauri', 'sesame-core', 'src', 'snapshot.rs')
  assert.match(snapshot, /has_password: !entry\.password\.is_empty\(\)/)
})

test('the saved password is revealed only through a presence gate', () => {
  const logins = read('src-tauri', 'src', 'commands', 'logins.rs')
  const start = logins.indexOf('pub fn reveal_login_secret(')
  assert.ok(start >= 0, 'reveal_login_secret does not exist')
  const body = logins.slice(start, logins.indexOf('\n#[cfg(test)]', start))
  assert.match(body, /require_release_presence\(&state, &presence\)/)
  const vault = read('src', 'lib', 'vault.ts')
  assert.match(vault, /invoke(<[^>]+>)?\('reveal_login_secret', \{ id \}\)/)
})

test('a blank password on edit keeps the stored secret', () => {
  const logins = read('src-tauri', 'src', 'commands', 'logins.rs')
  const start = logins.indexOf('pub fn save_login(')
  const body = logins.slice(start, logins.indexOf('\n#[tauri::command]', start))
  assert.match(body, /keep_stored_password_on_blank_edit\(&mut updated, &previous\)/)
})
