import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import test from 'node:test'

const root = process.cwd()
const read = (...parts) => readFileSync(join(root, ...parts), 'utf8')

const GATED_RELEASES = ['export_backup', 'export_vault_csv', 'export_recovery_kit']

test('every deliberate release command requires presence in Rust', () => {
  const commands = read('src-tauri', 'src', 'commands', 'backups.rs')
  const application = read('src-tauri', 'sesame-app', 'src', 'application', 'backups.rs')
  for (const command of GATED_RELEASES) {
    const commandStart = commands.indexOf(`pub fn ${command}(`)
    assert.ok(commandStart >= 0, `${command} does not exist`)
    const commandNext = commands.indexOf('\n#[tauri::command]', commandStart)
    const commandBody = commands.slice(commandStart, commandNext === -1 ? commands.length : commandNext)
    assert.match(
      commandBody,
      new RegExp(`\\b${command}_in_state\\(`),
      `${command} does not call its application rule`,
    )
    const start = application.indexOf(`pub fn ${command}_in_state(`)
    assert.ok(start >= 0, `${command}_in_state does not exist in the application module`)
    const next = application.indexOf('\npub fn ', start)
    const body = application.slice(start, next === -1 ? application.length : next)
    assert.match(
      body,
      /require_release_presence\(state, presence\)/,
      `${command} releases vault contents without requiring presence`,
    )
  }
})

test('the release sentinel and the grant command agree across the seam', () => {
  const presence = read('src-tauri', 'sesame-app', 'src', 'release.rs')
  assert.match(presence, /PRESENCE_REQUIRED: &str = "presenceRequired"/)
  assert.match(presence, /PRESENCE_TTL: Duration = Duration::from_secs\(\d+\)/)

  const vault = read('src', 'lib', 'vault.ts')
  assert.match(vault, /PRESENCE_REQUIRED = 'presenceRequired'/)
  assert.match(vault, /invoke\('grant_presence', \{ secret \}\)/)

  const command = read('src-tauri', 'src', 'commands', 'release.rs')
  assert.match(command, /#\[tauri::command\(async\)\]\npub fn grant_presence\(/, 'the master password check runs on the window thread and freezes the window')

  const registered = read('src-tauri', 'src', 'lib.rs')
  assert.match(registered, /commands::grant_presence,/)
  assert.match(registered, /\.manage\(release::ReleasePresence::default\(\)\)/)

  const permissions = read('src-tauri', 'permissions', 'desktop.toml')
  assert.match(permissions, /"grant_presence"/)
})

test('release verification re-authenticates instead of trusting the session', () => {
  const presence = read('src-tauri', 'sesame-app', 'src', 'release.rs')
  assert.match(presence, /unwrap_with_password\(/)
  assert.match(presence, /bytes_match\(/)
  const crypto = read('src-tauri', 'sesame-core', 'src', 'crypto.rs')
  const unwrap = crypto.slice(crypto.indexOf('pub fn unwrap_with_password('), crypto.indexOf('fn derive_key_from_exact('))
  assert.match(unwrap, /derive_key_from_exact\(/)
  assert.match(unwrap, /decrypt_bytes\(/)
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
  const next = logins.indexOf('\n#[tauri::command]', start)
  const command = logins.slice(start, next === -1 ? logins.length : next)
  assert.match(
    command,
    /reveal_login_secret_in_state\(/,
    'reveal_login_secret does not call its application rule',
  )
  const rules = read('src-tauri', 'sesame-app', 'src', 'application', 'logins.rs')
  const ruleStart = rules.indexOf('pub fn reveal_login_secret_in_state(')
  assert.ok(ruleStart >= 0, 'reveal_login_secret_in_state is missing from the application module')
  const body = rules.slice(ruleStart, rules.indexOf('\npub fn ', ruleStart))
  assert.match(body, /require_release_presence\(state, presence\)\?/)
  assert.ok(
    body.indexOf('require_release_presence(state, presence)?') < body.indexOf('session.open_item('),
    'reveal_login_secret opens the item before the presence check',
  )
  const vault = read('src', 'lib', 'vault.ts')
  assert.match(vault, /invoke(<[^>]+>)?\('reveal_login_secret', \{ id \}\)/)
})

test('a tag keeps the unsigned release unpublished until a maintainer publishes it', () => {
  for (const scriptPath of ['reconcile-github-release.mjs', 'publish-linux-release.mjs']) {
    const script = read('tools', scriptPath)
    assert.match(
      script,
      /parseReleaseVisibility\(process\.env\.SESAME_RELEASE_VISIBILITY\)/,
      `${scriptPath} does not resolve the publication policy`,
    )
    assert.match(script, /visibility === RELEASE_VISIBILITY_DRAFT \? \['--draft'\] : \[\]/, `${scriptPath} can create a public release`)
  }

  const windows = read('.github', 'workflows', 'release-early-access.yml')
  const linux = read('.github', 'workflows', 'release-linux-early-access.yml')
  for (const [name, workflow] of [['Windows', windows], ['Linux', linux]]) {
    assert.match(workflow, /SESAME_RELEASE_VISIBILITY: draft/, `${name} does not declare the draft policy`)
    assert.match(workflow, /--json isDraft/, `${name} does not verify the draft state`)
    assert.match(workflow, /releases\/download\/\$GITHUB_REF_NAME/, `${name} does not probe the public asset URL`)
  }
  assert.match(windows, /for asset in "\$installer" latest\.json; do/, 'the Windows lane must prove the updater manifest is unreachable')
})

test('a blank password on edit keeps the stored secret', () => {
  const storage = read('src-tauri', 'sesame-core', 'src', 'storage.rs')
  const start = storage.indexOf('pub fn payload_with_saved_login(')
  assert.ok(start >= 0, 'payload_with_saved_login does not exist')
  const next = storage.indexOf('\npub fn ', start + 1)
  const body = storage.slice(start, next === -1 ? storage.length : next)
  assert.match(
    body,
    /updated\.password = previous\.password\.clone\(\)/,
    'the vault mutation must keep the stored secret when the edit leaves the password blank',
  )

  const logins = read('src-tauri', 'src', 'commands', 'logins.rs')
  const saveStart = logins.indexOf('pub fn save_login(')
  assert.ok(saveStart >= 0, 'save_login does not exist')
  const saveNext = logins.indexOf('\n#[tauri::command]', saveStart)
  const saveBody = logins.slice(saveStart, saveNext === -1 ? logins.length : saveNext)
  assert.match(
    saveBody,
    /save_login_in_state\(/,
    'save_login does not call its application rule',
  )
  const rules = read('src-tauri', 'sesame-app', 'src', 'application', 'logins.rs')
  const ruleStart = rules.indexOf('pub fn save_login_in_state(')
  assert.ok(ruleStart >= 0, 'save_login_in_state is missing from the application module')
  const ruleBody = rules.slice(ruleStart, rules.indexOf('\npub fn ', ruleStart))
  assert.match(
    ruleBody,
    /payload_with_saved_login\(/,
    'save_login must write through the one vault-domain mutation',
  )
})

test('release notes written by the release workflows never describe the release as a draft', () => {
  for (const workflow of ['release-early-access.yml', 'release-linux-early-access.yml']) {
    const text = read('.github', 'workflows', workflow)
    for (const target of ['release-section.md', 'release-notes.md']) {
      const end = text.indexOf(`} > ${target}`)
      assert.ok(end > 0, `${workflow} no longer writes ${target}`)
      const notes = text.slice(text.lastIndexOf('          {\n', end), end)
      assert.doesNotMatch(notes, /draft/i, `${workflow} writes a draft claim into notes that outlive the draft`)
    }
  }
})

test('each release workflow hands its own platform section to the tool that merges it into the shared body', () => {
  const windows = read('.github', 'workflows', 'release-early-access.yml')
  const linux = read('.github', 'workflows', 'release-linux-early-access.yml')
  assert.match(windows, /reconcile-github-release\.mjs [^\n]* release-notes\.md release-section\.md\n/)
  assert.match(linux, /publish-linux-release\.mjs [^\n]* release-notes\.md release-section\.md\n/)
  const sectionOf = (text) => text.slice(text.lastIndexOf('          {\n', text.indexOf('} > release-section.md')), text.indexOf('} > release-section.md'))
  const windowsSection = sectionOf(windows)
  assert.match(windowsSection, /echo "Early access build for Windows 10 and 11, x64\."/)
  assert.match(windowsSection, /not Authenticode signed, so SmartScreen will warn you/)
  assert.match(windowsSection, /gh release download \$GITHUB_REF_NAME --repo \$GITHUB_REPOSITORY/)
  assert.match(windowsSection, /verify-sesame-release\.ps1 -Installer/)
  assert.match(windowsSection, /-HashOnly/)
  assert.match(windowsSection, /SHA-256 of \$installer/)
  assert.doesNotMatch(windowsSection, /Release set digest|\$changes/)
  const linuxSection = sectionOf(linux)
  assert.match(linuxSection, /echo "Early access build for Linux x86_64: deb, rpm, and AppImage packages\."/)
  assert.match(linuxSection, /not signed by a distribution key/)
  assert.match(linuxSection, /SHA-256 digests are in SHA256SUMS-linux\./)
  assert.doesNotMatch(linuxSection, /Release set digest|\$changes/)
  for (const [name, text] of [['Windows', windows], ['Linux', linux]]) {
    const notes = text.slice(text.lastIndexOf('          {\n', text.indexOf('} > release-notes.md')), text.indexOf('} > release-notes.md'))
    assert.match(notes, /echo "\$changes"[\s\S]*cat release-section\.md[\s\S]*Release set digest: \$setdigest/, `${name} creates the release body from the changelog, its section and its digest`)
  }
})
