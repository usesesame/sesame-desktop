import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { dirname, join, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const read = (...parts) => readFileSync(join(root, ...parts), 'utf8')

function sourceFiles(dir, pattern) {
  return readdirSync(join(root, dir)).flatMap((name) => {
    const relative = join(dir, name)
    if (statSync(join(root, relative)).isDirectory()) return sourceFiles(relative, pattern)
    return pattern.test(name) ? [relative] : []
  })
}

test('Sync stays disabled: the capability flag is never defaulted on', () => {
  const routes = read('backend', 'internal', 'httpapi', 'sync_routes.go')
  assert.match(
    routes,
    /if !a\.syncEnabled\(request\.Context\(\)\) \{/,
    'requireSync must gate on syncEnabled, so the route gate and the reported capability can never disagree',
  )

  const server = read('backend', 'internal', 'httpapi', 'server.go')
  const definition = server.match(/func \(a \*api\) syncEnabled\(ctx context\.Context\) bool \{([^}]*)\}/)
  assert.ok(definition, 'syncEnabled is no longer a single function this test can read')
  assert.match(
    definition[1],
    /runtimeFlagBool\(ctx, "cloud_sync_available", false\)/,
    'syncEnabled must read the flag with an explicit false fallback',
  )
  assert.match(
    definition[1],
    /&&\s*a\.config\.Sync != nil/,
    'syncEnabled must also require a configured store, or the flag alone would enable Sync',
  )

  for (const [name, source] of [['sync_routes.go', routes], ['syncEnabled', definition[1]]]) {
    assert.doesNotMatch(
      source,
      /capabilityEnabled\(/,
      `${name}: capabilityEnabled falls back to true when no admin flag store is configured, which is every test and every local run. Sync must fail closed.`,
    )
  }
})

test('Sync stays disabled: nothing reports it as available on the flag alone', () => {
  for (const parts of [
    ['backend', 'internal', 'httpapi', 'capabilities.go'],
    ['backend', 'internal', 'httpapi', 'server.go'],
  ]) {
    const source = read(...parts)
    for (const line of source.split('\n')) {
      if (!/"sync"|cloudSyncAvailable/.test(line)) continue
      if (!/cloud_sync_available/.test(line)) continue
      assert.fail(
        `${parts.join('/')} reports Sync from the flag directly. Use a.syncEnabled:\n  ${line.trim()}`,
      )
    }
  }
})

test('Sync stays disabled: the store is not wired into the running API', () => {
  const main = read('backend', 'cmd', 'api', 'main.go')
  assert.doesNotMatch(
    main,
    /Sync:\s*syncstore\./,
    'configuring Config.Sync is a deliberate Phase 5 step. Enabling Sync should take a code change and a flag change, not a flag change alone.',
  )
})

test('Sync stays disabled: no sync command is reachable from a shipping build', () => {
  const lib = read('src-tauri', 'src', 'lib.rs')

  const base = lib.match(/macro_rules! sesame_invoke_handler \{[\s\S]*?\n\}/)
  assert.ok(base, 'the shared invoke handler list is no longer a single macro this test can read')
  assert.doesNotMatch(
    base[0],
    /sync/i,
    'a Sync command is in the shared command list, so it registers in every build',
  )

  const arms = [
    ...lib.matchAll(
      /#\[cfg\((not\()?feature = "sync-preview"\)?\)\]\s*\nmacro_rules! sesame_handler \{[\s\S]*?\n\}/g,
    ),
  ]
  assert.equal(arms.length, 2, 'expected exactly one sync-preview arm and one without it')
  for (const arm of arms) {
    const gated = !arm[1]
    const mentionsSync = /commands::sync::/.test(arm[0])
    assert.equal(
      mentionsSync,
      gated,
      gated
        ? 'the sync-preview arm no longer registers the Sync commands'
        : 'the arm compiled without sync-preview registers a Sync command, which would ship it',
    )
  }

  const commands = read('src-tauri', 'src', 'commands.rs')
  assert.match(
    commands,
    /#\[cfg\(feature = "sync-preview"\)\]\s*\npub mod sync;/,
    'commands::sync must be declared behind #[cfg(feature = "sync-preview")]',
  )
})

test('the Sync client never hands key material to the webview', () => {
  for (const file of sourceFiles(join('src-tauri', 'src', 'commands'), /\.rs$/)) {
    const whole = read(file)
    const testModule = whole.indexOf('#[cfg(test)]')
    const source = testModule === -1 ? whole : whole.slice(0, testModule)

    assert.ok(
      !whole.includes('#[tauri::command]') || source.includes('#[tauri::command]'),
      `${file}: every command sits below #[cfg(test)], so this check reads nothing`,
    )

    for (const forbidden of ['secret_bytes', 'signing_key(', 'encryption_keypair(', 'to_bytes()']) {
      assert.ok(
        !source.includes(forbidden),
        `${file} calls ${forbidden}: key material must not cross the IPC boundary`,
      )
    }
  }
})

test('the Sync service stores bytes it cannot read', () => {
  const store = read('backend', 'internal', 'syncstore', 'envelopes.go')
  assert.doesNotMatch(store, /string\(envelope\.Ciphertext\)/)
  assert.doesNotMatch(store, /json\.Unmarshal\(envelope\.Ciphertext/)
  assert.match(
    store,
    /Ciphertext\s+\[\]byte/,
    'envelope ciphertext must stay []byte in the store',
  )
})

test('signing and key agreement use separate keys', () => {
  const identity = read('src-tauri', 'src', 'sync', 'identity.rs')
  assert.match(identity, /signing:\s*SigningKey/)
  assert.match(identity, /encryption:\s*EncryptionKeypair/)

  const migration = read(
    'backend',
    'internal',
    'accounts',
    'migrations',
    '0024_sync_control_plane.sql',
  )
  assert.match(migration, /signing_public_key\s+BYTEA/)
  assert.match(migration, /encryption_public_key\s+BYTEA/)
})

test('the append-only Sync audit records no vault content', () => {
  const migration = read(
    'backend',
    'internal',
    'accounts',
    'migrations',
    '0024_sync_control_plane.sql',
  )
  const audit = migration.slice(migration.indexOf('CREATE TABLE IF NOT EXISTS sesame_sync_audit'))
  const table = audit.slice(0, audit.indexOf(');'))
  for (const forbidden of ['ciphertext', 'nonce', 'signature', 'label', 'size', 'bytes']) {
    assert.ok(
      !table.includes(forbidden),
      `sesame_sync_audit must not record ${forbidden}: an audit row must not describe the vault`,
    )
  }
  assert.match(migration, /sesame_sync_audit is append-only/)
})

test('the Sync screens render only in a preview build', () => {
  const settings = read('src', 'lib', 'ui', 'SettingsView.svelte')
  const guarded = settings.match(/\{#if SYNC_PREVIEW_AVAILABLE\}([\s\S]*?)\{\/if\}/)
  assert.ok(guarded, 'the Sync host is no longer inside an {#if SYNC_PREVIEW_AVAILABLE} block')
  assert.match(guarded[1], /<SyncPreviewHost\s*\/>/, 'the guard no longer renders SyncPreviewHost')

  for (const component of ['SyncPreviewHost', 'SyncVaultStorageRow']) {
    const uses = [...settings.matchAll(new RegExp(`<${component}\\s*/>`, 'g'))]
    assert.ok(uses.length > 0, `${component} is no longer rendered by SettingsView`)
    const blocks = [...settings.matchAll(/\{#if SYNC_PREVIEW_AVAILABLE\}([\s\S]*?)\{\/if\}/g)]
    const gated = blocks.some((block) => block[1].includes(`<${component}`))
    assert.ok(gated, `${component} renders outside an {#if SYNC_PREVIEW_AVAILABLE} guard, so a release build would ship the Sync client`)
  }

  const app = read('src', 'App.svelte')
  const host = read('src', 'lib', 'ui', 'SyncPreviewHost.svelte')
  const callers = [
    ['App.svelte', app],
    ['SettingsView.svelte', settings],
  ]
  for (const screen of ['SyncEnableModal', 'SyncApproveDeviceModal', 'SyncConflictModal']) {
    read('src', 'lib', 'ui', `${screen}.svelte`)
    assert.match(host, new RegExp(`<${screen}\\b`), `${screen} is not rendered by SyncPreviewHost`)
    for (const [name, source] of callers) {
      assert.ok(
        !source.includes(`<${screen}`),
        `${screen} renders directly in ${name}, which keeps it in a release bundle even when nothing shows it`,
      )
    }
  }
  for (const [name, source] of callers) {
    assert.ok(
      !source.includes('createSyncPreviewController'),
      `the Sync controller is constructed in ${name}, so it survives into a release bundle`,
    )
  }

  const meta = read('src', 'lib', 'app-meta.ts')
  const definition = meta.match(/export const SYNC_PREVIEW_AVAILABLE =([\s\S]*?)(?:\n\n|\n?$)/)
  assert.ok(definition, 'SYNC_PREVIEW_AVAILABLE is no longer a single declaration this test can read')
  assert.match(definition[1], /import\.meta\.env\.DEV/, 'the preview flag must require a development build')
  assert.match(
    definition[1],
    /VITE_SESAME_SYNC_PREVIEW === 'true'/,
    'the preview flag must require an explicit opt-in as well as a development build',
  )
})

test('a release build says where to check Sync, and claims nothing itself', () => {
  const settings = read('src', 'lib', 'ui', 'SettingsView.svelte')
  const row = settings.match(/\{#if !SYNC_PREVIEW_AVAILABLE\}([\s\S]*?)\n {12}\{\/if\}/)
  assert.ok(row, 'the release-build Sync status row is gone, so Settings never mentions Sync at all')

  assert.match(
    row[1],
    /\{#if serviceConnection\.syncAvailable\}/,
    'the Sync row picks its wording from something other than the service field, so it can contradict the website',
  )
  assert.match(
    row[1],
    /class="status-pill">\{serviceConnection\.syncAvailable \?/,
    'the Sync row states a fixed availability rather than the one the service reports',
  )
  assert.match(
    row[1],
    /onOpenWebsite\(syncStatusUrl\)/,
    'the Sync row no longer links anywhere someone can check the current state',
  )

  for (const forbidden of ['SyncPreviewHost', 'SyncVaultStorageRow', 'createSyncPreviewController', 'invoke(']) {
    assert.ok(
      !row[1].includes(forbidden),
      `the release-build Sync row references ${forbidden}, which puts the Sync client into a shipping bundle`,
    )
  }

  const site = read('website', 'src', 'Site.svelte')
  assert.match(
    site,
    /<dt>Sesame Sync<\/dt><dd>\{productStatus\?\.cloudSyncAvailable \? 'Available' : 'Not available'\}<\/dd>/,
    'the website no longer reports Sync status from the product status endpoint',
  )

  const meta = read('src', 'lib', 'app-meta.ts')
  const target = meta.match(/SYNC_STATUS_URL = siteOrigin \? `\$\{siteOrigin\}(\/[^`]*)`/)
  assert.ok(target, 'SYNC_STATUS_URL is no longer a single origin-relative declaration this test can read')
  const [path, fragment] = target[1].split('#')
  assert.match(site, new RegExp(`page === '${path.slice(1)}'`), `the website has no ${path} page for Settings to link to`)
  assert.match(site, new RegExp(`id="${fragment}"`), `the ${path} page has no #${fragment} section for the link to land on`)
})

test('the Sync conflict screen never preselects a side', () => {
  const conflict = read('src', 'lib', 'ui', 'SyncConflictModal.svelte')
  assert.match(
    conflict,
    /let choice: 'this' \| 'other' \| '' = ''/,
    'the conflict choice must start empty',
  )
  assert.match(
    conflict,
    /disabled=\{!choice \|\| working \|\| !detailsLoaded\}/,
    'the keep button must require a choice and real details for both sides',
  )
})

test('the cross-language signing fixture is committed and asserted from both sides', () => {
  const fixture = JSON.parse(
    read('backend', 'internal', 'syncproto', 'testdata', 'envelope-signing-payload.json'),
  )
  assert.ok(fixture.snapshotSigningPayload, 'the fixture must carry a snapshot payload')
  assert.ok(
    !fixture.tombstoneSigningPayload,
    'the fixture describes a tombstone payload for an operation the protocol refuses',
  )
  assert.ok(
    fixture.input?.previousDigest,
    'the fixture no longer covers the revision chain, so the two sides can drift on it',
  )
  assert.ok(
    fixture.snapshotSigningPayload.includes('"previousDigest"'),
    'the predecessor digest is outside the signed payload again',
  )
  assert.ok(
    fixture.rustSignedSnapshot?.signature,
    'the fixture must carry a Rust-produced signature for Go to verify',
  )

  const goTest = read('backend', 'internal', 'syncproto', 'envelope_fixture_test.go')
  assert.match(goTest, /envelope-signing-payload\.json/)
  assert.match(goTest, /VerifySignature/)
  assert.match(
    goTest,
    /filepath\.Join\("testdata"/,
    'the Go fixture path must not escape the module, or the containerised build cannot see it',
  )

  const rustTest = read('src-tauri', 'src', 'sync', 'envelope.rs')
  assert.match(rustTest, /envelope-signing-payload\.json/)

  const desktopRoot = join(root, 'src-tauri', 'contracts', 'sync', 'v2')
  const desktopSource = JSON.parse(readFileSync(join(desktopRoot, 'source.json'), 'utf8'))
  assert.match(desktopSource.sourceCommit, /^[0-9a-f]{40}$/)
  for (const name of Object.keys(desktopSource.files)) {
    assert.deepEqual(
      readFileSync(join(desktopRoot, name)),
      readFileSync(join(root, 'backend', 'internal', 'syncproto', 'testdata', name)),
      `${name}: the desktop and server contract snapshots drifted`,
    )
  }
})

test('Sync stays disabled: the network client is not compiled into a shipping build', () => {
  const manifest = read('src-tauri', 'Cargo.toml')
  assert.match(manifest, /^sync-preview = \[\]$/m, 'the sync-preview feature is gone')

  const defaultFeature = manifest.match(/^default = \[([^\]]*)\]/m)
  if (defaultFeature) {
    assert.doesNotMatch(
      defaultFeature[1],
      /sync-preview/,
      'sync-preview is in the default feature set, so a plain `cargo build` compiles the Sync client',
    )
  }
  for (const line of manifest.split('\n')) {
    const other = line.match(/^([a-z-]+) = \[(.*)\]$/)
    if (!other || other[1] === 'sync-preview') continue
    assert.doesNotMatch(
      other[2],
      /"sync-preview"/,
      `the ${other[1]} feature enables sync-preview, which routes around the gate`,
    )
  }

  const module = read('src-tauri', 'src', 'sync', 'mod.rs')
  assert.match(
    module,
    /#\[cfg\(feature = "sync-preview"\)\]\s*\npub\(crate\) use crate::adapters::network::sync as client;/,
    'the sync::client compatibility export must stay behind #[cfg(feature = "sync-preview")]',
  )
  const adapters = read('src-tauri', 'src', 'adapters', 'network', 'mod.rs')
  assert.match(
    adapters,
    /#\[cfg\(feature = "sync-preview"\)\]\s*\npub\(crate\) mod sync;/,
    'the network adapter itself must stay behind #[cfg(feature = "sync-preview")]',
  )
})

test('Sync stays disabled: only a development binary wires the store', () => {
  const preview = read('backend', 'cmd', 'api-sync-preview', 'main.go')
  assert.match(
    preview,
    /os\.Getenv\("SESAME_ENV"\)\) != "development"/,
    'the Sync preview API must refuse to start outside development',
  )
  assert.match(preview, /Sync:\s+syncstore\.New\(/, 'the preview API no longer wires the Sync store')

  const dockerfile = read('backend', 'Dockerfile')
  assert.doesNotMatch(
    dockerfile,
    /api-sync-preview/,
    'the container image builds the Sync preview binary, which would ship a Sync-wired API',
  )

  const wiring = []
  for (const file of sourceFiles(join('backend', 'cmd'), /\.go$/)) {
    if (/Sync:\s+syncstore\./.test(read(file))) wiring.push(file)
  }
  assert.deepEqual(
    wiring.map((file) => file.split(sep).join('/')),
    ['backend/cmd/api-sync-preview/main.go'],
    'a binary other than the development preview wires the Sync store',
  )
})

test('the Sync preview command opens both gates, not just one', () => {
  const scripts = JSON.parse(read('package.json')).scripts
  const runner = scripts['sync:preview:desktop']
  assert.ok(runner, 'sync:preview:desktop is gone')

  assert.doesNotMatch(
    runner,
    /^tauri /,
    'sync:preview:desktop sets the Cargo feature directly, so it cannot also set the frontend flag',
  )

  const source = read('tools', 'run-sync-preview-desktop.mjs')
  assert.match(
    source,
    /VITE_SESAME_SYNC_PREVIEW: 'true'/,
    'the preview runner no longer opens the frontend gate, so the panel will not render',
  )
  assert.match(
    source,
    /'--features',\s*'sync-preview'/,
    'the preview runner no longer opens the Cargo gate, so the commands will not exist',
  )

  assert.doesNotMatch(
    source,
    /SESAME_API_BASE_URL/,
    'the preview runner overrides the API URL, which invalidates an existing account link',
  )
  const code = source
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('//'))
    .join('\n')
  assert.doesNotMatch(
    code,
    /shell:\s*true/,
    'the preview runner spawns through a shell, which concatenates its arguments',
  )
  assert.doesNotMatch(
    code,
    /spawn\(\s*['"]npm/,
    'the preview runner spawns npm directly, which fails with EINVAL on Windows',
  )
  assert.match(
    code,
    /spawn\(process\.execPath/,
    'the preview runner must run the Tauri CLI through node, not through a shell or npm',
  )

  const port = read('tools', 'run-sync-preview-api.mjs').match(
    /SESAME_API_ADDR:[^']*'127\.0\.0\.1:(\d+)'/,
  )
  assert.ok(port, 'the preview API no longer names a default port this test can read')
  const desktopUrl = read('src-tauri', '.env.example').match(/SESAME_API_BASE_URL=(.*)/)
  assert.ok(desktopUrl, 'src-tauri/.env.example no longer records the development API URL')
  assert.ok(
    desktopUrl[1].includes(port[1]),
    `the preview API listens on ${port[1]} but the desktop is built against ${desktopUrl[1].trim()}`,
  )
})

test('both X25519 exchanges refuse a non-contributory result', () => {
  const keys = read('src-tauri', 'src', 'sync', 'keys.rs')
  assert.match(
    keys,
    /fn contributory_shared_secret\(/,
    'the shared helper that performs the check is gone',
  )
  assert.match(
    keys,
    /if !shared\.was_contributory\(\)/,
    'the exchange no longer rejects a non-contributory shared secret',
  )
  assert.doesNotMatch(
    keys,
    /diffie_hellman\([^)]*\)\s*\n?\s*\.to_bytes\(\)/,
    'an exchange converts the shared secret to bytes without checking it first',
  )
})

test('the Sync UI claims no safety property the code does not provide', () => {
  const conflict = read('src', 'lib', 'ui', 'SyncConflictModal.svelte')
  assert.doesNotMatch(
    conflict,
    /saves a local backup|nothing is lost/i,
    'the conflict screen promises a backup again. Implement it before claiming it.',
  )
})

test('the approval fingerprint is derived from the device keys', () => {
  const commands = read('src-tauri', 'src', 'commands', 'sync.rs')
  const derive = commands.match(/pub\(super\) fn approval_fingerprint\([\s\S]*?\n\}/)
  assert.ok(derive, 'approval_fingerprint is gone, so nothing derives a key-bound value')
  for (const field of ['vault_id', 'device_id', 'signing_public_key', 'encryption_public_key']) {
    assert.ok(
      derive[0].includes(`${field}.as_bytes()`),
      `the fingerprint no longer covers ${field}, so substituting it goes unnoticed`,
    )
  }

  const controller = read('src', 'lib', 'controllers', 'sync-preview-controller.ts')
  assert.doesNotMatch(
    controller,
    /function readableFingerprint|\.match\(\/\.\{1,4\}\/g\)/,
    'the webview derives its own fingerprint again, which authenticates nothing',
  )
  assert.match(
    controller,
    /invoke<\{[\s\S]{0,120}?\}>\(\s*'sync_prepare_approval',/,
    'the approval screen no longer shows a fingerprint frozen before confirmation',
  )
  assert.match(
    controller,
    /invoke<string>\('sync_this_device_fingerprint'\)/,
    'the joining device no longer shows its own locally derived fingerprint, so there is nothing to compare against',
  )
})

test('an upload is numbered from the local base, not the server head', () => {
  const transfer = read('src-tauri', 'src', 'commands', 'sync_transfer.rs')
  const upload = transfer.match(/pub async fn sync_upload_vault\([\s\S]*?\n\}/)
  assert.ok(upload, 'sync_upload_vault is no longer a single function this test can read')

  assert.match(
    upload[0],
    /decide_upload\(base_revision, current\.revision\)/,
    'the upload no longer asks sync::state whether it may proceed',
  )
  const revisionLine = upload[0]
    .split('\n')
    .find((line) => /^\s*revision:/.test(line))
  assert.ok(revisionLine, 'the envelope draft no longer sets a revision this test can read')
  assert.ok(
    !revisionLine.includes('current.revision'),
    `the upload numbers itself from the server head again, which is the overwrite:\n  ${revisionLine.trim()}`,
  )

  assert.match(
    upload[0],
    /sync::state::write_protected\(/,
    'the accepted revision is never recorded, or is recorded unauthenticated',
  )

  const verify = transfer.match(/async fn fetch_verified_snapshot\([\s\S]*?\n\}\n/)
  assert.ok(verify, 'fetch_verified_snapshot is gone, so nothing verifies a downloaded snapshot')
  assert.match(
    verify[0],
    /envelope\.vault_id != current\.vault_id/,
    'the download no longer compares the signed envelope against the outer response',
  )
  assert.match(
    verify[0],
    /sync::envelope::verify\(&envelope, &verifying\)/,
    'a downloaded envelope is no longer verified against the sending device key',
  )
  assert.match(
    verify[0],
    /sender\.state != "approved"/,
    'an envelope from a revoked device is no longer refused',
  )

  const download = transfer.match(/pub async fn sync_download_vault\([\s\S]*?\n\}/)
  assert.ok(download, 'sync_download_vault is no longer a single function this test can read')
  assert.match(
    download[0],
    /fetch_verified_snapshot\(&client\)/,
    'the download no longer goes through the one verified-snapshot path',
  )
  assert.match(
    download[0],
    /has_local_changes/,
    'an ordinary pull no longer refuses to run over unsynced local edits',
  )
})

test('nothing is persisted without verifying who signed it', () => {
  const envelopes = read('backend', 'internal', 'syncstore', 'envelopes.go')
  assert.match(
    envelopes,
    /VerifySignature\(/,
    'AppendEnvelope persists without verifying the envelope signature',
  )
  const devices = read('backend', 'internal', 'syncstore', 'devices.go')
  assert.match(
    devices,
    /VerifySignature\(/,
    'ApproveDevice persists a key package without verifying who signed it',
  )

  for (const [name, source] of [['envelopes.go', envelopes], ['devices.go', devices]]) {
    assert.match(
      source,
      /tx\.QueryRowContext\(ctx, `[\s\S]*?signing_public_key/,
      `${name} reads the signing key outside the transaction that persists`,
    )
  }

  const control = read('backend', 'internal', 'syncproto', 'control_plane.go')
  const payload = control.match(
    /func \(key EncryptedKeyPackage\) signingPayload\(\) \(\[\]byte, error\) \{[\s\S]*?\n\}/,
  )
  assert.ok(payload, 'the key package signing payload is no longer a single function')
  assert.doesNotMatch(
    payload[0],
    /CreatedAt/,
    'the key package payload carries a server-stamped timestamp again, which no signer can know',
  )
})

test('a conflict is resolved only after both recovery copies verify', () => {
  const transfer = read('src-tauri', 'src', 'commands', 'sync_transfer.rs')
  const resolve = transfer.match(/pub async fn sync_resolve_conflict\([\s\S]*?\n\}\n/)
  assert.ok(resolve, 'sync_resolve_conflict is gone, so nothing writes a recovery copy')
  const body = resolve[0]

  const backupAt = body.indexOf('conflict_backup::write_verified(')
  assert.ok(backupAt > 0, 'the resolution no longer writes a verified recovery copy')

  for (const [mutation, description] of [
    ['commit_payload_change(vault, payload)?', 'the local vault is replaced transactionally'],
    ['client.upload(', "this device's vault is uploaded over the other one"],
  ]) {
    const at = body.indexOf(mutation)
    assert.ok(at > 0, `${description} no longer happens in sync_resolve_conflict`)
    assert.ok(
      at > backupAt,
      `${description} before the recovery copies are written, so a failure to write one still discards a vault`,
    )
  }

  assert.match(
    body,
    /write_verified\([\s\S]*?\)\?;/,
    'a failed recovery copy no longer aborts the resolution',
  )

  for (const side of ['Side::ThisDevice', 'Side::OtherDevice']) {
    assert.ok(body.includes(side), `only one side of the conflict is backed up: ${side} is missing`)
  }

  const backup = read('src-tauri', 'src', 'sync', 'conflict_backup.rs')
  assert.match(
    backup,
    /encrypt_bytes\(&vault\.key,/,
    'the recovery copy is no longer encrypted with the vault key',
  )
  assert.doesNotMatch(
    backup,
    /atomic_replace\(&path, payload\)|write\(&path, payload\)/,
    'the recovery copy writes the payload in the clear',
  )
})

test('the conflict screen shows both sides as they are', () => {
  const controller = read('src', 'lib', 'controllers', 'sync-preview-controller.ts')
  assert.match(
    controller,
    /invoke<[\s\S]{0,160}?>\('sync_conflict_details'\)/,
    'the conflict screen no longer reads both sides, so the choice is made against a placeholder',
  )
  assert.match(
    controller,
    /invoke<[\s\S]{0,120}?>\('sync_resolve_conflict', \{\s*keep: choice,?\s*\}\)/,
    'a conflict is resolved by calling upload or download directly again, which writes no recovery copy',
  )
})

test('per-vault quotas are enforced inside the transaction', () => {
  const devices = read('backend', 'internal', 'syncstore', 'devices.go')
  const enroll = devices.match(/func \(s \*Store\) EnrollDevice\([\s\S]*?\n\}\n/)
  assert.ok(enroll, 'EnrollDevice is gone')
  assert.match(
    enroll[0],
    /syncproto\.MaxDevicesPerVault/,
    'enrollment no longer checks the device limit',
  )
  assert.match(
    enroll[0],
    /tx\.QueryRowContext\(ctx, `[\s\S]*?COUNT\(\*\) FROM sesame_sync_devices/,
    'the device count is read outside the transaction, so two concurrent enrollments can both pass it',
  )

  const envelopes = read('backend', 'internal', 'syncstore', 'envelopes.go')
  assert.match(
    envelopes,
    /DELETE FROM sesame_sync_envelopes[\s\S]*?syncproto\.MaxSnapshotsPerVault/,
    'snapshots are no longer pruned to the retention limit, so a vault grows without bound',
  )
})

test('a serialisation failure is retried, not returned as an outage', () => {
  const store = read('backend', 'internal', 'syncstore', 'store.go')
  assert.match(
    store,
    /pgErr\.Code == "40001"/,
    'nothing recognises a serialisation failure any more',
  )
  assert.match(
    store,
    /func \(s \*Store\) inTx\([\s\S]*?isSerializationFailure\(err\)/,
    'inTx no longer retries the transaction, so a lost serialisation looks like an outage',
  )
  assert.doesNotMatch(
    store,
    /isSerializationFailure\(ErrConflict\)|errors\.Is\(err, ErrConflict\)[\s\S]{0,40}retry/,
    'a conflict is being retried, which discards the other device changes',
  )
})

test('Sync entitlement and rate limiting are decided in one place', () => {
  const routes = read('backend', 'internal', 'httpapi', 'sync_routes.go')
  const gate = routes.match(/func \(a \*api\) requireSyncCaller\([\s\S]*?\n\}\n/)
  assert.ok(gate, 'requireSyncCaller is gone, so entitlement is decided per handler again')
  for (const keyed of ['":account:"', '":device:"']) {
    assert.ok(
      gate[0].includes(keyed),
      `the gate no longer limits by ${keyed}, so one account across many addresses is unbounded`,
    )
  }
  const outside = routes.replace(gate[0], '')
  assert.doesNotMatch(
    outside,
    /a\.allowRequest\(/,
    'a sync handler limits by IP on its own again, so the account and device limits do not apply to it',
  )
  assert.doesNotMatch(
    outside,
    /a\.desktopConnectionForRequest\(/,
    'a sync handler resolves the desktop token outside the gate, which is how handlers drifted apart',
  )
})

test('the first device can be approved and a second can fetch its key', () => {
  const devices = read('backend', 'internal', 'syncstore', 'devices.go')
  assert.doesNotMatch(
    devices,
    /func \(s \*Store\) BootstrapFirstDevice\(/,
    'first-device approval is a separate transaction again, which two concurrent enrollments can both lose',
  )
  assert.match(
    devices,
    /SELECT id FROM sesame_sync_vaults WHERE id = \$1 FOR UPDATE/,
    'enrollment no longer serialises on the vault row, so concurrent first enrollments race',
  )
  assert.match(
    devices,
    /state = "approved"/,
    'enrollment no longer approves the first device in a vault, so Sync cannot be turned on at all',
  )
  const client = read('src-tauri', 'src', 'adapters', 'network', 'sync.rs')
  assert.match(
    client,
    /\/v1\/sync\/key-package\?deviceId=/,
    'the client requests a key package without a deviceId, which the route answers 400',
  )
})

test('removing a device rotates the vault key', () => {
  const rekey = read('backend', 'internal', 'syncstore', 'rekey.go')
  assert.match(
    rekey,
    /func \(s \*Store\) RevokeAndRekey\(/,
    'RevokeAndRekey is gone, so removing a device no longer rotates the vault key',
  )
  const body = rekey.match(/func \(s \*Store\) RevokeAndRekey\([\s\S]*?\n\}\n/)[0]
  for (const [required, why] of [
    ['s.inTx(', 'the rekey is no longer one transaction'],
    ['appendEnvelopeTx', 'the re-encrypted head is not committed with the revocation'],
    ['sesame_sync_key_packages', 'survivors are not rewrapped to the new key'],
    ['FOR UPDATE', 'two concurrent rekeys can both claim the new epoch'],
  ]) {
    assert.ok(body.includes(required), why)
  }

  const transfer = read('src-tauri', 'src', 'commands', 'sync_transfer.rs')
  const remove = transfer.match(/pub async fn sync_remove_device\([\s\S]*?\n\}\n/)
  assert.ok(remove, 'sync_remove_device is gone')
  assert.match(
    remove[0],
    /fill_random\(&mut new_key\)/,
    'the removal no longer generates a new vault key on the device',
  )
  assert.match(
    remove[0],
    /seal_vault_key\(&new_key,/,
    'the new key is not wrapped to the surviving devices',
  )
})

test('removing a device is signed by the device asking', () => {
  const routes = read('backend', 'internal', 'httpapi', 'sync_routes.go')
  assert.match(
    routes,
    /syncproto\.VerifyRevocationIntent\(/,
    'removal no longer requires the calling device to have signed it',
  )
  const transfer = read('src-tauri', 'src', 'commands', 'sync_transfer.rs')
  assert.match(
    transfer,
    /sign_revocation_intent\(/,
    'the desktop no longer signs its removal intent',
  )
})

test('revisions form a chain and the service signs what it accepted', () => {
  const envelope = read('backend', 'internal', 'syncproto', 'envelope.go')
  const payload = envelope.match(/func \(envelope Envelope\) signingPayload\([\s\S]*?\n\}/)[0]
  assert.ok(
    payload.includes('PreviousDigest'),
    'the predecessor digest is outside the signed payload, so the service can rewrite the chain',
  )
  const store = read('backend', 'internal', 'syncstore', 'envelopes.go')
  assert.match(
    store,
    /envelope\.PreviousDigest != expectedPrevious/,
    'the store no longer checks that a revision chains to what it actually holds',
  )
  assert.match(
    store,
    /syncproto\.SignReceipt\(/,
    'the service no longer signs what it accepted',
  )

  const transfer = read('src-tauri', 'src', 'commands', 'sync_transfer.rs')
  assert.match(
    transfer,
    /accepted\.digest != sent_digest/,
    'the desktop accepts whatever digest the service reports, so the service can choose where the next revision chains from',
  )
})

test('a coordinator drives Sync, and never resolves a conflict itself', () => {
  const coordinator = read('src-tauri', 'src', 'sync', 'coordinator.rs')
  for (const [required, why] of [
    ['pub fn begin(', 'nothing claims the right to run a single transfer'],
    ['follow_up', 'concurrent requests are no longer coalesced into one follow-up'],
    ['MAX_ATTEMPTS', 'retries are unbounded'],
    ['pub fn backoff(', 'retries no longer back off'],
    ['Revoked', 'a revoked device is no longer a terminal halt the loop stops on'],
    ['NotEntitled', 'an unentitled account is no longer a terminal halt'],
    ['Incompatible', 'an incompatible client is no longer a terminal halt'],
  ]) {
    assert.ok(coordinator.includes(required), why)
  }
  assert.doesNotMatch(
    coordinator,
    /sync_resolve_conflict|fn resolve_conflict|keep_this|choose_winner/,
    'the coordinator resolves conflicts by itself, which is the one decision that must stay with a person',
  )
  assert.match(
    coordinator,
    /Conflict/,
    'a conflict no longer stops the coordinator, so it would keep retrying a decision only a person can make',
  )
})

test('one canonical AEAD context, shared by both languages', () => {
  const rust = read('src-tauri', 'src', 'sync', 'envelope.rs')
  assert.match(
    rust,
    /pub fn snapshot_aad\(/,
    'the canonical AEAD context is gone from the desktop',
  )
  assert.doesNotMatch(
    rust,
    /sesame-sync-snapshot-v1/,
    'the one-field AEAD context is back, so revisions and epochs are unbound',
  )
  for (const file of ['sync_transfer.rs', 'sync_adopt.rs']) {
    const source = read('src-tauri', 'src', 'commands', file)
    assert.doesNotMatch(
      source,
      /fn snapshot_aad\(/,
      `${file} defines its own AEAD context, which is how the two drifted apart`,
    )
  }
  const fixture = JSON.parse(
    read('backend', 'internal', 'syncproto', 'testdata', 'snapshot-aad.json'),
  )
  assert.ok(fixture.contextBase64, 'the AEAD context fixture carries no expected value')
  assert.match(
    read('backend', 'internal', 'syncproto', 'chain.go'),
    /func SnapshotAAD\(/,
    'the Go side no longer defines the canonical context, so nothing can check the desktop against it',
  )
})

test('the local Sync state is authenticated', () => {
  const state = read('src-tauri', 'src', 'sync', 'state.rs')
  assert.match(state, /pub fn write_protected\(/, 'the state is written unauthenticated again')
  assert.match(state, /protect_for_windows_profile\(&state_tag\(&body\)\)/, 'the tag is no longer DPAPI-protected')

  for (const file of ['sync_transfer.rs', 'sync.rs', 'sync_adopt.rs']) {
    const source = read('src-tauri', 'src', 'commands', file)
    for (const forbidden of ['sync::state::write(', 'sync::state::read(', 'sync::state::forget(']) {
      assert.ok(
        !source.includes(forbidden),
        `${file} uses ${forbidden}, which skips the tag that makes the state trustworthy`,
      )
    }
  }
})

test('stored ciphertext has a byte ceiling, not just a count', () => {
  assert.match(
    read('backend', 'internal', 'syncproto', 'control_plane.go'),
    /MaxStoredBytesPerVault/,
    'the per-vault byte ceiling is gone',
  )
  assert.match(
    read('backend', 'internal', 'syncstore', 'envelopes.go'),
    /SUM\(LENGTH\(ciphertext\)\)[\s\S]{0,400}?s\.byteBudget\(\)/,
    'the byte ceiling is no longer enforced before an envelope is stored',
  )
})

test('the lifecycle is reachable from the interface', () => {
  const controller = read('src', 'lib', 'controllers', 'sync-preview-controller.ts')
  for (const [command, why] of [
    ['sync_adopt_vault', 'an approved joining device still has no way to join'],
    ['sync_list_conflict_backups', 'recovery copies cannot be found'],
    ['sync_restore_conflict_backup', 'recovery copies cannot be restored, so the conflict screen promises something the product cannot do'],
    ['sync_remove_device', 'removing a device does not rotate the vault key'],
    ['sync_deny_device', 'denying a pending device still rotates the vault'],
    ['sync_now', 'Sync is still two buttons and a person choosing a direction'],
    ['sync_coordinator_status', 'the panel cannot show what Sync is doing'],
  ]) {
    assert.ok(controller.includes(`'${command}'`), why)
  }
  assert.match(
    controller,
    /invoke<\{ recoveryKit: string \}>\('sync_remove_device', \{\s*deviceId,\s*masterPassword,/,
    'removing a device no longer proves ownership of the vault it re-keys',
  )
})
