import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

// Split from the former monorepo cross-repo suite. The Go-side assertions live
// in sesame-server; these read only files this repository owns.

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const read = (...parts) => readFileSync(join(root, ...parts), 'utf8')

test('the shared Sync fixtures name a server commit and match their recorded hashes', () => {
  const directory = ['src-tauri', 'contracts', 'sync', 'v3']
  const source = JSON.parse(read(...directory, 'source.json'))
  assert.equal(source.sourceRepository, 'usesesame/sesame-server')
  assert.match(source.sourceCommit, /^[0-9a-f]{40}$/)
  assert.deepEqual(Object.keys(source.files).sort(), ['v3-fixture.json', 'wire-fixture.json'])
  for (const [file, digest] of Object.entries(source.files)) {
    assert.equal(createHash('sha256').update(read(...directory, file)).digest('hex'), digest)
    assert.equal(source.sourcePaths[file], `internal/${file === 'v3-fixture.json' ? 'syncproto' : 'syncv3http'}/testdata/${file}`)
  }
})

function sourceFiles(dir, pattern) {
  return readdirSync(join(root, dir)).flatMap((name) => {
    const relative = join(dir, name)
    if (statSync(join(root, relative)).isDirectory()) return sourceFiles(relative, pattern)
    return pattern.test(name) ? [relative] : []
  })
}

test('Sync is off by default: a device that never turned it on contacts nothing', () => {
  const commands = read('src-tauri', 'src', 'commands', 'sync.rs')
  const status = commands.match(/pub async fn sync_status\([\s\S]*?\n\}\n/)
  assert.ok(status, 'sync_status is no longer a single function this test can read')
  const offline = status[0].indexOf('never_turned_on(')
  const connect = status[0].indexOf('SyncClient::connect(')
  assert.ok(offline !== -1 && connect !== -1 && offline < connect, 'sync_status must decide a never enrolled device is off before it connects')
  assert.match(commands, /fn never_turned_on\(has_state: bool, has_identity: bool\) -> bool \{\s*!has_state && !has_identity\s*\}/)

  const transfer = read('src-tauri', 'src', 'commands', 'sync_transfer.rs')
  const coordinatorStatus = transfer.match(/pub async fn sync_coordinator_status\([\s\S]*?\n\}\n/)
  assert.ok(coordinatorStatus && !coordinatorStatus[0].includes('SyncClient'), 'reading the coordinator status must not touch the network')

  const controller = read('src', 'lib', 'controllers', 'sync-controller.ts')
  const auto = controller.match(/async autoSync\(\) \{[\s\S]*?\n {4}\},/)
  assert.ok(auto, 'autoSync is no longer a single function this test can read')
  assert.match(auto[0], /current\.state !== 'approved'/, 'automatic sync runs on a device that is not an approved member')
})

test('Sync commands are registered once and permitted by the main window only', () => {
  const lib = read('src-tauri', 'src', 'lib.rs')
  const shared = lib.match(/macro_rules! sesame_invoke_handler \{[\s\S]*?\n\}/)
  assert.ok(shared, 'the shared invoke handler list is no longer a single macro this test can read')
  const registered = [...shared[0].matchAll(/commands::sync[a-z_]*::(sync_[a-z_]+)/g)].map((match) => match[1])
  assert.equal(registered.length, 19, 'the registered Sync command list changed')
  assert.equal(new Set(registered).size, registered.length, 'a Sync command is registered twice')
  assert.doesNotMatch(lib.replace(shared[0], ''), /commands::sync/, 'a Sync command is registered outside the shared list')
  const permissions = read('src-tauri', 'permissions', 'desktop.toml')
  const block = permissions.split('[[permission]]').find((item) => item.includes('identifier = "sync"'))
  assert.ok(block, 'the sync permission is gone')
  assert.deepEqual([...block.matchAll(/"(sync_[a-z_]+)"/g)].map((match) => match[1]).sort(), [...registered].sort())
  const main = JSON.parse(read('src-tauri', 'capabilities', 'default.json'))
  assert.ok(main.permissions.includes('sync'), 'the main window no longer holds the sync permission')
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

test('signing and key agreement use separate keys', () => {
  const identity = read('src-tauri', 'src', 'sync', 'identity.rs')
  assert.match(identity, /signing:\s*SigningKey/)
  assert.match(identity, /encryption:\s*EncryptionKeypair/)
})

test('the Settings screen shows the Sync panel and the storage row, and says no review has happened', () => {
  const settings = read('src', 'lib', 'ui', 'SettingsView.svelte')
  assert.match(settings, /<SyncPanel\s*\/>/, 'Settings no longer renders the Sync panel')
  assert.match(settings, /<SyncVaultStorageRow\s*\/>/, 'Settings no longer renders the storage row')
  assert.doesNotMatch(settings, /SYNC_PREVIEW_AVAILABLE|syncStatusUrl/, 'Settings still reads the old preview gate')
  const panel = read('src', 'lib', 'ui', 'SyncPanel.svelte')
  assert.match(panel, /Not independently reviewed/)
  assert.match(panel, /has not had an independent security review/)
  const meta = read('src', 'lib', 'app-meta.ts')
  assert.doesNotMatch(meta, /SYNC_PREVIEW_AVAILABLE|VITE_SESAME_SYNC_PREVIEW/, 'the preview flag is still defined')
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

test('the Sync client no longer hides behind a build feature, and nothing of the old gate is left', () => {
  const manifest = read('src-tauri', 'Cargo.toml')
  assert.doesNotMatch(manifest, /sync-preview/, 'the sync-preview feature is still declared')
  for (const file of sourceFiles(join('src-tauri', 'src'), /\.rs$/)) {
    assert.doesNotMatch(read(file), /feature = "sync-preview"/, `${file} still gates code behind sync-preview`)
  }
  assert.ok(!existsSync(join(root, 'src-tauri', 'capabilities', 'sync-preview.json')), 'the preview capability file is still there')
  assert.ok(!existsSync(join(root, 'src-tauri', 'tauri.sync-preview.conf.json')), 'the preview configuration is still there')
  assert.deepEqual(readdirSync(join(root, 'tools')).filter((name) => name.includes('sync-preview')), [], 'a preview tool is still there')
  const scripts = JSON.parse(read('package.json')).scripts
  for (const name of Object.keys(scripts)) {
    assert.ok(!/sync:preview/.test(name), `the ${name} script is left over from the old gate`)
  }
  assert.equal(scripts['desktop:test:rust:sync'], 'npm run desktop:test:rust')
  const vite = read('vite.config.ts')
  assert.doesNotMatch(vite, /SYNC_PREVIEW/)
  const module = read('src-tauri', 'src', 'sync', 'mod.rs')
  assert.match(module, /pub\(crate\) use crate::adapters::network::sync as client;/)
})

test('the first run notice says Sync is off, asks for nothing, and is shown once', () => {
  const notice = read('src', 'lib', 'ui', 'SyncNotice.svelte')
  assert.match(notice, /Sesame Sync is off/)
  assert.match(notice, /has not had an independent security review/)
  assert.doesNotMatch(notice, /\b(audited|secure by|production-ready)\b/i, 'the notice claims a safety property')
  assert.doesNotMatch(notice, /invoke\(|createSyncController/, 'the notice must not talk to the Sync client')
  const app = read('src', 'App.svelte')
  assert.match(app, /<SyncNotice\b/)
  const preferences = read('src', 'lib', 'preferences.ts')
  assert.match(preferences, /syncNotice: 'sesame-sync-notice-v1'/)
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

test('the conflict screen shows both sides as they are', () => {
  const controller = read('src', 'lib', 'controllers', 'sync-controller.ts')
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

test('a coordinator drives Sync, and never resolves a conflict itself', () => {
  const coordinator = read('src-tauri', 'src', 'sync', 'coordinator.rs')
  for (const [required, why] of [
    ['pub fn begin(', 'nothing claims the right to run a single transfer'],
    ['follow_up', 'concurrent requests are no longer coalesced into one follow-up'],
    ['MAX_ATTEMPTS', 'retries are unbounded'],
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

test('the local Sync state is authenticated', () => {
  const state = read('src-tauri', 'src', 'sync', 'state.rs')
  assert.match(state, /pub fn write_protected\(/, 'the state is written unauthenticated again')
  assert.match(state, /protect\(&state_tag\(&body\)\)/, 'the tag is no longer device-protected')
  assert.match(
    state,
    /crate::vault::platform::protect_for_device\(bytes\)/,
    'the tag helper no longer routes through the platform device protection',
  )

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


test('the Sync screens are rendered by the panel alone, and one shared controller serves the app', () => {
  const settings = read('src', 'lib', 'ui', 'SettingsView.svelte')
  const app = read('src', 'App.svelte')
  const host = read('src', 'lib', 'ui', 'SyncPanel.svelte')
  const callers = [
    ['App.svelte', app],
    ['SettingsView.svelte', settings],
  ]
  for (const screen of ['SyncEnableModal', 'SyncPairingModal', 'SyncJoinModal', 'SyncConflictModal']) {
    read('src', 'lib', 'ui', `${screen}.svelte`)
    assert.match(host, new RegExp(`<${screen}\\b`), `${screen} is not rendered by SyncPanel`)
    for (const [name, source] of callers) {
      assert.ok(!source.includes(`<${screen}`), `${screen} renders directly in ${name}`)
    }
  }
  const builders = sourceFiles('src', /\.(ts|svelte)$/).filter((file) => !file.endsWith('.test.ts') && /createSyncController\(/.test(read(file)))
  assert.deepEqual(builders.map((file) => file.replaceAll('\\', '/')).sort(), ['src/lib/controllers/sync-controller.ts', 'src/lib/sync.ts'], 'more than one place builds a Sync controller, so the screens would disagree')
  for (const file of ['SyncPanel.svelte', 'SyncVaultStorageRow.svelte']) {
    assert.match(read('src', 'lib', 'ui', file), /from '\.\.\/sync'/, `${file} does not use the shared controller`)
  }
})

test('the app syncs without being asked and shows the result in the window bar', () => {
  const app = read('src', 'App.svelte')
  assert.match(app, /syncController\.startBackground\(\)/, 'nothing starts the background sync')
  assert.match(app, /syncController\.vaultChanged\(\)/, 'a change to the vault no longer triggers a sync')
  assert.match(app, /syncStatusLabel=\{syncChrome\?\.label\}/, 'the window bar no longer shows the sync status')
  assert.match(app, /vaultLabel=\{syncChrome \? 'Synced vault' : 'Local vault'\}/, 'the sidebar no longer follows the synced state')
  const controller = read('src', 'lib', 'controllers', 'sync-controller.ts')
  assert.match(controller, /sesame-sync-cache-v1/, 'the synced state is no longer cached for the first paint')
  const storage = read('src', 'lib', 'ui', 'SyncVaultStorageRow.svelte')
  assert.doesNotMatch(storage, /refresh\(\)/, 'the Data tab waits for the network before it knows the vault is synced')
})

test('the Go and Rust sides share one v3 fixture and the Rust tests read it', () => {
  const fixture = JSON.parse(read('src-tauri', 'contracts', 'sync', 'v3', 'v3-fixture.json'))
  for (const part of ['chain', 'removalChain', 'headers', 'request', 'receipt', 'keyPackage', 'brokenChains', 'brokenHeaders']) {
    assert.ok(fixture[part], `the fixture lost its ${part} vectors`)
  }
  const tests = read('src-tauri', 'src', 'sync', 'v3_contract_tests.rs')
  assert.match(tests, /contracts[\s\S]*v3[\s\S]*v3-fixture\.json/, 'the Rust tests no longer read the shared fixture')
  assert.ok(!existsSync(join(root, 'src-tauri', 'contracts', 'sync', 'v2')), 'the v2 fixtures are retired with the v2 wire format')
})

test('a device list and every header are verified from the stored chain, never from the service listing', () => {
  const refresh = read('src-tauri', 'src', 'commands', 'sync.rs')
  const body = refresh.match(/async fn refresh\([\s\S]*?\n}\n/)
  assert.ok(body, 'refresh is no longer a single function this test can read')
  assert.match(body[0], /verify_server_view\(/, 'refresh must verify the service view through the engine')
  assert.match(body[0], /client\.instance_key\(\)/, 'receipts must be checked against the pinned instance key')
  for (const file of ['sync_transfer.rs', 'sync_pairing.rs', 'sync.rs']) {
    const source = read('src-tauri', 'src', 'commands', file)
    assert.doesNotMatch(source, /\.devices\(\)[\s\S]{0,200}state\s*==\s*"approved"[\s\S]{0,80}signing/, `${file} trusts the service listing for an approval`)
  }
  const engine = read('src-tauri', 'src', 'sync', 'engine.rs')
  for (const rule of ['verify_header_chain', 'verify_header(', 'check_receipt', 'floor_for']) {
    assert.ok(engine.includes(rule), `the engine no longer calls ${rule}`)
  }
})

test('an upload is numbered from the local head and its header is planned before it is encrypted', () => {
  const transfer = read('src-tauri', 'src', 'commands', 'sync_transfer.rs')
  assert.match(transfer, /decide_upload\(\s*local\.head_revision\(\),\s*refreshed\.server\.current_revision/, 'the upload decision must compare the local head with the verified service revision')
  assert.match(transfer, /plan_header\([^)]*previous\.as_ref\(\)/, 'the header must name the previous header the device holds')
  const plan = transfer.indexOf('plan.aad()')
  const encrypt = transfer.indexOf('encrypt_bytes(key, &padded, &aad)')
  assert.ok(plan > 0 && encrypt > plan, 'the context that binds a snapshot must be fixed before the vault is encrypted')
  assert.match(transfer, /verify_accepted\(/, 'an accepted upload must be checked against the header that was sent')
})

test('one canonical AEAD context, shared by encryption and decryption', () => {
  const transfer = read('src-tauri', 'src', 'commands', 'sync_transfer.rs')
  assert.match(transfer, /header\.aad\(\)/, 'decryption must use the header context')
  assert.match(transfer, /plan\.aad\(\)/, 'encryption must use the planned header context')
  const pairing = read('src-tauri', 'src', 'commands', 'sync_pairing.rs')
  assert.match(pairing, /head\.aad\(\)/, 'a joining device must decrypt with the header context')
  const header = read('src-tauri', 'src', 'sync', 'header.rs')
  assert.match(header, /pub fn aad\(&self\)/)
})

test('a new device is added only after a code the person typed, and the approver comes from the exchange', () => {
  const pairing = read('src-tauri', 'src', 'commands', 'sync_pairing.rs')
  assert.match(pairing, /pake::answer\(/, 'the approving device must run the exchange')
  assert.match(pairing, /Offer::begin\(/, 'the joining device must run the exchange')
  assert.match(pairing, /verify_confirmation\(/, 'the approver must check the new device proved the code')
  assert.match(pairing, /verify_join\(/, 'the joining device must check the device list and key package through the engine')
  const engine = read('src-tauri', 'src', 'sync', 'engine.rs')
  assert.match(engine, /check\.approver\.signing_key/, 'the joining device must take the approver key from the exchange')
  assert.match(engine, /adding\.signer_device_id != approver\.device_id/, 'the entry that added this device must be signed by the device that gave the code')
  assert.doesNotMatch(pairing, /record_verified|fingerprint/, 'the first-sight trust and fingerprint comparison are gone')
  const pake = read('src-tauri', 'src', 'sync', 'pake', 'mod.rs')
  assert.match(pake, /CODE_ALPHABET/, 'codes come from a fixed alphabet')
  assert.match(pake, /is_identity\(\)/, 'an identity point must be refused')
})

test('every request that changes state carries a device signature', () => {
  const client = read('src-tauri', 'src', 'adapters', 'network', 'sync.rs')
  const methods = [...client.matchAll(/pub async fn (\w+)\([\s\S]*?\n {4}}\n/g)].map((match) => [match[1], match[0]])
  const changing = ['create_vault', 'begin_pairing', 'answer_pairing', 'confirm_pairing', 'cancel_pairing', 'approve', 'remove', 'activate', 'upload', 'reset']
  for (const name of changing) {
    const found = methods.find(([method]) => method === name)
    assert.ok(found, `the client has no ${name}`)
    assert.match(found[1], /self\s*\.write(?:_raw)?\(/, `${name} must send a signed request`)
    assert.match(found[1], /identity/, `${name} must take the device identity that signs`)
  }
  const dispatch = client.match(/async fn write_raw\([\s\S]*?\n {4}}\n/)
  assert.ok(dispatch, 'write_raw is no longer one function this test can read')
  assert.match(dispatch[0], /sign_request\(/)
  assert.match(dispatch[0], /token: &self\.token/, 'the signature must bind the bearer token')
  for (const name of ['state', 'device_list', 'devices', 'pairing_status', 'key_package', 'headers', 'snapshot']) {
    const found = methods.find(([method]) => method === name)
    assert.ok(found, `the client has no ${name}`)
    assert.doesNotMatch(found[1], /write_raw|self\s*\.write\(/, `${name} only reads and must not be a signed route`)
  }
})

test('the company-signed Sync floor gates the one place every Sync command connects, and no server input can set it', () => {
  const client = read('src-tauri', 'src', 'adapters', 'network', 'sync.rs')
  const connect = client.match(/pub async fn connect\(app: &AppHandle\)[\s\S]*?\n {4}\}\n/)
  assert.ok(connect, 'SyncClient::connect is no longer a single function this test can read')
  assert.ok(
    connect[0].indexOf('require_sync_allowed(') !== -1 &&
      connect[0].indexOf('require_sync_allowed(') < connect[0].indexOf('read_service_connection('),
    'connect must check the floor before it reads the connection or any token',
  )
  for (const file of sourceFiles(join('src-tauri', 'src', 'commands'), /\.rs$/)) {
    const source = read(file)
    const body = source.slice(0, source.indexOf('#[cfg(test)]') === -1 ? undefined : source.indexOf('#[cfg(test)]'))
    assert.doesNotMatch(body, /for_target\(|reqwest::Client/, `${file} builds a Sync connection without going through connect`)
  }
  const writers = sourceFiles(join('src-tauri', 'src'), /\.rs$/).filter((file) => {
    const source = read(file)
    const body = source.slice(0, source.indexOf('#[cfg(test)]') === -1 ? undefined : source.indexOf('#[cfg(test)]'))
    return /raise_floor\(|record_manifest_floor\(/.test(body)
  })
  assert.deepEqual(
    writers.map((file) => file.replaceAll('\\', '/')).sort(),
    ['src-tauri/src/adapters/network/sync_floor.rs', 'src-tauri/src/sync/floor.rs'],
    'only the company manifest reader may write the Sync floor',
  )
  const floorReader = read('src-tauri', 'src', 'adapters', 'network', 'sync_floor.rs')
  assert.match(floorReader, /configured_endpoint\(\)/)
  assert.match(floorReader, /candidate_trust\(\)/)
  assert.doesNotMatch(floorReader, /capabilit|service_target|read_service/, 'the floor must not read anything a Sync server supplies')
})

test('the service must say it offers Sync in a signed document before this device talks to it', () => {
  const client = read('src-tauri', 'src', 'adapters', 'network', 'sync.rs')
  assert.match(client, /fetch_signed_document\(/)
  assert.match(client, /require_sync_enabled\(/)
  const capabilities = read('src-tauri', 'src', 'adapters', 'network', 'capabilities.rs')
  assert.match(capabilities, /features\s*\.get\("sync"\)/)
})

test('removing a device rotates the vault key and leaving does the same', () => {
  const transfer = read('src-tauri', 'src', 'commands', 'sync_transfer.rs')
  const rekey = transfer.match(/async fn rekey_without\([\s\S]*?\n}\n/)
  assert.ok(rekey, 'rekey_without is no longer one function this test can read')
  assert.match(rekey[0], /fill_secret\(&mut new_key\)/)
  assert.match(rekey[0], /remove_entry\(/)
  assert.match(rekey[0], /survivor_packages\(/)
  assert.match(rekey[0], /verify_master_password\(/)
  assert.match(transfer, /seal_for_recipient\(new_key, &recipient, vault_id, epoch\)/)
  assert.match(transfer, /rekey_without\(app, state, &identity\.device_id, master_password, false\)/, 'leaving must rekey for the devices that stay')
})

test('the lifecycle is reachable from the interface', () => {
  const controller = read('src', 'lib', 'controllers', 'sync-controller.ts')
  for (const command of [
    'sync_create_vault',
    'sync_pairing_code',
    'sync_approve_with_code',
    'sync_cancel_pairing',
    'sync_join_with_code',
    'sync_take_new_key',
    'sync_list_conflict_backups',
    'sync_restore_conflict_backup',
    'sync_remove_device',
    'sync_disable',
    'sync_now',
    'sync_coordinator_status',
    'sync_status',
  ]) {
    assert.ok(controller.includes(`'${command}'`), `the interface cannot reach ${command}`)
  }
  assert.match(controller, /'sync_remove_device',\s*\{[\s\S]*?masterPassword/, 'removing a device must ask for the master password')
})

test('a fork or a disagreement stops Sync and is shown, never applied', () => {
  const sync = read('src-tauri', 'src', 'commands', 'sync.rs')
  assert.match(sync, /sync_fork:/)
  const coordinator = read('src-tauri', 'src', 'commands', 'sync_transfer_coordinator.rs')
  assert.match(coordinator, /starts_with\("sync_fork:"\)[\s\S]*Halt::Fork/)
  const host = read('src', 'lib', 'ui', 'SyncPanel.svelte')
  assert.match(host, /Your devices disagree/)
})
