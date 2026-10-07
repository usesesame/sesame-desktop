import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const read = (...parts) => readFileSync(join(root, ...parts), 'utf8')
const IGNORED_DIRECTORIES = new Set([
  'node_modules', '.git', 'dist', 'target', 'test-results', 'release-artifacts', 'release-evidence',
])

function filesMatching(pattern, from = root) {
  const found = []
  const walk = (dir) => {
    for (const entry of readdirSync(dir)) {
      if (IGNORED_DIRECTORIES.has(entry)) continue
      const path = join(dir, entry)
      if (statSync(path).isDirectory()) walk(path)
      else if (pattern.test(entry)) found.push(path)
    }
  }
  walk(from)
  return found
}

function withoutComments(text) {
  return text
    .replace(/<#[\s\S]*?#>/g, '')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|\s)\/\/.*$/gm, '$1')
    .replace(/(^|\s)#.*$/gm, '$1')
}

test('nothing in tools/ is left behind unreferenced', () => {
  const workflowDirectory = join(root, '.github', 'workflows')
  const referrers = [
    { name: 'package.json', text: withoutComments(read('package.json')) },
    ...['vite.config.ts', 'vitest.config.ts'].map((name) => ({ name, text: withoutComments(read(name)) })),
    ...readdirSync(workflowDirectory).map((name) => ({ name, text: withoutComments(read('.github', 'workflows', name)) })),
    ...filesMatching(/\.(mjs|js|ps1)$/, join(root, 'tools')).map((path) => ({
      name: relative(join(root, 'tools'), path),
      text: withoutComments(readFileSync(path, 'utf8')),
    })),
  ]

  const orphans = []
  for (const path of readdirSync(join(root, 'tools'))) {
    if (path.endsWith('-contracts.test.mjs')) continue
    if (statSync(join(root, 'tools', path)).isDirectory()) continue
    const reachable = referrers.some((referrer) => referrer.name !== path && referrer.text.includes(path))
    if (!reachable) orphans.push(path)
  }
  assert.deepEqual(orphans, [], `these files in tools/ are referenced by nothing:\n  ${orphans.join('\n  ')}`)
})

test('shipping webviews do not expose embedded Edge inspection surfaces', () => {
  const shell = read('src-tauri', 'src', 'adapters', 'platform', 'desktop_shell.rs')
  const rust = read('src-tauri', 'src', 'lib.rs')
  const capability = read('src-tauri', 'capabilities', 'default.json')
  const main = read('src', 'main.ts')
  const quickAccess = read('src', 'quick-access-main.ts')

  assert.match(shell, /cfg\(all\(windows, not\(debug_assertions\)\)\)/)
  assert.match(shell, /SetAreDefaultContextMenusEnabled\(false\)/)
  assert.match(shell, /SetAreDevToolsEnabled\(false\)/)
  assert.match(rust, /cfg\(all\(windows, not\(debug_assertions\)\)\)/)
  for (const variable of [
    'WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS',
    'WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER',
    'WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER',
  ]) {
    assert.match(rust, new RegExp(`"${variable}"`))
  }
  const run = rust.indexOf('pub fn run()')
  const preparation = rust.indexOf('prepare_release_webview_environment();', run)
  const builder = rust.indexOf('tauri::Builder::default()', run)
  assert.ok(run >= 0 && preparation > run && builder > preparation)
  assert.match(capability, /core:webview:deny-internal-toggle-devtools/)
  for (const entrypoint of [main, quickAccess]) {
    assert.match(entrypoint, /import\.meta\.env\.PROD/)
    assert.match(entrypoint, /disableDefaultContextMenu\(\)/)
  }
})

test('each desktop webview gets only the Tauri permissions its imports need', () => {
  const main = JSON.parse(read('src-tauri', 'capabilities', 'default.json'))
  const quick = JSON.parse(read('src-tauri', 'capabilities', 'quick-access.json'))
  assert.deepEqual(main.windows, ['main'])
  assert.deepEqual(quick.windows, ['quick-access'])
  assert.deepEqual(main.permissions, [
    'core:app:allow-version',
    'core:event:allow-listen',
    'core:event:allow-unlisten',
    'core:window:allow-close',
    'core:window:allow-minimize',
    'core:window:allow-start-dragging',
    'core:window:allow-toggle-maximize',
    'core:webview:deny-internal-toggle-devtools',
    'vault-lifecycle',
    'vault-read',
    'vault-edit',
    'vault-tools',
    'backup-import',
    'account-service',
    'desktop-updater',
    'diagnostics',
    'external-navigation',
    'browser-approval',
    'desktop-settings',
    'website-icons',
    'clipboard-guard',
  ])
  assert.deepEqual(quick.permissions, [
    'core:event:allow-listen',
    'core:event:allow-unlisten',
    'core:window:allow-hide',
    'core:webview:deny-internal-toggle-devtools',
    'quick-access',
  ])
  for (const capability of [main, quick]) {
    assert.ok(!capability.permissions.includes('core:default'), `${capability.identifier} regained broad core defaults`)
    assert.ok(
      !capability.permissions.some((permission) => typeof permission === 'string' && permission.startsWith('opener:')),
      `${capability.identifier} regained frontend URL-launch authority`,
    )
  }

  const packageJson = JSON.parse(read('package.json'))
  assert.ok(!packageJson.dependencies['@tauri-apps/plugin-opener'], 'the renderer regained the opener client')
  const vaultClient = read('src', 'lib', 'vault.ts')
  assert.doesNotMatch(vaultClient, /@tauri-apps\/plugin-opener|openUrl\(/)
  assert.match(vaultClient, /invoke\('open_external_url', \{ url, purpose \}\)/)
  for (const path of filesMatching(/\.(ts|svelte)$/, join(root, 'src'))) {
    assert.doesNotMatch(
      readFileSync(path, 'utf8'),
      /@tauri-apps\/plugin-dialog/,
      `${relative(root, path)} can open a native file dialog without going through Rust`,
    )
  }
  const externalUrl = read('src-tauri', 'src', 'adapters', 'platform', 'external_url.rs')
  assert.match(externalUrl, /matches!\(parsed\.scheme\(\), "http" \| "https"\)/)
  assert.match(externalUrl, /parsed\.username\(\)\.is_empty\(\)/)
  assert.match(externalUrl, /parsed\.password\(\)\.is_some\(\)/)
  assert.match(externalUrl, /window\.label\(\) != "main"/)
  assert.match(externalUrl, /entry_owns_url\(entry, &parsed\)/)
  assert.match(externalUrl, /support_url_matches\(&parsed, option_env!\("VITE_SESAME_SITE_ORIGIN"\)\)/)
  assert.match(externalUrl, /requested\.path\(\) != "\/support"/)
  assert.match(externalUrl, /"appVersion" \| "diagnosticCode" \| "browserIntegration" \| "requestId"/)

  const config = JSON.parse(read('src-tauri', 'tauri.conf.json'))
  assert.ok(config.app.security.capabilities.includes('quick-access-capability'), 'the quick-access capability is not enabled')

  const build = read('src-tauri', 'build.rs')
  assert.match(build, /app_manifest\(tauri_build::AppManifest::new\(\)\)/, 'custom application commands are still implicitly available')

  const permissions = read('src-tauri', 'permissions', 'desktop.toml')
  const quickPermission = permissions.match(/identifier = "quick-access"([\s\S]*?)(?=\n\[\[permission\]\]|$)/)
  assert.ok(quickPermission, 'the dedicated quick-access application permission is missing')
  assert.deepEqual(
    [...quickPermission[1].matchAll(/"([a-z0-9_]+)"/g)].map((match) => match[1]),
    [
      'get_quick_access_status',
      'search_quick_access_items',
      'get_quick_access_field',
      'confirm_quick_access_field',
      'open_quick_access_item',
      'copy_secret',
      'clear_clipboard_if_unchanged',
    ],
  )

  const handler = read('src-tauri', 'src', 'lib.rs')
  const registeredCommands = [...handler.matchAll(/(?:commands::(?:[a-z0-9_]+::)*|clipboard::|desktop_settings::|desktop_shell::|website_icons::|adapters::platform::external_url::)([a-z0-9_]+),/g)]
    .map((match) => match[1])
  const permissionCommands = new Set(
    [...permissions.matchAll(/commands\.allow\s*=\s*\[([\s\S]*?)\]/g)]
      .flatMap((match) => [...match[1].matchAll(/"([a-z0-9_]+)"/g)].map((command) => command[1])),
  )
  assert.deepEqual(
    [...new Set(registeredCommands.filter((command) => !permissionCommands.has(command)))],
    [],
    'a registered custom command has no explicit application permission',
  )

  const quickView = read('src', 'lib', 'ui', 'QuickAccessView.svelte')
  assert.doesNotMatch(quickView, /unlockVault|unlockWithPin|getVaultStatus|getLoginCard/)
  assert.ok(!quick.permissions.includes('website-icons'), 'the quick-access window regained website-icon fetching')
  assert.doesNotMatch(quickView, /WebsiteIcon/, 'the quick-access window renders a website icon it cannot fetch')
  assert.match(quickView, /getQuickAccessStatus/)
  assert.match(quickView, /searchQuickAccessItems/)
  assert.match(quickView, /getQuickAccessField/)
  assert.match(quickView, /openQuickAccessItem/)
  const quickCommands = read('src-tauri', 'src', 'commands', 'quick_access.rs')
  assert.match(quickCommands, /window\.label\(\) == QUICK_ACCESS_WINDOW/)
  assert.match(quickCommands, /session\s*\.as_ref\(\)\s*\.ok_or\("Unlock your vault in Sesame first\."\)/)
  assert.doesNotMatch(quickCommands.split('#[cfg(test)]')[0], /VaultSnapshot|LoginCard|backup_codes:\s*|notes:\s*|username:\s*/)
})

function assertNoUpdaterPermissions(projectRoot) {
  const tauriRoot = join(projectRoot, 'src-tauri')
  const capabilities = []
  const collect = (value, source) => {
    assert.ok(value && typeof value === 'object' && !Array.isArray(value), `${source} must define a capability object`)
    assert.ok(typeof value.identifier === 'string' && value.identifier.length > 0, `${source} must define a capability identifier`)
    assert.ok(Array.isArray(value.permissions), `${source} must define a permissions array`)
    capabilities.push({ ...value, source })
  }
  for (const path of filesMatching(/\.(json|json5|toml)$/, join(tauriRoot, 'capabilities'))) {
    const source = relative(projectRoot, path).replaceAll('\\', '/')
    assert.ok(path.endsWith('.json'), `${source} must use JSON so the updater permission gate can inspect it`)
    const value = JSON.parse(readFileSync(path, 'utf8'))
    const hasCapabilities = value && !Array.isArray(value) && Object.hasOwn(value, 'capabilities')
    assert.ok(!hasCapabilities || !Object.hasOwn(value, 'identifier'), `${source} must define one capability shape`)
    const entries = Array.isArray(value) ? value : hasCapabilities ? value.capabilities : [value]
    assert.ok(Array.isArray(entries), `${source} must define a capability or a capabilities array`)
    for (const capability of entries) collect(capability, source)
  }
  for (const name of readdirSync(tauriRoot)) {
    if (!/^tauri(?:\.[^.]+)*\.conf\.(json|json5)$/.test(name) && !/^Tauri(?:\.[^.]+)*\.toml$/.test(name)) continue
    assert.ok(name.endsWith('.json'), `${name} must use JSON so the updater permission gate can inspect it`)
    const config = JSON.parse(readFileSync(join(tauriRoot, name), 'utf8'))
    const entries = config.app?.security?.capabilities ?? []
    assert.ok(Array.isArray(entries), `${name} must define a capabilities array`)
    for (const capability of entries) {
      if (typeof capability === 'string') {
        assert.ok(capability.length > 0, `${name} must reference a capability identifier`)
      } else {
        collect(capability, name)
      }
    }
  }
  const offenders = capabilities.flatMap((capability) => capability.permissions.map((permission) => {
    const identifier = typeof permission === 'string' ? permission : permission?.identifier
    assert.ok(typeof identifier === 'string' && identifier.length > 0, `${capability.source} must define a permission identifier`)
    return identifier.startsWith('updater:') ? `${capability.source} grants ${identifier}` : null
  }).filter(Boolean))
  assert.deepEqual(offenders, [], `updater permissions would hand the webview the updater plugin surface:\n  ${offenders.join('\n  ')}`)
}

test('no capability grants a webview an updater permission', () => {
  assertNoUpdaterPermissions(root)
})

test('the updater permission gate inspects inline and grouped capabilities', () => {
  const fixture = mkdtempSync(join(tmpdir(), 'sesame-updater-permissions-'))
  const tauriRoot = join(fixture, 'src-tauri')
  const capabilityRoot = join(tauriRoot, 'capabilities')
  const configPath = join(tauriRoot, 'tauri.conf.json')
  mkdirSync(capabilityRoot, { recursive: true })
  const safe = { identifier: 'fictional-safe', windows: ['main'], permissions: ['core:window:allow-show'] }
  const updater = { identifier: 'fictional-updater', windows: ['main'], permissions: ['updater:default'] }
  const configure = (capabilities) => writeFileSync(configPath, JSON.stringify({ app: { security: { capabilities } } }))
  const capabilityPath = join(capabilityRoot, 'fictional.json')
  try {
    configure([safe])
    writeFileSync(capabilityPath, JSON.stringify(safe))
    assert.doesNotThrow(() => assertNoUpdaterPermissions(fixture))
    configure([updater])
    assert.throws(() => assertNoUpdaterPermissions(fixture), /tauri.conf.json grants updater:default/)
    configure([{ ...updater, permissions: [{ identifier: 'updater:allow-download', allow: [] }] }])
    assert.throws(() => assertNoUpdaterPermissions(fixture), /tauri.conf.json grants updater:allow-download/)
    configure(['fictional-safe'])
    for (const value of [updater, [safe, updater], { capabilities: [safe, updater] }]) {
      writeFileSync(capabilityPath, JSON.stringify(value))
      assert.throws(() => assertNoUpdaterPermissions(fixture), /fictional.json grants updater:default/)
    }
    writeFileSync(capabilityPath, JSON.stringify({ ...updater, capabilities: [safe] }))
    assert.throws(() => assertNoUpdaterPermissions(fixture), /must define one capability shape/)
    writeFileSync(capabilityPath, JSON.stringify({ capabilities: null }))
    assert.throws(() => assertNoUpdaterPermissions(fixture), /must define a capability or a capabilities array/)
    writeFileSync(capabilityPath, JSON.stringify(safe))
    const platformPath = join(tauriRoot, 'tauri.windows.conf.json')
    writeFileSync(platformPath, JSON.stringify({ app: { security: { capabilities: [updater] } } }))
    assert.throws(() => assertNoUpdaterPermissions(fixture), /tauri.windows.conf.json grants updater:default/)
    rmSync(platformPath)
    for (const capability of [null, { ...safe, permissions: null }, { ...safe, permissions: [null] }]) {
      configure([capability])
      assert.throws(() => assertNoUpdaterPermissions(fixture), /must define/)
    }
    configure([safe])
    writeFileSync(capabilityPath, '{invalid')
    assert.throws(() => assertNoUpdaterPermissions(fixture), SyntaxError)
    writeFileSync(capabilityPath, JSON.stringify(safe))
    for (const name of ['fictional.toml', 'fictional.json5']) {
      const path = join(capabilityRoot, name)
      writeFileSync(path, 'fictional unsupported capability')
      assert.throws(() => assertNoUpdaterPermissions(fixture), /must use JSON/)
      rmSync(path)
    }
    for (const name of ['Tauri.toml', 'tauri.conf.json5']) {
      const path = join(tauriRoot, name)
      writeFileSync(path, 'fictional unsupported config')
      assert.throws(() => assertNoUpdaterPermissions(fixture), /must use JSON/)
      rmSync(path)
    }
  } finally {
    rmSync(fixture, { recursive: true, force: true })
  }
})

function generatedPermission(manifests, identifier) {
  const separator = identifier.lastIndexOf(':')
  if (separator > 0) {
    const scoped = manifests[identifier.slice(0, separator)]?.permissions?.[identifier.slice(separator + 1)]
    if (scoped) return scoped
  }
  return manifests['__app-acl__'].permissions[identifier] ?? null
}

function capabilityCommands(manifests, capabilities, identifier) {
  const capability = capabilities[identifier]
  assert.ok(capability, `the generated ACL does not define the ${identifier} capability`)
  const commands = new Set()
  for (const name of capability.permissions) {
    const permission = generatedPermission(manifests, name)
    assert.ok(permission, `${identifier} names permission ${name}, which the generated ACL does not define`)
    for (const command of permission.commands.allow) commands.add(command)
  }
  return commands
}

function topLevelArguments(slice) {
  const parts = []
  let depth = 0
  let start = 0
  for (let i = 0; i < slice.length; i += 1) {
    const character = slice[i]
    if (character === '(' || character === '[' || character === '{' || character === '<') depth += 1
    else if (character === ')' || character === ']' || character === '}' || character === '>') depth -= 1
    else if (character === ',' && depth === 0) {
      parts.push(slice.slice(start, i))
      start = i + 1
    }
  }
  parts.push(slice.slice(start))
  return parts.map((part) => part.trim()).filter(Boolean)
}

function callerSuppliedBooleanGates(text) {
  const gates = []
  for (const match of text.matchAll(/#\[tauri::command[^\]]*\]\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)\s*\(/g)) {
    const open = text.indexOf('(', match.index + match[0].length - 1)
    const slice = callArgumentSlice(text, open, false)
    if (slice === null) continue
    for (const raw of topLevelArguments(slice)) {
      const parameter = raw.replace(/^#\s*\[[^\]]*\]\s*/, '').replace(/^mut\s+/, '')
      const named = parameter.match(/^([a-z_][a-z0-9_]*)\s*:\s*(.+)$/)
      if (!named || !/^(?:Option\s*<\s*)?bool\s*>?$/.test(named[2])) continue
      if (['confirmed', 'secret', 'reveal'].includes(named[1])) gates.push(`${match[1]}:${named[1]}`)
    }
  }
  return gates
}

test('the quick-access window cannot reach deliberate release or input-injection commands', () => {
  const manifests = JSON.parse(read('src-tauri', 'gen', 'schemas', 'acl-manifests.json'))
  const capabilities = JSON.parse(read('src-tauri', 'gen', 'schemas', 'capabilities.json'))
  const forbidden = ['reveal_login_secret', 'auto_type', 'export_backup', 'export_vault_csv', 'export_recovery_kit']

  const permission = manifests['__app-acl__'].permissions['quick-access']
  assert.ok(permission, 'the generated ACL does not define the quick-access permission')
  const granted = new Set(permission.commands.allow)
  const permissionOffenders = forbidden.filter((command) => granted.has(command))
  assert.deepEqual(
    permissionOffenders,
    [],
    `the quick-access permission grants deliberate release or input commands: ${permissionOffenders.join(', ')}`,
  )

  const reachable = capabilityCommands(manifests, capabilities, 'quick-access-capability')
  const windowOffenders = forbidden.filter((command) => reachable.has(command))
  assert.deepEqual(
    windowOffenders,
    [],
    `the quick-access window can now reach deliberate release or input commands: ${windowOffenders.join(', ')}`,
  )
})

test('only the quick-access permission hands out get_quick_access_field', () => {
  const manifests = JSON.parse(read('src-tauri', 'gen', 'schemas', 'acl-manifests.json'))
  const capabilities = JSON.parse(read('src-tauri', 'gen', 'schemas', 'capabilities.json'))

  const holders = []
  for (const manifest of Object.values(manifests)) {
    for (const definition of Object.values(manifest.permissions ?? {})) {
      if (definition.commands.allow.includes('get_quick_access_field')) holders.push(definition.identifier)
    }
  }
  assert.deepEqual(
    holders.sort(),
    ['quick-access'],
    `get_quick_access_field must stay confined to the quick-access permission, but the generated ACL grants it through: ${holders.join(', ')}`,
  )
  assert.ok(
    !capabilityCommands(manifests, capabilities, 'main-capability').has('get_quick_access_field'),
    'the main window capability gained get_quick_access_field',
  )
})

test('only the quick-access permission hands out confirm_quick_access_field', () => {
  const manifests = JSON.parse(read('src-tauri', 'gen', 'schemas', 'acl-manifests.json'))
  const capabilities = JSON.parse(read('src-tauri', 'gen', 'schemas', 'capabilities.json'))

  const holders = []
  for (const manifest of Object.values(manifests)) {
    for (const definition of Object.values(manifest.permissions ?? {})) {
      if (definition.commands.allow.includes('confirm_quick_access_field')) holders.push(definition.identifier)
    }
  }
  assert.deepEqual(
    holders.sort(),
    ['quick-access'],
    `confirm_quick_access_field must stay confined to the quick-access permission, but the generated ACL grants it through: ${holders.join(', ')}`,
  )
  assert.ok(
    capabilityCommands(manifests, capabilities, 'quick-access-capability').has('confirm_quick_access_field'),
    'the quick-access window capability lost confirm_quick_access_field',
  )
  assert.ok(
    !capabilityCommands(manifests, capabilities, 'main-capability').has('confirm_quick_access_field'),
    'the main window capability gained confirm_quick_access_field',
  )
})

test('caller-supplied boolean gates on the command surface stay pinned', () => {
  const gates = filesMatching(/\.rs$/, join(root, 'src-tauri', 'src'))
    .flatMap((path) => callerSuppliedBooleanGates(readFileSync(path, 'utf8')))
    .sort()
  assert.deepEqual(
    gates,
    [],
    'a command gained a caller-supplied boolean authorization gate; confirmation state must live in backend state',
  )
})

test('desktop OS and reusable HTTP adapters stay in their named Rust boundaries', () => {
  const rustFiles = filesMatching(/\.rs$/, join(root, 'src-tauri', 'src'))
  const platformOffenders = rustFiles
    .filter((path) => readFileSync(path, 'utf8').includes('windows_sys::'))
    .map((path) => relative(root, path).replaceAll('\\', '/'))
    .filter((path) => !path.startsWith('src-tauri/src/adapters/platform/'))
  assert.deepEqual(platformOffenders, [], `windows-sys escaped the platform adapters:\n${platformOffenders.join('\n')}`)

  const networkOffenders = rustFiles
    .filter((path) => /(?:use\s+reqwest|reqwest::)/.test(readFileSync(path, 'utf8')))
    .map((path) => relative(root, path).replaceAll('\\', '/'))
    .filter((path) => !path.startsWith('src-tauri/src/adapters/network/'))
  assert.deepEqual(networkOffenders, [], `reqwest escaped the network adapters:\n${networkOffenders.join('\n')}`)

  const adapterRoot = read('src-tauri', 'src', 'adapters', 'mod.rs')
  assert.match(adapterRoot, /mod network;/)
  assert.match(adapterRoot, /mod platform;/)
})

test('the updater VM lab is ephemeral, loopback-only, and cannot alter shipping transport', () => {
  const prepare = read('tools', 'prepare-updater-vm-lab.mjs')
  const serve = read('tools', 'serve-updater-vm-lab.mjs')
  const verify = read('tools', 'verify-updater-vm-lab.mjs')
  const shippingConfig = read('src-tauri', 'tauri.conf.json')

  assert.match(prepare, /outputLocation\.startsWith\(`\.\.\$\{sep\}`\)/)
  assert.match(prepare, /await rm\(privateDirectory, \{ recursive: true, force: true \}\)/)
  assert.match(prepare, /if \(!completed\) await rm\(output, \{ recursive: true, force: true \}\)/)
  assert.match(prepare, /const host = '127\.0\.0\.1'/)
  assert.match(prepare, /SESAME_UPDATE_MANIFEST_URL: `http:\/\/\$\{host\}:\$\{port\}\/latest\.json`/)
  assert.match(prepare, /SESAME_ALLOW_INSECURE_UPDATE_LOOPBACK: '1'/)
  assert.match(prepare, /dangerousInsecureTransportProtocol: true/)
  assert.match(serve, /config\.host !== '127\.0\.0\.1'/)
  assert.match(serve, /url\.pathname === '\/latest\.json'/)
  assert.match(serve, /timingSafeEqual/)
  assert.match(verify, /Relabelled manifest does not isolate the version-label attack/)
  assert.match(verify, /Private-key-shaped payload remains/)
  assert.doesNotMatch(shippingConfig, /dangerousInsecureTransportProtocol/)
})

test('no release workflow enables the insecure loopback update path', () => {
  const workflowDirectory = join(root, '.github', 'workflows')
  const releaseWorkflows = readdirSync(workflowDirectory).filter((name) => /^release-.*\.ya?ml$/.test(name))
  assert.ok(releaseWorkflows.length >= 2, `expected the tagged-release workflows, found ${releaseWorkflows.length}`)
  const offenders = releaseWorkflows.filter((name) =>
    readFileSync(join(workflowDirectory, name), 'utf8').includes('SESAME_ALLOW_INSECURE_UPDATE_LOOPBACK'))
  assert.deepEqual(offenders, [], `a release workflow enables the loopback-only insecure update path:\n  ${offenders.join('\n  ')}`)
})

test('desktop updates use an account-independent signed static manifest', () => {
  const updater = read('src-tauri', 'src', 'commands', 'updater.rs')
  const publicUpdates = read('src-tauri', 'src', 'adapters', 'network', 'public_updates.rs')
  const build = read('src-tauri', 'build.rs')
  const settings = read('src', 'lib', 'ui', 'SettingsView.svelte')
  const app = read('src', 'App.svelte')
  const settingsController = read('src', 'lib', 'controllers', 'settings-controller.ts')
  const manifestTool = read('tools', 'create-static-update-manifest.mjs')
  const workflow = read('.github', 'workflows', 'release-early-access.yml')

  assert.doesNotMatch(updater, /read_service_(?:connection|token)|Authorization|\/v1\/desktop\/updates/)
  assert.match(updater, /adapters::network::public_updates::check\(app\)/)
  assert.match(publicUpdates, /option_env!\("SESAME_UPDATE_MANIFEST_URL"\)/)
  assert.match(publicUpdates, /parsed\.scheme\(\) == "https"/)
  assert.match(publicUpdates, /SESAME_ALLOW_INSECURE_UPDATE_LOOPBACK/)
  assert.match(publicUpdates, /url::Host::Ipv4\(ip\) => ip\.is_loopback\(\)/)
  assert.match(publicUpdates, /url::Host::Ipv6\(ip\) => ip\.is_loopback\(\)/)
  assert.match(build, /cargo:rerun-if-env-changed=SESAME_UPDATE_MANIFEST_URL/)
  assert.match(settings, /No Sesame account is required\./)
  assert.doesNotMatch(settings, /!serviceConnection\.connected[^\n]*onCheckForUpdate/)
  assert.doesNotMatch(app, /startBackgroundUpdateChecks/)
  assert.doesNotMatch(settingsController, /startBackgroundUpdateChecks|setInterval[^\n]*checkForUpdate/)
  assert.match(manifestTool, /const target = `\$\{candidate\.platform\}-\$\{candidate\.architecture\}-\$\{artifact\.format\}`/)
  assert.match(manifestTool, /candidateReceipt/)
  assert.match(manifestTool, /SESAME_PUBLIC_UPDATE_ARTIFACT_URL/)
  assert.match(workflow, /create-static-update-manifest\.mjs \$candidate candidate-receipt\/latest\.json/)
  assert.match(workflow, /SESAME_RELEASE_CANDIDATE_PUBLIC_KEY/)
  const commands = workflow
    .split('\n')
    .filter((line) => !/^\s*echo\b/.test(line))
    .join('\n')
  assert.doesNotMatch(commands, /gh release create|softprops\/action-gh-release/, 'the release workflow creates a GitHub release')
})

test('every file command resolves its path through a Rust-issued choice', () => {
  const commands = [
    ['backups.rs', 'export_backup'],
    ['backups.rs', 'export_vault_csv'],
    ['backups.rs', 'export_recovery_kit'],
    ['backups.rs', 'inspect_backup'],
    ['backups.rs', 'verify_backup'],
    ['backups.rs', 'restore_backup'],
    ['imports.rs', 'preview_import'],
    ['support.rs', 'export_diagnostics'],
  ]
  for (const [file, command] of commands) {
    const source = read('src-tauri', 'src', 'commands', file)
    const start = source.indexOf(`pub fn ${command}(`)
    assert.ok(start >= 0, `${command} does not exist in ${file}`)
    const next = source.indexOf('\n#[tauri::command]', start)
    const body = source.slice(start, next === -1 ? source.length : next)
    const resolution = command === 'restore_backup' ? /claim\(/ : /resolve_path\(/
    assert.match(body, resolution, `${command} takes a file path without a Rust-issued choice`)
  }

  const selection = read('src-tauri', 'src', 'commands', 'file_selection.rs')
  const resolveBody = braceBody(selection, selection.indexOf('pub(crate) fn resolve_path('))
  assert.match(
    resolveBody,
    /#\[cfg\(feature = "wdio"\)\][\s\S]*PathBuf::from\(path\)[\s\S]*#\[cfg\(not\(feature = "wdio"\)\)\]/,
    'the raw path bypass is not confined to the wdio feature',
  )
  assert.match(
    selection,
    /#\[cfg\(feature = "wdio"\)\]\s*#\[tauri::command\]\s*pub fn wdio_issue_file_choice/,
    'the file-choice test bridge is not confined to the wdio feature',
  )
})

test('the restore gate redeems a Rust-issued file choice and never a raw path', () => {
  const gate = read('tools', 'run-vault-restore-gate.mjs')
  const calls = [...gate.matchAll(/bridge\.call\('restore_backup'/g)]
  assert.ok(calls.length > 0, 'the restore gate never calls restore_backup')
  for (const call of calls) {
    const args = callArgumentSlice(gate, call.index + 'bridge.call'.length)
    assert.ok(args, 'a restore_backup call could not be read')
    assert.match(args, /\btoken\b/, 'a restore_backup call does not pass a Rust-issued token')
    assert.doesNotMatch(args, /\bsource\b/, 'a restore_backup call still passes a raw source path')
  }
  assert.match(
    gate,
    /bridge\.call\('wdio_issue_file_choice'/,
    'the restore gate never asks the Rust bridge for a file choice',
  )
})

test('the installed-app test bridge is excluded from normal desktop builds', () => {
  const cargo = read('src-tauri', 'Cargo.toml')
  const rust = read('src-tauri', 'src', 'lib.rs')
  const frontend = read('src', 'main.ts')

  assert.match(cargo, /^wdio = \[\]$/m, 'the test-only Rust feature is missing')
  assert.match(rust, /#\[cfg\(feature = "wdio"\)\]\s*mod desktop_e2e;/)
  assert.match(
    rust,
    /#\[cfg\(feature = "wdio"\)\]\s*let builder = builder\.invoke_handler\(sesame_wdio_handler!\(\)\);/,
    'the test command is no longer confined to WDIO builds',
  )
  assert.match(
    rust,
    /#\[cfg\(not\(feature = "wdio"\)\)\]\s*let builder = builder\.invoke_handler\(sesame_handler!\(\)\);/,
    'normal builds no longer select the shipping command handler explicitly',
  )
  assert.match(frontend, /import\.meta\.env\.VITE_SESAME_WDIO === 'true'/)
  assert.match(frontend, /import\('\.\/lib\/desktop-e2e-bridge'\)/)
})

function callArgumentSlice(text, openParenIndex, singleQuotes = true) {
  let depth = 0
  let quote = null
  for (let i = openParenIndex + 1; i < text.length; i += 1) {
    const character = text[i]
    if (quote) {
      if (character === '\\') { i += 1; continue }
      if (character === quote) quote = null
      continue
    }
    if (character === '"' || (singleQuotes && character === "'")) { quote = character; continue }
    if (character === '(') depth += 1
    else if (character === ')') {
      if (depth === 0) return text.slice(openParenIndex + 1, i)
      depth -= 1
    }
  }
  return null
}

function braceBody(text, startIndex, singleQuotes = true) {
  const open = text.indexOf('{', startIndex)
  if (open < 0) return ''
  let depth = 0
  let quote = null
  for (let i = open; i < text.length; i += 1) {
    const character = text[i]
    if (quote) {
      if (character === '\\') { i += 1; continue }
      if (character === quote) quote = null
      continue
    }
    if (character === '"' || (singleQuotes && character === "'")) { quote = character; continue }
    if (character === '{') depth += 1
    else if (character === '}') {
      depth -= 1
      if (depth === 0) return text.slice(open + 1, i)
    }
  }
  return ''
}

function firstArgument(slice, singleQuotes = true) {
  let depth = 0
  let quote = null
  for (let i = 0; i < slice.length; i += 1) {
    const character = slice[i]
    if (quote) {
      if (character === '\\') { i += 1; continue }
      if (character === quote) quote = null
      continue
    }
    if (character === '"' || (singleQuotes && character === "'")) { quote = character; continue }
    if (character === '(' || character === '[' || character === '{') depth += 1
    else if (character === ')' || character === ']' || character === '}') depth -= 1
    else if (character === ',' && depth === 0) return slice.slice(0, i)
  }
  return slice
}

function stringLiterals(slice, singleQuotes = true) {
  const found = []
  const pattern = singleQuotes
    ? /"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'/g
    : /"((?:[^"\\]|\\.)*)"/g
  for (const match of slice.matchAll(pattern)) found.push(match[1] ?? match[2])
  return found
}

function callSites(text, name, singleQuotes = true) {
  const sites = []
  for (const match of text.matchAll(new RegExp(`${name}\\(`, 'g'))) {
    const slice = callArgumentSlice(text, match.index + name.length, singleQuotes)
    if (slice !== null) sites.push({ slice, index: match.index })
  }
  return sites
}

function allowlistOf(diagnostics, functionName) {
  const start = diagnostics.indexOf(`fn ${functionName}(`)
  if (start < 0) return new Set()
  return new Set(stringLiterals(braceBody(diagnostics, start, false), false))
}

function severityCodes(diagnostics) {
  const start = diagnostics.indexOf('fn severity(')
  if (start < 0) return new Set()
  const labels = new Set(['error', 'warn', 'info'])
  return new Set(stringLiterals(braceBody(diagnostics, start, false), false).filter((code) => !labels.has(code)))
}

function locationOf(text, index) {
  const before = text.slice(0, index)
  const line = before.split('\n').length
  return `${line}:${before.length - before.lastIndexOf('\n')}`
}

test('every diagnostic code the app can emit stays on the diagnostics allowlist', () => {
  const diagnostics = read('src-tauri', 'src', 'diagnostics.rs')
  const allowedOperation = allowlistOf(diagnostics, 'allowed_operation')
  const allowedCode = allowlistOf(diagnostics, 'allowed_code')
  const allowedBrowserHost = allowlistOf(diagnostics, 'allowed_browser_host_code')
  const offenders = []

  for (const path of filesMatching(/\.(ts|svelte)$/, join(root, 'src'))) {
    const text = readFileSync(path, 'utf8')
    for (const site of callSites(text, 'recordDiagnostic')) {
      const [operation, code] = stringLiterals(site.slice)
      const where = `${relative(root, path)}:${locationOf(text, site.index)}`
      if (operation && !allowedOperation.has(operation)) offenders.push(`${where} emits operation ${operation}`)
      if (code && !allowedCode.has(code)) offenders.push(`${where} emits code ${code}`)
    }
  }

  const settings = read('src', 'lib', 'controllers', 'settings-controller.ts')
  const mapping = settings.match(
    /const code = result\.code === 'hostMissing' \? '([a-z0-9_]+)'\s*\n\s*: result\.code === 'manifestMissing' \? '([a-z0-9_]+)'\s*\n\s*: result\.code === 'registrationMissing' \? '([a-z0-9_]+)' : '([a-z0-9_]+)'/
  )
  assert.ok(mapping, 'the repair-browser-integration diagnostic mapping changed shape')
  for (const code of mapping.slice(1)) {
    if (!allowedCode.has(code)) offenders.push(`settings-controller.ts dynamic mapping code ${code}`)
  }

  for (const path of filesMatching(/\.rs$/, join(root, 'src-tauri', 'src'))) {
    const text = readFileSync(path, 'utf8')
    for (const name of ['record_browser_host_registration', 'record_browser_host_process']) {
      for (const site of callSites(text, name, false)) {
        const where = `${relative(root, path)}:${locationOf(text, site.index)}`
        for (const code of stringLiterals(site.slice, false)) {
          if (!allowedBrowserHost.has(code)) offenders.push(`${where} emits code ${code}`)
        }
      }
    }
    for (const site of callSites(text, 'RegistrationError::new', false)) {
      const code = stringLiterals(firstArgument(site.slice, false), false)[0]
      if (code && !allowedBrowserHost.has(code)) {
        offenders.push(`${relative(root, path)}:${locationOf(text, site.index)} emits code ${code}`)
      }
    }
  }

  assert.deepEqual(offenders, [], `diagnostic codes emitted outside the allowlists are rejected and never written:\n  ${offenders.join('\n  ')}`)
})

test('every allowlisted diagnostic code has an explicit severity classification', () => {
  const diagnostics = read('src-tauri', 'src', 'diagnostics.rs')
  const allowed = new Set([
    ...allowlistOf(diagnostics, 'allowed_code'),
    ...allowlistOf(diagnostics, 'allowed_browser_host_code'),
  ])
  const classified = severityCodes(diagnostics)
  const missing = [...allowed].filter((code) => !classified.has(code)).sort()
  assert.deepEqual(missing, [], `allowlisted codes with no explicit severity default to info and are pruned after a day:\n  ${missing.join('\n  ')}`)
})

test('the C ABI exports only the intended sesame_core symbols', () => {
  const rust = filesMatching(/\.rs$/, join(root, 'src-tauri')).map((path) => readFileSync(path, 'utf8'))
  const attributes = rust.flatMap((text) => text.match(/#\[no_mangle\]/g) ?? [])
  assert.equal(attributes.length, 4, 'an unexpected #[no_mangle] export was added to src-tauri')

  const exported = rust
    .flatMap((text) => [
      ...text.matchAll(/#\[no_mangle\]\s*(?:pub\s+)?(?:unsafe\s+)?extern\s+"C"\s+fn\s+([A-Za-z0-9_]+)/g),
    ].map((match) => match[1]))
    .sort()

  assert.deepEqual(exported, [
    'sesame_core_api_version',
    'sesame_core_close_vault',
    'sesame_core_entry_count',
    'sesame_core_open_vault',
  ])
})

test('the recovery kit wait reads server time, never the local clock', () => {
  const source = readFileSync(join(root, 'src-tauri', 'src', 'commands', 'recovery_replacement.rs'), 'utf8')
  assert.match(source, /trusted_time\(\)\.await\?\.latest/, 'a recovery kit request must record the later server time')
  assert.match(source, /trusted_time\(\)\.await\?\.earliest/, 'issuing a recovery kit must use the earlier server time')
  assert.doesNotMatch(source, /SystemTime|Utc::now|Local::now|Instant::now|unix_timestamp/, 'the recovery kit wait read the local clock')
})

const FEATURE_GATED_PERMISSIONS = ['sync-preview', 'desktop-e2e']

function applicationPermissions() {
  const permissions = new Map()
  const source = read('src-tauri', 'permissions', 'desktop.toml')
  for (const block of source.split('[[permission]]').slice(1)) {
    const identifier = block.match(/identifier = "([a-z0-9-]+)"/)?.[1]
    const list = block.match(/commands\.allow\s*=\s*\[([\s\S]*?)\]/)?.[1] ?? ''
    assert.ok(identifier, 'an application permission has no identifier')
    permissions.set(identifier, [...list.matchAll(/"([a-z0-9_]+)"/g)].map((match) => match[1]))
  }
  return permissions
}

function commandNames(block) {
  return [...block.matchAll(/(?:[a-z0-9_]+::)+([a-z0-9_]+),/g)].map((match) => match[1])
}

function shippingRegisteredCommands() {
  const lib = read('src-tauri', 'src', 'lib.rs')
  const shared = lib.match(/macro_rules! sesame_invoke_handler \{[\s\S]*?tauri::generate_handler!\[([\s\S]*?)\$\(\$extra,\)\*/)
  assert.ok(shared, 'the shared invoke handler list is no longer a single macro this test can read')
  return new Set(commandNames(shared[1]))
}

function featureRegisteredCommands(feature) {
  const lib = read('src-tauri', 'src', 'lib.rs')
  const arms = [...lib.matchAll(new RegExp(`#\\[cfg\\(all\\(feature = "wdio"[^\\]]*\\)\\)\\]\\s*macro_rules! sesame_wdio_handler \\{([\\s\\S]*?)\\n\\}`, 'g'))]
  const sync = lib.match(/#\[cfg\(feature = "sync-preview"\)\]\s*macro_rules! sesame_handler \{([\s\S]*?)\n\}/)
  assert.ok(sync && arms.length === 2, 'the feature gated handler arms moved')
  return new Set(feature === 'sync-preview' ? commandNames(sync[1]) : commandNames(arms.map((arm) => arm[1]).join('\n')).filter((name) => !name.startsWith('sync_')))
}

function capabilityFiles() {
  const directory = join(root, 'src-tauri', 'capabilities')
  return new Map(readdirSync(directory).map((name) => {
    const capability = JSON.parse(readFileSync(join(directory, name), 'utf8'))
    return [capability.identifier, { ...capability, name }]
  }))
}

function configuredCapabilities(name) {
  return JSON.parse(read('src-tauri', name)).app.security.capabilities
}

test('every command a shipping capability permits is registered in the shipping handler', () => {
  const permissions = applicationPermissions()
  const registered = shippingRegisteredCommands()
  const capabilities = capabilityFiles()
  const shipping = configuredCapabilities('tauri.conf.json')
  assert.deepEqual(shipping, ['main-capability', 'quick-access-capability'])

  for (const identifier of shipping) {
    const capability = capabilities.get(identifier)
    assert.ok(capability, `${identifier} has no capability file`)
    for (const permission of capability.permissions) {
      assert.ok(
        !FEATURE_GATED_PERMISSIONS.includes(permission),
        `${identifier} names the feature gated ${permission} permission`,
      )
      if (!permissions.has(permission)) continue
      for (const command of permissions.get(permission)) {
        assert.ok(registered.has(command), `${identifier} permits ${command} through ${permission}, but the shipping handler does not register it`)
      }
    }
  }
})

test('a permission whose commands are not all shipping commands is feature gated', () => {
  const permissions = applicationPermissions()
  const registered = shippingRegisteredCommands()
  const unregistered = [...permissions]
    .filter(([, commands]) => commands.some((command) => !registered.has(command)))
    .map(([identifier]) => identifier)
  assert.deepEqual(unregistered.sort(), [...FEATURE_GATED_PERMISSIONS].sort())
  for (const identifier of FEATURE_GATED_PERMISSIONS) {
    assert.ok(
      permissions.get(identifier).every((command) => !registered.has(command)),
      `${identifier} mixes shipping and feature gated commands`,
    )
  }
})

test('the feature gated permissions name only commands their own build registers', () => {
  const permissions = applicationPermissions()
  for (const [permission, feature] of [['sync-preview', 'sync-preview'], ['desktop-e2e', 'wdio']]) {
    const registered = featureRegisteredCommands(feature === 'wdio' ? 'wdio' : feature)
    assert.deepEqual(
      permissions.get(permission).filter((command) => !registered.has(command)),
      [],
      `${permission} permits a command the ${feature} build does not register`,
    )
  }
})

test('the feature gated capabilities exist only in the builds that compile their commands', () => {
  const capabilities = capabilityFiles()
  const shipped = new Set(configuredCapabilities('tauri.conf.json'))
  assert.deepEqual(capabilities.get('sync-preview-capability')?.permissions, ['sync-preview'])
  assert.deepEqual(capabilities.get('desktop-e2e-capability')?.permissions, ['desktop-e2e'])
  for (const identifier of ['sync-preview-capability', 'desktop-e2e-capability']) {
    assert.ok(!shipped.has(identifier), `the shipping configuration enables ${identifier}`)
    assert.deepEqual(capabilities.get(identifier).windows, ['main'])
  }
  assert.deepEqual([...capabilities.keys()].sort(), [
    'desktop-e2e-capability',
    'main-capability',
    'quick-access-capability',
    'sync-preview-capability',
  ])
  assert.deepEqual(configuredCapabilities('tauri.wdio.conf.json'), ['main-capability', 'desktop-e2e-capability'])
  assert.deepEqual(
    configuredCapabilities('tauri.sync-preview.conf.json'),
    ['main-capability', 'quick-access-capability', 'sync-preview-capability'],
  )
  const runner = read('tools', 'run-sync-preview-desktop.mjs')
  assert.match(runner, /'--features', 'sync-preview', '--config', 'src-tauri\/tauri\.sync-preview\.conf\.json'/)
  const wdioCommands = [
    ...read('.github', 'workflows', 'ci.yml').matchAll(/tauri build --features wdio[^\n]*/g),
    ...read('.github', 'workflows', 'release-early-access.yml').matchAll(/tauri build --features wdio[^\n]*/g),
    ...read('.github', 'workflows', 'release-linux-early-access.yml').matchAll(/tauri build --features wdio[^\n]*/g),
  ]
  assert.ok(wdioCommands.length >= 3)
  for (const command of wdioCommands) assert.match(command[0], /--config src-tauri\/tauri\.wdio\.conf\.json/)
})

test('the generated capability manifest matches the capability files', () => {
  const generated = JSON.parse(read('src-tauri', 'gen', 'schemas', 'capabilities.json'))
  const capabilities = capabilityFiles()
  for (const [identifier, capability] of Object.entries(generated)) {
    assert.deepEqual(capability.permissions, capabilities.get(identifier)?.permissions, `${identifier} drifted from its capability file`)
  }
  assert.ok(generated['main-capability'] && generated['quick-access-capability'])
})

test('the generated ACL grants the feature gated commands only to their own builds', () => {
  const manifests = JSON.parse(read('src-tauri', 'gen', 'schemas', 'acl-manifests.json'))
  const capabilities = Object.fromEntries(capabilityFiles())
  const permissions = applicationPermissions()
  const enabledCommands = (configName) => {
    const commands = new Set()
    for (const identifier of configuredCapabilities(configName)) {
      for (const command of capabilityCommands(manifests, capabilities, identifier)) commands.add(command)
    }
    return commands
  }

  const release = enabledCommands('tauri.conf.json')
  for (const [permission, configName, capabilityName] of [
    ['sync-preview', 'tauri.sync-preview.conf.json', 'sync-preview-capability'],
    ['desktop-e2e', 'tauri.wdio.conf.json', 'desktop-e2e-capability'],
  ]) {
    const granted = [...capabilityCommands(manifests, capabilities, capabilityName)].sort()
    assert.deepEqual(granted, [...permissions.get(permission)].sort(), `${capabilityName} drifted from the ${permission} permission`)
    const feature = enabledCommands(configName)
    for (const command of granted) {
      assert.ok(feature.has(command), `${configName} cannot reach ${command} through ${capabilityName}`)
      assert.ok(!release.has(command), `the release build reaches ${command} through ${capabilityName}`)
    }
  }
})

test('no webview holds a clipboard plugin permission or the clipboard plugin client', () => {
  const capabilities = capabilityFiles()
  for (const capability of capabilities.values()) {
    assert.ok(
      !capability.permissions.some((permission) => String(permission).startsWith('clipboard-manager:')),
      `${capability.identifier} grants a clipboard plugin permission`,
    )
  }
  const packageJson = JSON.parse(read('package.json'))
  assert.ok(!packageJson.dependencies['@tauri-apps/plugin-clipboard-manager'], 'the renderer regained the clipboard plugin client')
  assert.ok(!JSON.parse(read('package-lock.json')).packages['node_modules/@tauri-apps/plugin-clipboard-manager'])
  for (const path of filesMatching(/\.(ts|svelte)$/, join(root, 'src'))) {
    assert.doesNotMatch(readFileSync(path, 'utf8'), /@tauri-apps\/plugin-clipboard-manager/, `${relative(root, path)} imports the clipboard plugin`)
  }
  const arboardCopy = read('src-tauri', 'src', 'adapters', 'platform', 'clipboard.rs')
  assert.doesNotMatch(arboardCopy, /tauri_plugin_clipboard_manager/)
})

function parseContentSecurityPolicy(policy) {
  const directives = new Map()
  for (const part of policy.split(';').map((entry) => entry.trim()).filter(Boolean)) {
    const [name, ...sources] = part.split(/\s+/)
    assert.ok(!directives.has(name), `the policy repeats ${name}`)
    directives.set(name, sources)
  }
  return directives
}

test('the content security policy closes every embedding and worker route', () => {
  const security = JSON.parse(read('src-tauri', 'tauri.conf.json')).app.security
  const production = parseContentSecurityPolicy(security.csp)
  const development = parseContentSecurityPolicy(security.devCsp)
  const wdio = parseContentSecurityPolicy(JSON.parse(read('src-tauri', 'tauri.wdio.conf.json')).app.security.csp)
  const closed = ['frame-src', 'worker-src', 'media-src', 'manifest-src', 'frame-ancestors', 'object-src']
  for (const policy of [production, development, wdio]) {
    for (const directive of closed) assert.deepEqual(policy.get(directive), ["'none'"], `${directive} is not 'none'`)
    assert.deepEqual(policy.get('default-src'), ["'self'"])
    assert.deepEqual(policy.get('base-uri'), ["'self'"])
    assert.deepEqual(policy.get('form-action'), ["'self'"])
  }
  assert.deepEqual(production.get('script-src'), ["'self'"])
  assert.deepEqual(production.get('connect-src'), ["'self'", 'ipc:', 'http://ipc.localhost'])
  assert.deepEqual(production.get('img-src'), ["'self'", 'data:', 'asset:', 'http://asset.localhost'])
  assert.deepEqual(wdio.get('script-src'), ["'self'"])
  assert.deepEqual(wdio.get('connect-src'), ["'self'", 'ipc:', 'http://ipc.localhost', 'http://127.0.0.1:*'])
  assert.deepEqual(development.get('script-src'), ["'self'", "'unsafe-inline'", "'unsafe-eval'"])
  assert.deepEqual(development.get('connect-src'), ["'self'", 'ipc:', 'http://ipc.localhost', 'http://localhost:5173', 'ws://localhost:5173'])
})

test('the shipping style policy has no inline allowance', () => {
  const security = JSON.parse(read('src-tauri', 'tauri.conf.json')).app.security
  const production = parseContentSecurityPolicy(security.csp)
  const wdio = parseContentSecurityPolicy(JSON.parse(read('src-tauri', 'tauri.wdio.conf.json')).app.security.csp)
  assert.deepEqual(production.get('style-src'), ["'self'"])
  assert.deepEqual(wdio.get('style-src'), ["'self'"])
  assert.ok(!production.has('style-src-attr') && !production.has('style-src-elem'))
  for (const policy of [production, wdio]) {
    for (const [directive, sources] of policy) {
      assert.ok(!sources.includes("'unsafe-inline'") && !sources.includes("'unsafe-eval'"), `${directive} allows inline or eval`)
    }
  }
  const html = [read('index.html'), read('quick-access.html')].join('\n')
  assert.doesNotMatch(html, /<style[\s>]|\sstyle\s*=/, 'an entry page carries inline style the policy now blocks')
})

test('every webview navigation goes through the app origin guard', () => {
  const guard = read('src-tauri', 'src', 'adapters', 'platform', 'navigation_guard.rs').split('#[cfg(test)]')[0]
  const lib = read('src-tauri', 'src', 'lib.rs')
  const platform = read('src-tauri', 'src', 'adapters', 'platform', 'mod.rs')
  assert.match(platform, /pub\(crate\) mod navigation_guard;/)
  const single = lib.indexOf('tauri_plugin_single_instance::init')
  const registration = lib.indexOf('.plugin(adapters::platform::navigation_guard::plugin())')
  const builder = lib.indexOf('.build(tauri::generate_context!())')
  assert.ok(single >= 0 && registration > single && builder > registration, 'the guard is not registered on the application builder')
  assert.match(guard, /\.on_navigation\(\|webview, url\|/)
  assert.match(guard, /if windows \{\s*\("http", "tauri\.localhost"\)\s*\} else \{\s*\("tauri", "localhost"\)\s*\}/)
  assert.match(guard, /has_origin\(url, scheme, host, None\)/)
  assert.match(guard, /url\.username\(\)\.is_empty\(\)/)
  assert.match(guard, /url\.password\(\)\.is_none\(\)/)
  assert.match(guard, /if cfg!\(debug_assertions\) \{\s*webview\.config\(\)\.build\.dev_url\.as_ref\(\)\s*\} else \{\s*None\s*\}/)
  assert.match(guard, /is_app_url\(url, cfg!\(windows\), development_url\)/)
  assert.doesNotMatch(guard, /"https"|file:|localhost:\d|5173|"\*"|starts_with|contains\(/)
  const config = JSON.parse(read('src-tauri', 'tauri.conf.json'))
  assert.equal(config.build.devUrl, 'http://localhost:5173')
  assert.equal(config.app.windows.find((window) => window.label === 'quick-access').url, 'quick-access.html')
  assert.ok(!config.app.windows.some((window) => window.useHttpsScheme || /^[a-z]+:/.test(window.url ?? '')), 'a configured window leaves the app origin')
})

test('no webview may open a new window and the rebuilt main window denies it explicitly', () => {
  for (const path of filesMatching(/\.rs$/, join(root, 'src-tauri', 'src'))) {
    const source = readFileSync(path, 'utf8')
    const handlers = [...source.matchAll(/\.on_new_window\(([\s\S]*?)\)\s*(?:\.|;)/g)]
    for (const handler of handlers) {
      assert.match(handler[1], /NewWindowResponse::Deny/, `${relative(root, path)} lets a webview open a window`)
      assert.doesNotMatch(handler[1], /NewWindowResponse::(Allow|Create)/)
    }
  }
  const shell = read('src-tauri', 'src', 'adapters', 'platform', 'desktop_shell.rs')
  assert.match(shell, /\.on_new_window\(\|_, _\| NewWindowResponse::Deny\)\s*\.build\(\)/)
  assert.equal([...shell.matchAll(/WebviewWindowBuilder::new/g)].length, 1)
})
