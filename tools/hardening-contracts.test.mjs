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

test('release Linux builds scrub WebKit inspection variables before the Tauri builder starts', () => {
  const rust = read('src-tauri', 'src', 'lib.rs')
  const module = read('src-tauri', 'src', 'adapters', 'platform', 'webview_environment.rs')
  const platform = read('src-tauri', 'src', 'adapters', 'platform', 'mod.rs').replace(/\s+/g, '').replace(/,\)/g, ')')

  const release = /#\[cfg\(all\(target_os = "linux", not\(debug_assertions\), not\(feature = "wdio"\)\)\)\]\s*fn prepare_release_webview_environment\(\) \{\s*adapters::platform::webview_environment::remove_inspection_variables\(\);/
  assert.match(rust, release, 'the Linux release preparation does not call the scrub')
  assert.match(platform, /cfg\(any\(test,all\(target_os="linux",not\(debug_assertions\),not\(feature="wdio"\)\)\)\)\]pub\(crate\)modwebview_environment;/)
  for (const variable of [
    'TAURI_WEBVIEW_AUTOMATION',
    'WEBKIT_INSPECTOR_SERVER',
    'WEBKIT_INSPECTOR_HTTP_SERVER',
    'WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS',
    'WEBKIT_ENABLE_DEBUG_PERMISSIONS_IN_SANDBOX',
    'WEBKIT_INJECTED_BUNDLE_PATH',
  ]) {
    assert.match(module, new RegExp(`"${variable}"`), `${variable} is not scrubbed`)
  }
  assert.match(module, /BLOCKED_PREFIXES[^=]*=\s*\["JSC_"\]/)
  for (const workaround of ['WEBKIT_DISABLE_DMABUF_RENDERER', 'WEBKIT_DISABLE_COMPOSITING_MODE']) {
    assert.doesNotMatch(
      module.slice(0, module.indexOf('#[cfg(test)]')),
      new RegExp(workaround),
      `${workaround} is a rendering workaround and must stay available`,
    )
  }
  const run = rust.indexOf('pub fn run()')
  const preparation = rust.indexOf('prepare_release_webview_environment();', run)
  const builder = rust.indexOf('tauri::Builder::default()', run)
  assert.ok(run >= 0 && preparation > run && builder > preparation)
})

test('desktop updates are reported only for the systems the updater accepts', () => {
  const updater = read('src-tauri', 'src', 'commands', 'updater.rs')
  const capabilities = read('src-tauri', 'src', 'adapters', 'platform', 'capabilities.rs')

  const accepted = [...updater.match(/fn updater_platform_for\(os: &str\)[^{]*\{\s*match os \{([\s\S]*?)\n {4}\}/)[1].matchAll(/"([a-z]+)"\s*=>\s*Ok/g)].map((match) => match[1])
  const reported = [...capabilities.match(/fn desktop_updates_for\(os: &str\) -> bool \{([\s\S]*?)\n\}/)[1].matchAll(/"([a-z]+)"/g)].map((match) => match[1])

  assert.ok(accepted.length > 0, 'the updater platform check was not found')
  assert.deepEqual([...new Set(reported)].sort(), [...new Set(accepted)].sort())
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
    'clipboard-manager:allow-write-text',
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
    'sync-preview',
    'desktop-e2e',
  ])
  assert.deepEqual(quick.permissions, [
    'core:event:allow-listen',
    'core:event:allow-unlisten',
    'core:window:allow-hide',
    'core:webview:deny-internal-toggle-devtools',
    'clipboard-manager:allow-write-text',
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
