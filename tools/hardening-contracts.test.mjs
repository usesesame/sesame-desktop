import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
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

test('nothing in tools/ is left behind unreferenced', () => {
  const workflowDirectory = join(root, '.github', 'workflows')
  const referrers = [
    { name: 'package.json', text: read('package.json') },
    ...readdirSync(workflowDirectory).map((name) => ({ name, text: read('.github', 'workflows', name) })),
    ...filesMatching(/\.(mjs|js|ps1)$/, join(root, 'tools')).map((path) => ({
      name: relative(join(root, 'tools'), path),
      text: readFileSync(path, 'utf8'),
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
    'clipboard-manager:allow-write-text',
    'dialog:allow-save',
    'dialog:allow-open',
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
      'open_quick_access_item',
      'copy_secret',
      'clear_clipboard_if_unchanged',
    ],
  )

  const handler = read('src-tauri', 'src', 'lib.rs')
  const registeredCommands = [...handler.matchAll(/(?:commands::(?:[a-z0-9_]+::)*|clipboard::|desktop_shell::|website_icons::|adapters::platform::external_url::)([a-z0-9_]+),/g)]
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
  assert.match(workflow, /create-static-update-manifest\.mjs \$candidate release-handoff\/latest\.json/)
  assert.match(workflow, /SESAME_RELEASE_CANDIDATE_PUBLIC_KEY/)
  const commands = workflow
    .split('\n')
    .filter((line) => !/^\s*echo\b/.test(line))
    .join('\n')
  assert.doesNotMatch(commands, /gh release create|softprops\/action-gh-release/, 'the release workflow creates a GitHub release')
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
