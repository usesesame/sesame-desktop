import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const read = (...parts) => readFileSync(join(root, ...parts), 'utf8')
const platform = (name) => read('src-tauri', 'src', 'adapters', 'platform', name)
const config = () => JSON.parse(read('src-tauri', 'tauri.conf.json'))

function rustBrowserArguments() {
  const match = platform('webview_policy.rs').match(/pub const WEBVIEW2_BROWSER_ARGUMENTS: &str = "([^"]*)";/)
  assert.ok(match, 'webview_policy.rs must define WEBVIEW2_BROWSER_ARGUMENTS as one string literal')
  return match[1]
}

function sourceFiles(directory) {
  const found = []
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry)
    if (statSync(path).isDirectory()) found.push(...sourceFiles(path))
    else found.push(path)
  }
  return found
}

test('every window uses the browser arguments that the code passes to the main window', () => {
  const expected = rustBrowserArguments()
  const windows = config().app.windows
  assert.deepEqual(windows.map((window) => window.label).sort(), ['main', 'quick-access'])
  for (const window of windows) {
    assert.equal(window.additionalBrowserArgs, expected, `window ${window.label} must use the shared browser arguments`)
  }
  const shell = platform('desktop_shell.rs')
  assert.equal([...shell.matchAll(/\.additional_browser_args\(/g)].length, 1)
  assert.match(shell, /\.additional_browser_args\(WEBVIEW2_BROWSER_ARGUMENTS\)/)
})

test('the browser arguments keep the wry defaults and turn the JIT off once', () => {
  const expected = rustBrowserArguments()
  const wryDefaults = '--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --autoplay-policy=no-user-gesture-required'
  assert.equal(expected, `${wryDefaults} --js-flags=--jitless`)
  assert.equal(expected.match(/--js-flags/g).length, 1)
})

test('the wry version whose defaults were copied is the locked one', () => {
  const lock = read('src-tauri', 'Cargo.lock')
  const wry = lock.match(/\[\[package\]\]\nname = "wry"\nversion = "([^"]+)"/)
  assert.ok(wry, 'Cargo.lock must lock wry')
  assert.equal(wry[1], '0.55.1', 'read the new wry src/webview2/mod.rs create_environment defaults and update WEBVIEW2_BROWSER_ARGUMENTS before changing this version')
})

test('nothing shipped to the webview uses WebAssembly, which the JIT switch disables', () => {
  const files = [...sourceFiles(join(root, 'src')), join(root, 'index.html'), join(root, 'quick-access.html')]
    .filter((path) => /\.(ts|js|svelte|html|wasm)$/.test(path))
  assert.deepEqual(files.filter((path) => path.endsWith('.wasm')), [])
  const users = files.filter((path) => /WebAssembly/.test(readFileSync(path, 'utf8')) && !path.endsWith('.test.ts') && !path.endsWith('.test.mjs'))
  assert.deepEqual(users, [])
  assert.doesNotMatch(read('src-tauri', 'tauri.conf.json'), /wasm-unsafe-eval/)
})

test('both windows hide from capture unless the stored setting allows it', () => {
  const shell = platform('desktop_shell.rs')
  const policy = platform('webview_policy.rs')
  const settings = platform('desktop_settings.rs')
  assert.match(shell, /SetWindowDisplayAffinity\(hwnd\.0 as _, value\)/)
  assert.match(shell, /DisplayAffinity::ExcludeFromCapture => WDA_EXCLUDEFROMCAPTURE/)
  assert.match(shell, /\["main", "quick-access"\]/)
  assert.match(shell, /fn secure_window\(window: &WebviewWindow\) \{\n {4}harden_release_webview\(window\);[\s\S]*?set_display_affinity\(window, display_affinity\(capture_allowed\)\)/)
  assert.match(shell, /#\[cfg\(windows\)\]\nfn set_display_affinity/)
  assert.doesNotMatch(shell, /cfg\(all\(windows, not\(debug_assertions\)\)\)\]\nfn set_display_affinity/)
  assert.match(shell, /if changed == 0 \{\n\s+return Err\(/)
  assert.match(shell, /\.hwnd\(\)\n\s+\.map_err/)
  assert.match(settings, /if let Err\(error\) = apply\(requested\) \{\n\s+let _ = apply\(previous\);/)
  assert.match(policy, /if capture_allowed \{\s*DisplayAffinity::Unrestricted/)
  assert.match(settings, /#\[derive\([^)]*Default[^)]*\)\]\n#\[serde\(rename_all = "camelCase", default\)\]\npub struct DesktopSettings/)
  assert.match(settings, /is_some_and\(\|settings\| settings\.screen_capture_allowed\)/)
})

test('the capture setting commands are registered and permitted for the main window only', () => {
  const handler = read('src-tauri', 'src', 'lib.rs')
  const permissions = read('src-tauri', 'permissions', 'desktop.toml')
  const quickAccess = read('src-tauri', 'capabilities', 'quick-access.json')
  for (const command of ['get_screen_capture_allowed', 'set_screen_capture_allowed']) {
    assert.match(handler, new RegExp(`desktop_settings::${command},`))
    assert.match(permissions, new RegExp(`"${command}"`))
    assert.doesNotMatch(quickAccess, new RegExp(command))
  }
})
