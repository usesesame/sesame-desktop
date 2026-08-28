import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import test from 'node:test'

const root = process.cwd()

function read(...parts) {
  return readFileSync(join(root, ...parts), 'utf8')
}

test('the manifest directory resolution matches the packaged identifier', () => {
  const config = JSON.parse(read('src-tauri', 'tauri.conf.json'))
  const identity = read('src-tauri', 'src', 'adapters', 'platform', 'app_identity.rs')
  assert.match(identity, /pub const APP_IDENTIFIER: &str = "app\.usesesame\.desktop";/)
  assert.equal(config.identifier, 'app.usesesame.desktop')
})

test('the shipped browser host owns registration cleanup on every OS', () => {
  const config = JSON.parse(read('src-tauri', 'tauri.conf.json'))

  const hook = read('src-tauri', 'nsis', 'native-host-uninstall.nsh')
  assert.match(hook, /NSIS_HOOK_PREUNINSTALL/)
  assert.match(hook, /\$UpdateMode <> 1/)
  assert.match(hook, /ExecWait '"\$INSTDIR\\sesame-browser-host\.exe" unregister'/)
  assert.doesNotMatch(hook, /HKLM|vault\.sesame|backups|recovery|RmDir|DeleteRegKey/i)

  const scriptLines = read('src-tauri', 'linux', 'pre-remove.sh')
    .split('\n')
    .filter((line) => !/^\s*#/.test(line))
    .join('\n')
  assert.match(scriptLines, /\/usr\/bin\/sesame-browser-host unregister/)
  assert.match(scriptLines, /\[ "\$1" = "remove" \] \|\| \[ "\$1" = "0" \]/)
  assert.doesNotMatch(scriptLines, /rm /)

  assert.equal(config.bundle.linux.deb.preRemoveScript, 'linux/pre-remove.sh')
  assert.equal(config.bundle.linux.rpm.preRemoveScript, 'linux/pre-remove.sh')
  assert.equal(config.bundle.windows.nsis.installerHooks, 'nsis/native-host-uninstall.nsh')
})
