import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

// Salvaged from the former monorepo workspace suite when the products split.
// These read only files this repository owns.

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const read = (...parts) => readFileSync(join(root, ...parts), 'utf8')

test('the version gate supports a Cargo workspace before the desktop package', () => {
  const cargo = read('src-tauri', 'Cargo.toml')
  assert.match(cargo, /^\[workspace\]$/m)
  assert.match(cargo, /^\[package\]$/m)
  assert.doesNotThrow(() => {
    execFileSync(process.execPath, [join(root, 'tools', 'version-contract.mjs'), 'check'], {
      cwd: root,
      encoding: 'utf8',
    })
  })
})

test('the installer owns its own template and never offers to delete app data', () => {
  // Stock Tauri 2.11.4 NSIS "Delete app data" checkbox recursively deletes %LOCALAPPDATA%, which holds the live vault and every backup.
  const config = JSON.parse(read('src-tauri', 'tauri.conf.json'))
  assert.equal(config.bundle.windows.nsis.template, 'nsis/installer.nsi')
  assert.equal(config.bundle.windows.allowDowngrades, false)
  assert.equal(config.bundle.windows.webviewInstallMode.type, 'embedBootstrapper')
  assert.equal(config.bundle.windows.webviewInstallMode.silent, true)

  const installer = read('src-tauri', 'nsis', 'installer.nsi')

  assert.match(installer, /Derived from the Tauri 2\.11\.4 stock template/)

  const code = installer
    .split('\n')
    .filter((line) => !/^\s*;/.test(line))
    .join('\n')

  assert.doesNotMatch(code, /deleteAppData/i)
  assert.doesNotMatch(code, /DeleteAppDataCheckbox/)
  assert.doesNotMatch(code, /__NSD_CheckBox/)
  assert.doesNotMatch(code, /BM_GETCHECK/)

  assert.doesNotMatch(code, /rmdir\s+\/r(?![a-z])/i)

  assert.doesNotMatch(code, /\$APPDATA\\\$\{BUNDLEID\}/)
  assert.doesNotMatch(code, /\$LOCALAPPDATA\\\$\{BUNDLEID\}/)

  assert.match(code, /\$\{If\} \$\{Silent\}\s*\$\{AndIf\} \$R0 = 0\s*Goto reinst_done/)
  assert.match(code, /\$\{ElseIf\} \$R0 = -1[\s\S]*SetErrorLevel 3\s*Quit[\s\S]*!insertmacro MUI_HEADER_TEXT/)
  assert.match(code, /Section EarlyChecks[\s\S]*SetErrorLevel 3\s*Quit[\s\S]*SectionEnd/)
})

test('Windows executables use a safe DLL search order and install per-machine', () => {
  const cargo = read('src-tauri', 'Cargo.toml')
  const desktop = read('src-tauri', 'src', 'lib.rs')
  const policy = read('src-tauri', 'src', 'adapters', 'platform', 'dll_search.rs')
  const config = JSON.parse(read('src-tauri', 'tauri.conf.json'))
  const template = read('src-tauri', 'nsis', 'installer.nsi')

  assert.match(cargo, /Win32_System_LibraryLoader/)
  assert.match(policy, /SetDefaultDllDirectories\(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS\)/)
  assert.match(policy, /std::io::Error::last_os_error\(\)/)
  assert.match(desktop, /pub fn run\(\) \{[\s\S]*?dll_search::harden_process\(\)[\s\S]*?prepare_release_webview_environment\(\)/)
  assert.match(desktop, /pub fn run_browser_host\(\) \{[\s\S]*?dll_search::harden_process\(\)[\s\S]*?browser_host::run\(\)/)
  assert.equal(config.bundle.windows.nsis.installMode, 'perMachine')
  assert.match(template, /!if "\$\{INSTALLMODE\}" == "perMachine"\s*\n {2}RequestExecutionLevel admin/)
})

test('the Windows uninstaller removes only Sesame native-host registration', () => {
  const config = JSON.parse(read('src-tauri', 'tauri.conf.json'))
  assert.equal(config.bundle.windows.nsis.installerHooks, 'nsis/native-host-uninstall.nsh')
  const hook = read('src-tauri', 'nsis', 'native-host-uninstall.nsh')
  assert.match(hook, /NSIS_HOOK_PREUNINSTALL/)
  assert.match(hook, /\$UpdateMode <> 1/)
  assert.match(hook, /ExecWait '"\$INSTDIR\\sesame-browser-host\.exe" unregister'/)
  assert.doesNotMatch(hook, /vault\.sesame|backups|recovery|HKLM|RmDir|DeleteRegKey/i)
})

test('installer lifecycle evidence scripts emit and compare file rows', { timeout: 30_000 }, (t) => {
  const collectorPath = join(root, 'tools', 'collect-installer-lifecycle-evidence.ps1')
  const comparerPath = join(root, 'tools', 'compare-installer-lifecycle-evidence.ps1')
  const collector = readFileSync(collectorPath, 'utf8')
  const comparer = readFileSync(comparerPath, 'utf8')

  assert.match(collector, /\[pscustomobject\]\[ordered\]@\{/)
  assert.match(collector, /relativePath\s*=/)
  assert.match(collector, /sha256\s*=/)
  assert.match(comparer, /missing required column/)
  assert.match(comparer, /\$changes = @\(foreach/)

  if (process.platform !== 'win32') {
    t.skip('PowerShell behavior contract runs on Windows')
    return
  }

  const scratch = mkdtempSync(join(tmpdir(), 'sesame-evidence-contract-'))
  try {
    const localAppData = join(scratch, 'local-app-data')
    const dataRoot = join(localAppData, 'app.usesesame.desktop')
    const outputRoot = join(scratch, 'evidence')
    mkdirSync(dataRoot, { recursive: true })
    writeFileSync(join(dataRoot, 'vault.sesame'), 'fictional-vault-state-one')
    mkdirSync(join(dataRoot, 'EBWebView'), { recursive: true })
    mkdirSync(join(dataRoot, 'logs'), { recursive: true })
    mkdirSync(join(dataRoot, 'native-messaging'), { recursive: true })
    writeFileSync(join(dataRoot, 'EBWebView', 'volatile-cache'), 'changes while the app runs')
    writeFileSync(join(dataRoot, 'logs', 'sesame.log'), 'fictional diagnostic')
    writeFileSync(join(dataRoot, 'native-messaging', 'app.usesesame.browser.json'), '{}')

    const collect = (label) => {
      const output = execFileSync(
        'powershell.exe',
        ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', collectorPath, '-Label', label, '-OutputRoot', outputRoot],
        { cwd: root, encoding: 'utf8', env: { ...process.env, LOCALAPPDATA: localAppData } },
      )
      return output.trim().split(/\r?\n/).at(-1)
    }

    const before = collect('before')
    const policy = JSON.parse(readFileSync(join(before, 'collector-policy.json'), 'utf8').replace(/^\uFEFF/, ''))
    const manifest = readFileSync(join(before, 'data-files.csv'), 'utf8')
    assert.match(manifest, /"relativePath","length","lastWriteTimeUtc","sha256"/)
    assert.match(
      manifest,
      /"vault\.sesame"/,
      `the manifest has no vault row. The collector read ${policy.dataRoot} from LOCALAPPDATA`,
    )
    assert.match(
      manifest,
      /"native-messaging\\app\.usesesame\.browser\.json"/,
      `the manifest has no native host manifest row. The collector read ${policy.dataRoot}`,
    )
    assert.doesNotMatch(manifest, /EBWebView|sesame\.log/)
    assert.doesNotMatch(manifest, /"Count","Keys","Values"/)
    assert.deepEqual(policy.excludedTopLevelRoots, ['EBWebView', 'logs'])
    const nativeHost = JSON.parse(readFileSync(join(before, 'native-host-state.json'), 'utf8').replace(/^\uFEFF/, ''))
    assert.equal(nativeHost.manifestExists, true)

    writeFileSync(join(dataRoot, 'vault.sesame'), 'fictional-vault-state-two')
    const after = collect('after')
    const comparison = join(scratch, 'comparison.csv')
    execFileSync(
      'powershell.exe',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', comparerPath, '-Before', before, '-After', after, '-OutputPath', comparison],
      { cwd: root, encoding: 'utf8' },
    )
    assert.match(readFileSync(comparison, 'utf8'), /"vault\.sesame","Changed"/)
  } finally {
    rmSync(scratch, { recursive: true, force: true })
  }
})

test('the installer never launches an executable through an unquoted path', () => {
  // An unquoted $TEMP path lets a writable "C:\Users\First.exe" run instead of the bootstrapper during elevated installs.
  const installer = read('src-tauri', 'nsis', 'installer.nsi')
  const code = installer
    .split('\n')
    .filter((line) => !/^\s*;/.test(line))
    .join('\n')

  const launches = [...code.matchAll(/^\s*ExecWait\s+(.+)$/gm)].map((match) => match[1].trim())
  assert.ok(launches.length > 0, 'no ExecWait lines were found, so this contract read nothing')
  for (const launch of launches) {
    const quotedExecutable = /^['"`]?"\$\w+"/.test(launch)
    const wholeCommandInOneVariable = /^['"`]\$\w+['"`]\s*\$\d$/.test(launch)
    assert.ok(
      quotedExecutable || wholeCommandInOneVariable,
      `ExecWait launches an executable through an unquoted path: ${launch}`,
    )
  }
})
