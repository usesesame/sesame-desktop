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

test('the installer pins the install directory instead of offering a choice', () => {
  const installer = read('src-tauri', 'nsis', 'installer.nsi')
  const code = installer
    .split('\n')
    .filter((line) => !/^\s*;/.test(line))
    .join('\n')

  assert.doesNotMatch(code, /MUI_PAGE_DIRECTORY/)
  assert.doesNotMatch(code, /RestorePreviousInstallLocation/)
  assert.doesNotMatch(code, /\$\{GetOptions\}\s+\$CMDLINE\s+"\/D/i)
  assert.doesNotMatch(code, /(?:ReadRegStr|ReadINIStr)\s+\$INSTDIR/)

  const onInit = code.match(/Function \.onInit\b([\s\S]*?)FunctionEnd/)
  assert.ok(onInit, 'the installer has no .onInit function, so this contract read nothing')
  assert.doesNotMatch(onInit[1], /\$INSTDIR\s*(?:==|!=)/)
  assert.match(
    onInit[1],
    /!if "\$\{INSTALLMODE\}" == "perMachine"\s*\n\s*StrCpy \$INSTDIR "\$PROGRAMFILES64\\\$\{PRODUCTNAME\}"/,
  )

  const assignments = [...code.matchAll(/StrCpy\s+\$INSTDIR\s+("[^"]*"|\S+)/g)].map((match) => match[1])
  assert.deepEqual(assignments, ['"$PROGRAMFILES64\\${PRODUCTNAME}"', '"$LOCALAPPDATA\\${PRODUCTNAME}"'])
})

test('the installer only runs a pre-existing uninstaller from an administrator-owned location', () => {
  const installer = read('src-tauri', 'nsis', 'installer.nsi')
  const code = installer
    .split('\n')
    .filter((line) => !/^\s*;/.test(line))
    .join('\n')

  const reinstall = code.match(/reinst_uninstall:([\s\S]*?)reinst_done:/)
  assert.ok(reinstall, 'reinst_uninstall was not found, so this contract read nothing')
  const block = reinstall[1]

  const recorded = block.search(/ReadRegStr \$4 SHCTX "\$\{MANUPRODUCTKEY\}" ""/)
  const canonical = block.search(/GetFullPathName \$R5 "\$4"/)
  assert.ok(recorded >= 0, 'the reinstall flow no longer reads the recorded old install directory')
  assert.ok(canonical > recorded, 'the recorded directory is not canonicalized before the trust check')
  assert.doesNotMatch(block, /StrCpy \$R3 \$4 /, 'the trust check reads the raw recorded directory')

  const prefixCheck = (name) =>
    String.raw`StrLen \$R0 "\$${name}"\s*\n\s*IntOp \$R0 \$R0 \+ 1\s*\n\s*StrCpy \$R3 \$R5 \$R0\s*\n\s*\$\{If\} \$R3 == "\$${name}\\"`
  const root64 = block.search(new RegExp(prefixCheck('PROGRAMFILES64')))
  const root32 = block.search(new RegExp(prefixCheck('PROGRAMFILES')))
  assert.ok(root64 > canonical, 'the trust check no longer matches $PROGRAMFILES64 on the canonical path')
  assert.ok(root32 > canonical, 'the trust check no longer matches $PROGRAMFILES on the canonical path')

  const gate = block.search(/\$\{If\} \$R2 = 1/)
  assert.ok(gate >= 0, 'the recorded uninstaller launch is not gated on a trust result')
  assert.ok(root64 < gate && root32 < gate, 'the launch is gated before both trust roots are checked')

  const branches = block.match(/\$\{If\} \$R2 = 1\s*\n([\s\S]*?)\n {6}\$\{Else\}\s*\n([\s\S]*?)\n {6}\$\{EndIf\}/)
  assert.ok(branches, 'the trust result has no trusted and untrusted branches')
  const [, trusted, untrusted] = branches

  assert.match(trusted, /StrCpy \$R1 '"\$R5\\uninstall\.exe"'/, 'the trusted branch does not run the uninstaller from the checked directory')
  assert.match(trusted, /StrCpy \$R1 "\$R1 _\?=\$R5"/)
  assert.match(trusted, /ExecWait '\$R1' \$0/, 'the trusted branch no longer runs the old uninstaller')
  assert.match(
    trusted,
    /\$\{If\} \$0 = 0[\s\S]*?\$\{AndIf\} \$R5 != \$INSTDIR[\s\S]*?Delete "\$R5\\uninstall\.exe"[\s\S]*?RMDir "\$R5"/,
    'the trusted branch no longer removes the leftover old uninstaller',
  )

  assert.doesNotMatch(untrusted, /Exec|RunAsUser|Delete|RMDir|Rename/i, 'the untrusted branch must neither run nor remove anything')
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

test('Windows CI builds the installer and runs its install lifecycle', () => {
  const workflow = read('.github', 'workflows', 'ci.yml')
  const windows = workflow.slice(workflow.indexOf('  desktop:'), workflow.indexOf('  desktop-linux:'))
  assert.match(windows, /npx tauri build --bundles nsis --config \$config -- --locked/)
  assert.match(windows, /createUpdaterArtifacts":false/)
  assert.match(windows, /\.\/tools\/test-windows-installer\.ps1 -InstallerPath/)

  const lifecycle = read('tools', 'test-windows-installer.ps1')
  for (const step of [/Invoke-Installer \$installer @\('\/S'\)/, /Invoke-Installer \$installer @\('\/P'\)/, /'\/S', "_\?=\$expectedDirectory"/]) {
    assert.match(lifecycle, step)
  }
  assert.match(lifecycle, /the old uninstaller outside Program Files never runs/)
  assert.match(lifecycle, /nothing is removed from the old directory/)
  assert.match(lifecycle, /the old uninstaller inside Program Files runs/)
  assert.match(lifecycle, /a traversal path into Program Files does not run the old uninstaller/)
})
