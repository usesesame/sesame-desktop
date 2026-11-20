import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import { unexpectedRegistryOperations } from './installer-registry-allowlist.mjs'

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
  assert.doesNotMatch(hook, /vault\.sesame|backups|recovery|RmDir|DeleteRegKey|DeleteRegValue|HKCU/i)
  assert.deepEqual(unexpectedRegistryOperations(hook), [])
})

test('the hook allowlist refuses every machine registry operation', () => {
  const allowed = 'WriteRegStr SHCTX "${MANUPRODUCTKEY}" "${SESAME_PATH_STATUS_VALUE}" "$0"'
  assert.deepEqual(unexpectedRegistryOperations(allowed), [])
  for (const line of [
    'ReadRegStr $R0 HKLM "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment" "Path"',
    'WriteRegExpandStr HKEY_LOCAL_MACHINE "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment" "Path" "$R1"',
    'WriteRegStr hkey_local_machine "Software\\Fictional" "Value" "1"',
    'WriteRegStr SHCTX "${MANUPRODUCTKEY}" "Other" "1"',
    'WriteRegStr SHCTX "${MANUPRODUCTKEY}" "${SESAME_PATH_STATUS_VALUE}" "$1"',
    "System::Call 'advapi32::RegSetValueExW(p 0x80000002, w \"Software\\Fictional\")'",
    'DeleteRegValue HKLM "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment" "Path"',
  ]) {
    assert.equal(unexpectedRegistryOperations(line).length, 1, line)
  }
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
  assert.match(collector, /GetValue\('Path', \$null, \[Microsoft\.Win32\.RegistryValueOptions\]::DoNotExpandEnvironmentNames\)/, 'the collector must record the machine Path as stored, without expanding it')
  assert.match(collector, /GetValueKind\('Path'\)/)
  assert.match(collector, /'machine-path\.json'/)
  assert.match(collector, /\$excludedDataRoots = @\('EBWebView', 'quick-access-webview', 'logs'\)/, 'only the WebView2 profiles and the logs may be left out of the data comparison')
  assert.match(collector, /if \(-not \(Test-HeldByAnotherProcess \$_\.Exception\)\) \{ throw \}\s+\$status = 'locked'/, 'a file another process holds open must be recorded as locked, and every other error must still stop the collector')
  assert.match(collector, /\$code -eq 32 -or \$code -eq 33/)
  assert.match(comparer, /\$old\.status -eq 'locked' -or \$new\.status -eq 'locked'\) \{\s+\[pscustomobject\]\[ordered\]@\{ relativePath = \$path; status = 'Unverified'/, 'a locked file must be reported as unverified, never as unchanged')
  assert.match(collector, /-Name 'TerminalPathAdded'/)
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
    mkdirSync(join(dataRoot, 'quick-access-webview', 'EBWebView', 'Default'), { recursive: true })
    writeFileSync(join(dataRoot, 'quick-access-webview', 'EBWebView', 'Default', 'DIPS'), 'fictional profile state')
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
    assert.doesNotMatch(manifest, /EBWebView|quick-access-webview|sesame\.log/)
    assert.match(manifest, /"vault\.sesame","\d+","[^"]+","[0-9a-f]{64}","hashed"/)
    assert.doesNotMatch(manifest, /"Count","Keys","Values"/)
    assert.deepEqual(policy.excludedTopLevelRoots, ['EBWebView', 'quick-access-webview', 'logs'])
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
  const windows = workflow.slice(workflow.indexOf('  windows-installer:'), workflow.indexOf('  desktop:'))
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

  const steps = windows.indexOf('./tools/test-windows-installer.ps1')
  const commandLine = windows.indexOf('./tools/test-windows-command-line-install.ps1 -InstallerPath')
  assert.ok(commandLine > steps, 'CI no longer checks the command line tool on the machine Path after the install lifecycle')
  assert.match(windows.slice(commandLine), /-EvidenceRoot \(Join-Path \$env:RUNNER_TEMP 'command-line-install-evidence'\)/)
  assert.match(windows, /name: Check the command line tool on the machine Path\s+shell: powershell\s+timeout-minutes: \d+/)
  assert.match(windows, /uses: actions\/upload-artifact@[0-9a-f]{40} # v[\d.]+\s+if: always\(\)\s+with:\s+name: windows-command-line-install-evidence\s+path: \$\{\{ runner\.temp \}\}\/command-line-install-evidence/, 'the evidence must be uploaded when the check fails too')
})

test('the command line install test guards the machine Path and checks what the hook claims', () => {
  const script = read('tools', 'test-windows-command-line-install.ps1')
  const client = read('src-tauri', 'src', 'terminal_client.rs')
  const protocol = read('src-tauri', 'sesame-app', 'src', 'cli_protocol.rs')
  const broker = read('src-tauri', 'sesame-app', 'src', 'application', 'cli_broker.rs')
  const pipe = read('src-tauri', 'src', 'adapters', 'platform', 'browser_pipe', 'windows.rs')

  const refusal = script.indexOf("$env:GITHUB_ACTIONS -ne 'true' -and -not $AllowMachinePathChanges")
  const saved = script.indexOf('$originalPath = Get-MachinePath')
  const firstWrite = script.search(/^\s*Set-MachinePath \$/m)
  assert.ok(refusal > 0, 'the test must refuse to run outside CI without a flag')
  assert.ok(saved > refusal, 'the original Path is not saved right after the CI check')
  assert.ok(firstWrite > saved, 'the test writes the machine Path before it saves the original')
  const outerTry = script.search(/^try \{$/m)
  assert.ok(outerTry > saved, 'the test has no outer try after it saves the original Path')
  for (const prerequisite of [
    "if (Get-UninstallKey) { throw 'Sesame is already installed",
    'if (Get-PathRecord) { throw',
    'if (Test-Path -LiteralPath $installDirectory) { throw',
  ]) {
    const at = script.indexOf(prerequisite)
    assert.ok(at > 0 && at < outerTry, `${prerequisite} must stop the test before the cleanup in its finally block can remove an installation it did not create`)
  }
  assert.match(script, /\} finally \{\s+\$script:scenario = 'final restore'[\s\S]*Set-MachinePath \$originalPath\.Value \$originalPath\.Kind/, 'a failed run does not restore the runner Path')
  assert.match(script, /function Invoke-Scenario[\s\S]*?\} finally \{[\s\S]*?Set-MachinePath \$originalPath\.Value \$originalPath\.Kind/, 'a failed scenario does not restore the runner Path')
  assert.match(script, /OpenSubKey\(\$environmentKeyPath, \$true\)/)
  assert.equal((script.match(/OpenSubKey\([^)]*\$true\)/g) ?? []).length, 1, 'the test opens a registry key for writing outside the one machine Path helper')
  assert.doesNotMatch(script, /SetEnvironmentVariable|HKCU:\\Environment|setx/i, 'the test must never write the user Path')
  assert.match(script, /Confirm-That 'the user Path is untouched'/)

  const constant = (source, name) => {
    const match = source.match(new RegExp(`const ${name}: [^=]+= ([^;]+);`))
    assert.ok(match, `${name} is no longer defined`)
    return match[1].trim()
  }
  const quoted = (value) => value.replace(/^"|"$/g, '')
  assert.match(script, new RegExp(`\\$exitUnreachable = ${constant(client, 'EXIT_UNREACHABLE')}\\b`))
  assert.match(script, new RegExp(`\\$exitTimeout = ${constant(client, 'EXIT_TIMEOUT')}\\b`))
  assert.ok(script.includes(`$notRunningMessage = '${quoted(constant(client, 'NOT_RUNNING'))}'`), 'the not running message no longer matches the tool')
  assert.ok(client.includes(`"Unlock Sesame to continue."`) && script.includes(`$unlockWaitingMessage = 'Unlock Sesame to continue.'`))
  assert.match(protocol, /Self::Timeout => "Nobody answered in Sesame\."/)
  assert.ok(script.includes(`$timeoutMessage = 'Nobody answered in Sesame.'`))
  const unlockSeconds = Number(broker.match(/CLI_UNLOCK_TIMEOUT: Duration = Duration::from_secs\((\d+)\)/)[1])
  const clientSeconds = Number(pipe.match(/const TERMINAL_REPLY_TIMEOUT: Duration = Duration::from_secs\((\d+)\)/)[1])
  assert.match(script, new RegExp(`\\$unlockWaitSeconds = ${unlockSeconds}\\b`))
  assert.match(script, new RegExp(`\\$clientDeadlineSeconds = ${clientSeconds}\\b`))
  const limit = Number(script.match(/\$requestLimitSeconds = (\d+)/)[1])
  assert.ok(limit > clientSeconds && limit < clientSeconds + 60, 'the bounded wait for sesame list must outlast the tool deadline by a little')
  assert.ok(script.includes(String.raw`'\\.\pipe\'`) && script.includes(String.raw`'*\Sesame.Cli.*'`), 'the test no longer waits for the terminal pipe the desktop opens')
  assert.match(pipe, /pipe_prefix: "Sesame\.Cli"/)

  assert.match(script, /\$info\.EnvironmentVariables\['Path'\] = \$PathValue/, 'the tool must run with a Path rebuilt from the registry, not the stale one of this process')
  assert.match(script, /Invoke-SessionCommand 'where sesame'/)
  for (const command of ['sesame --help', 'sesame --version', 'sesame list']) {
    assert.ok(script.includes(`Invoke-SessionCommand '${command}'`), `the test no longer runs ${command}`)
  }
  assert.match(script, /'console'[\s\S]*'windows'/)
  for (const scenario of [
    'Passive install and passive uninstall',
    "Invoke-ExistingEntryScenario 'in the same form' $terminalFolder",
    "Invoke-ExistingEntryScenario 'with a trailing backslash' \"$terminalFolder\\\"",
    "Invoke-ExistingEntryScenario 'in different letter case' $terminalFolder.ToUpperInvariant()",
    'Path holds the entry twice at uninstall',
    "Path of type REG_SZ' $basePath 'String'",
    'Path that ends with a semicolon',
    "Uninstall-Sesame @('/S', '/UPDATE')",
    "Install-Sesame @('/S', '/UPDATE')",
    "Install-Sesame @('/P')",
    "foreach ($length in @(994, 995, 1022, 1023, 1024, 4096)) {",
    'Path that reaches $machinePathLimit characters with the entry',
    "Confirm-LookupFromNewCommandShell 'the install with a default user Path' $joined",
    "Remove-Item -LiteralPath $probeFolder -Recurse -Force",
    'if ($script:halted) {',
    'Wait-UninstallCopy $launched',
    "Confirm-LookupFromNewCommandShell 'the install' $session",
    'Path one character too long to add the entry without passing $machinePathLimit characters',
    "Confirm-Status \"an install that would pass $machinePathLimit characters\" $installed $statusNoRoom",
    "Confirm-LookupFromNewCommandShell 'a refused install' \"$(Get-MachineSessionPath $installed);$defaultUserPath\" -WithoutTool",
    'Path already past $machinePathLimit characters',
    'keeps PATH but finds no command through it, not even in the first entry',
    "The runner's own Path",
    "Invoke-ExistingEntryScenario 'in quotes'",
    "Invoke-ExistingEntryScenario 'written with %ProgramFiles%' '%ProgramFiles%\\Sesame\\cli'",
    'A Path edit that fails leaves the install working',
    "Set-MachinePath ($basePath.Replace(';', \"`n\")) 'MultiString'",
    "Confirm-Status 'an install whose Path edit fails' $installed $statusFailed",
    'Confirm-PathModeRefusals $installed.machinePath',
    "/trustlevel:0x20000",
    "sesame --help does not list the installer arguments",
    'A silent uninstall whose Path edit fails finishes and keeps the record',
    "Confirm-Status 'the next install' $again $statusUnchanged",
    "Confirm-RecordAdded 'a silent uninstall whose Path edit fails' $finished",
    "Confirm-RecordAdded 'a deployment uninstall whose Path edit fails' $ended",
    "Confirm-That 'a deployment uninstall whose Path edit fails exits 0' ($code -eq 0)",
    'An uninstall after someone else removed the entry',
    "Confirm-LookupFromNewCommandShell 'the install'",
    "Invoke-SessionCommand 'whoami'",
    'the longest that leaves room for the entry',
    'too long to add the entry',
    "Confirm-Status \"an install that would pass $environmentLimit characters\" $installed $statusNoRoom",
    'Invoke-CommandShellLimitScenario',
    'Register-BrowserHost',
    'a silent uninstall whose Path edit fails still removes the browser registration',
    'A deployment that runs uninstall.exe /S and waits when the Path edit fails',
    'Write-Host ("deployment uninstall: uninstall.exe /S exited {0}',
    "'call fictional-early-probe'",
    "'call fictional-late-probe'",
    'if defined PATH (echo cmd sees PATH) else (echo cmd sees no PATH)',
  ]) {
    assert.ok(script.includes(scenario), `the test no longer covers ${scenario}`)
  }
  assert.doesNotMatch(script, /Confirm-PathUnchanged 'an install that must not write Path'/, 'a long Path must get the entry like any other')
  const pure = read('src-tauri', 'src', 'machine_path.rs')
  const status = (name) => pure.match(new RegExp(`pub const ${name}: i32 = (\\d+);`))[1]
  assert.ok(script.includes(`$statusChanged = '${status('EXIT_CHANGED')}'`))
  assert.ok(script.includes(`$statusUnchanged = '${status('EXIT_UNCHANGED')}'`))
  assert.ok(script.includes(`$statusRefused = ${status('EXIT_REFUSED')}`))
  assert.ok(script.includes(`$statusFailed = '${status('EXIT_FAILED')}'`))
  assert.ok(script.includes(`$statusNoRoom = '${status('EXIT_NO_ROOM')}'`))
  assert.ok(script.includes(`$longestUserName = ${pure.match(/pub const LONGEST_USER_NAME: usize = (\d+);/)[1]}`))
  assert.ok(script.includes('$defaultUserPathAllowance = 67') && pure.includes('r"C:\\Users\\".len()') && pure.includes('r"\\AppData\\Local\\Microsoft\\WindowsApps".len()'), 'the test and the cli program no longer reserve the same room for a default user Path')
  assert.match(pure, /pub const MACHINE_PATH_LIMIT: usize = COMMAND_SHELL_LIMIT - DEFAULT_USER_PATH_ALLOWANCE;/)
  assert.match(pure, /if expanded_length\(value, lookup\) <= MACHINE_PATH_LIMIT\s+&& expanded_length\(&written, lookup\) > MACHINE_PATH_LIMIT/)
  assert.ok(script.includes(`$environmentLimit = ${pure.match(/pub const MAX_VALUE_UNITS: usize = ([\d_]+);/)[1].replaceAll('_', '')}`), 'the test no longer places its longest Path at the limit the cli program enforces')
  assert.ok(script.includes(`$commandShellLineLimit = ${pure.match(/pub const COMMAND_SHELL_LIMIT: usize = ([\d_]+);/)[1].replaceAll('_', '')}`), 'the test no longer checks the cmd.exe limit the cli program enforces')
  assert.match(script, /\$basePath = '%SystemRoot%\\system32;%SystemRoot%;/)
})

test('the Windows installer hands the system Path to the cli program and records only what it added', () => {
  const hook = read('src-tauri', 'nsis', 'native-host-uninstall.nsh')
  const windowsConfig = JSON.parse(read('src-tauri', 'tauri.windows.conf.json'))
  const config = JSON.parse(read('src-tauri', 'tauri.conf.json'))
  const pure = read('src-tauri', 'src', 'machine_path.rs')
  const native = read('src-tauri', 'src', 'adapters', 'platform', 'system_path.rs')
  const lib = read('src-tauri', 'src', 'lib.rs')
  const client = read('src-tauri', 'src', 'terminal_client.rs')
  assert.deepEqual(windowsConfig.bundle.resources, { 'binaries/cli/sesame.exe': 'cli/sesame.exe' })
  assert.match(hook, /!define SESAME_TERMINAL_FOLDER "\$INSTDIR\\cli"/)
  assert.doesNotMatch(hook, /NSIS_MAX_STRLEN|System::Call|HKLM|Session Manager|StrLen|WriteRegExpandStr/, 'the hook must not edit Path through NSIS strings, which stop at 1024 characters')

  const macro = (name) => {
    const match = hook.match(new RegExp(`!macro ${name}\\b[\\s\\S]*?!macroend`))
    assert.ok(match, `the hook has no ${name} macro`)
    return match[0]
  }
  const constant = (name) => pure.match(new RegExp(`pub const ${name}: [^=]+= ([^;]+);`))?.[1].trim().replace(/^"|"$/g, '')
  const add = macro('SESAME_ADD_TERMINAL_PATH')
  assert.ok(add.includes(`ExecWait '"$INSTDIR\\cli\\sesame.exe" ${constant('ADD_ARGUMENT')}' $0`), 'setup no longer asks the cli program to add its folder')
  assert.match(add, /ClearErrors\s+ExecWait[^\n]+\s+\$\{If\} \$\{Errors\}\s+StrCpy \$0 "not started"/, 'a program that did not start could read as success')
  assert.match(add, new RegExp(`\\$\\{If\\} \\$0 == "${constant('EXIT_CHANGED')}"\\s+ClearErrors\\s+WriteRegStr SHCTX "\\$\\{MANUPRODUCTKEY\\}" "\\$\\{SESAME_PATH_OWNER_VALUE\\}" "\\$\\{SESAME_TERMINAL_FOLDER\\}"\\s+\\$\\{If\\} \\$\\{Errors\\}\\s+ClearErrors\\s+ExecWait '"\\$INSTDIR\\\\cli\\\\sesame\\.exe" ${constant('REMOVE_ARGUMENT')}' \\$1`), 'Sesame records an entry it did not add, or keeps an entry it could not record')
  assert.match(add, new RegExp(`\\$\\{ElseIf\\} \\$0 == "${constant('EXIT_NO_ROOM')}"\\s+DetailPrint "[^"]*Remove entries you no longer need from the Path first, then add the folder[^"]*"`), 'a Path with no room must tell the person to make room before adding the folder')
  assert.match(add, /Push \$0\s+Push \$1[\s\S]*Pop \$1\s+Pop \$0\s+!macroend/)
  assert.match(add, new RegExp(`\\$\\{ElseIf\\} \\$0 == "${constant('EXIT_UNCHANGED')}"`))
  assert.match(add, /WriteRegStr SHCTX "\$\{MANUPRODUCTKEY\}" "\$\{SESAME_PATH_STATUS_VALUE\}" "\$0"/, 'the outcome of the Path edit is not recorded where a test can read it')
  assert.doesNotMatch(add, /Abort|Quit|SetErrorLevel/, 'a failed Path edit must not fail the install')
  assert.match(add, /\$\{Else\}\s+DetailPrint "Sesame could not add \$\{SESAME_TERMINAL_FOLDER\} to the system Path\. Add it by hand to use the sesame command\."/, 'a refused or failed add must tell the person to add the folder themselves')
  assert.equal((hook.match(/WriteRegStr SHCTX "\$\{MANUPRODUCTKEY\}" "\$\{SESAME_PATH_OWNER_VALUE\}"/g) ?? []).length, 2)
  assert.match(macro('NSIS_HOOK_POSTUNINSTALL'), /^!macro NSIS_HOOK_POSTUNINSTALL\s+\$\{If\} \$SesameTerminalPathLeft = 1\s+ClearErrors\s+WriteRegStr SHCTX "\$\{MANUPRODUCTKEY\}" "\$\{SESAME_PATH_OWNER_VALUE\}" "\$\{SESAME_TERMINAL_FOLDER\}"\s+\$\{If\} \$\{Errors\}\s+DetailPrint "[^"]*Remove the entry by hand\."\s+\$\{Else\}\s+DetailPrint "[^"]+"\s+\$\{EndIf\}\s+\$\{EndIf\}\s+!macroend$/, 'the record of the entry may only come back after an uninstall that could not remove it')

  const remove = macro('SESAME_REMOVE_TERMINAL_PATH')
  assert.match(remove, /\$\{If\} \$UpdateMode <> 1\s+\$\{AndIf\} \$SesameOwnsTerminalPath S== "\$\{SESAME_TERMINAL_FOLDER\}"/, 'uninstall removes a Path entry Sesame did not add, or removes it during an update')
  assert.match(remove, new RegExp(`\\$\\{ElseIf\\} \\$0 == "${constant('EXIT_UNCHANGED')}"\\s+DetailPrint "The system Path no longer holds [^"]*left it as it was\\."`), 'an entry that is already gone must not ask the person to remove it')
  assert.match(remove, new RegExp(`\\$\\{ElseIf\\} \\$0 == "${constant('EXIT_LEFT_FOR_PERSON')}"\\s+DetailPrint "[^"]*Remove the entries you no longer need by hand\\."`), 'an entry Sesame left in place must tell the person to remove it')
  const failure = remove.slice(remove.indexOf(`$0 == "${constant('EXIT_LEFT_FOR_PERSON')}"`))
  assert.match(failure, /\$\{Else\}\s+DetailPrint[^\n]+\s+StrCpy \$SesameTerminalPathLeft 1\s+\$\{IfNot\} \$\{Silent\}\s+\$\{AndIf\} \$PassiveMode <> 1\s+MessageBox MB_ICONEXCLAMATION\|MB_ABORTRETRYIGNORE "[^"]+" IDRETRY sesame_remove_terminal_path IDIGNORE sesame_remove_terminal_path_done\s+Pop \$0\s+Abort "[^"]+"\s+\$\{EndIf\}\s+\$\{EndIf\}\s+sesame_remove_terminal_path_done:\s+Pop \$0/, 'a removal that fails must offer a retry in the window, and a silent or passive run must finish without a dialog and keep the record')
  assert.match(remove, /Push \$0\s+sesame_remove_terminal_path:\s+StrCpy \$SesameTerminalPathLeft 0\s+ClearErrors\s+ExecWait/, 'a retry must run the cli program again and forget the earlier failure')
  assert.doesNotMatch(remove.slice(0, remove.indexOf('${Else}')), /Abort|MessageBox/, 'an outcome that changed or left the Path must not stop the uninstall')
  assert.ok(remove.includes(`ExecWait '"$INSTDIR\\cli\\sesame.exe" ${constant('REMOVE_ARGUMENT')}' $0`))
  assert.doesNotMatch(remove, /WriteReg|DeleteReg/)
  assert.match(macro('NSIS_HOOK_POSTINSTALL'), /!insertmacro SESAME_ADD_TERMINAL_PATH/)
  assert.match(macro('NSIS_HOOK_PREUNINSTALL'), /ReadRegStr \$SesameOwnsTerminalPath SHCTX "\$\{MANUPRODUCTKEY\}" "\$\{SESAME_PATH_OWNER_VALUE\}"/)
  assert.deepEqual(unexpectedRegistryOperations(hook), [])

  assert.match(lib, /#\[cfg\(windows\)\]\s+if let Some\(request\) = machine_path::requested\(&arguments\) \{\s+return adapters::platform::system_path::run\(request\);\s+\}\s+terminal_client::run_from_environment/, 'the Path mode must end the program before the terminal client can start')
  assert.match(lib, /pub fn run_terminal_client\(\) -> i32 \{\s+if dll_search::harden_process\(\)\.is_err\(\)/, 'the Path mode must run only after the process is hardened')
  assert.match(pure, /if arguments\.len\(\) == 1 \{\s+Some\(Request::Run\(mode\)\)\s+\} else \{\s+Some\(Request::Malformed\)/, 'the Path mode accepts more than its one argument')
  assert.doesNotMatch(client, /machine-path/, 'the terminal help must not list the installer arguments')
  const run = native.slice(native.indexOf('pub fn run(request: Request)'))
  assert.ok(run.indexOf('is_elevated()') > 0 && run.indexOf('is_elevated()') < run.indexOf('own_install()'), 'the Path mode does not refuse a process that is not elevated first')
  assert.match(native, /read != 0 && elevation\.TokenIsElevated != 0 && is_administrator\(\)/, 'an elevated token whose Administrators group is deny only must be refused')
  assert.match(native, /CreateWellKnownSid\(\s*WinBuiltinAdministratorsSid,[\s\S]*?CheckTokenMembership\(ptr::null_mut\(\), sid\.as_mut_ptr\(\)\.cast\(\), &mut member\)/)
  assert.match(native, /fn own_install\(\) -> Result<Install, String> \{[\s\S]*?program_files\(\)[\s\S]*?current_exe\(\)\.and_then\(std::fs::canonicalize\)[\s\S]*?std::fs::canonicalize\(&expected\)/, 'the Path mode must add only the folder of its own installed copy')
  assert.match(native, /"ProgramFilesDir"/)
  assert.match(native, new RegExp(`const PRODUCT_FOLDER: &str = "${config.productName}";`))
  assert.doesNotMatch(native, /args_os|std::env::args|cli_protocol|browser_pipe|vault|sesame_app/, 'the Path mode must take nothing from its arguments and stay apart from the vault protocol')
  assert.match(native, /Ok\(\(again_kind, again\)\) if again_kind == kind && again == bytes => \{\}\s+Ok\(_\) => continue/, 'the Path is not compared again just before it is written')
  assert.match(native, /RegSetValueExW\(\s*key\.0,\s*value_name\.as_ptr\(\),\s*0,\s*kind,/, 'the Path type is not kept')
  assert.match(native, /WM_SETTINGCHANGE/)
  assert.match(native, /fn broadcast\(\) \{[\s\S]*?std::thread::Builder::new\(\)\.spawn\(move \|\| \{[\s\S]*?SendMessageTimeoutW\([\s\S]*?\}\);\s+if sent\.is_ok\(\) \{\s+let _ = done\.recv_timeout\(BROADCAST_DEADLINE\);/, 'the wait for the environment broadcast must have one overall deadline')
  assert.match(native, /broadcast\(\);\s+return EXIT_CHANGED;/, 'a committed write must still report that it changed the Path')
  assert.match(native, /machine_reference\(name, &install\.program_files, &machine, &system\)/, 'references in the Path must resolve with the machine environment')
  assert.match(native, /return left_alone_code\(&other\);/)
  assert.match(native, /const _: \(\) = assert!\(ERROR_ACCESS_DENIED == ACCESS_DENIED\);/)
  assert.equal((native.match(/return registry_failure\(status, "(?:open the system environment|write the system Path)"\);/g) ?? []).length, 2, 'access denied on the open or the write must read as a refusal')
  assert.match(read('.github', 'SECURITY.md'), /--add-to-machine-path/, 'SECURITY.md does not describe the installer Path mode')
})

test('a cancelled Windows uninstall never reaches the Path cleanup', () => {
  const hook = read('src-tauri', 'nsis', 'native-host-uninstall.nsh')
  const code = read('src-tauri', 'nsis', 'installer.nsi')
    .split('\n')
    .filter((line) => !/^\s*;/.test(line))
    .join('\n')

  assert.doesNotMatch(hook, /!insertmacro SESAME_REMOVE_TERMINAL_PATH/, 'the hook runs the Path cleanup itself, outside the place the template chose for it')
  const postUninstall = hook.match(/!macro NSIS_HOOK_POSTUNINSTALL\b[\s\S]*?!macroend/)
  assert.ok(postUninstall, 'the hook no longer restores the record after a cleanup that failed')
  assert.doesNotMatch(postUninstall[0], /ExecWait|SESAME_REMOVE_TERMINAL_PATH|Abort|MessageBox/, 'the Path cleanup would run after cli\\sesame.exe is deleted')
  assert.equal((code.match(/!insertmacro SESAME_REMOVE_TERMINAL_PATH\b/g) ?? []).length, 1, 'the template runs the Path cleanup more than once')
  const section = code.match(/Section Uninstall\b([\s\S]*?)\nSectionEnd/)
  assert.ok(section, 'the template has no uninstall section')
  const body = section[1]
  const running = body.indexOf('!insertmacro CheckIfAppIsRunning')
  const cleanup = body.indexOf('!insertmacro SESAME_REMOVE_TERMINAL_PATH')
  const deletion = body.indexOf('!insertmacro SESAME_REMOVE_PROGRAM_FILE "$INSTDIR\\')
  assert.ok(running >= 0 && cleanup > running, 'the running app check, where a person can cancel, comes after the Path cleanup')
  assert.ok(deletion > cleanup, 'cli\\sesame.exe is deleted before it can remove its Path entry')
  const unregister = body.indexOf('!insertmacro SESAME_UNREGISTER_NATIVE_HOST')
  assert.ok(unregister > cleanup && unregister < deletion, 'the browser host is unregistered before the Path cleanup, so an uninstall that stops on the Path would leave the browser integration broken')
  assert.doesNotMatch(hook.match(/!macro NSIS_HOOK_PREUNINSTALL\b[\s\S]*?!macroend/)[0], /unregister/, 'the browser host is unregistered before the uninstall can stop on the Path')
  assert.match(hook, /!macro SESAME_UNREGISTER_NATIVE_HOST\s+\$\{If\} \$UpdateMode <> 1\s+ExecWait '"\$INSTDIR\\sesame-browser-host\.exe" unregister'\s+\$\{EndIf\}\s+!macroend/)
  assert.match(body.slice(running, cleanup + '!insertmacro SESAME_REMOVE_TERMINAL_PATH'.length), /^\s*!insertmacro CheckIfAppIsRunning[^\n]*\n\s*!insertmacro SESAME_REMOVE_TERMINAL_PATH/, 'something runs between the running app check and the Path cleanup')
  assert.doesNotMatch(body.slice(cleanup), /\bAbort\b|\bQuit\b|MessageBox/, 'something after the Path cleanup can still cancel the uninstall')
  const errorLevels = body.slice(cleanup).match(/[^\n]*\n[^\n]*SetErrorLevel[^\n]*\n[^\n]*/g) ?? []
  assert.deepEqual(errorLevels.map((lines) => lines.trim().split(/\s*\n\s*/)), [['${If} $SesameProgramLeft = 1', 'SetErrorLevel 2', '${EndIf}']], 'the uninstall sets an exit code for anything but a program file it could not remove')

  for (const [, name, fn] of code.matchAll(/Function (un\.[\w.]+)\b([\s\S]*?)FunctionEnd/g)) {
    assert.doesNotMatch(fn, /SESAME_|machine-path/, `${name} touches the Path before the uninstall has started`)
  }
})

test('the Windows command line program is staged before the bundle needs it', () => {
  const stage = read('tools', 'stage-browser-host.mjs')
  assert.match(stage, /if \(process\.platform === 'win32'\) \{\s+buildTerminalClient\(/)
  assert.match(stage, /join\(stageDirectory, 'cli'\)/)
  assert.match(stage, /'sesame\.exe'/)
  const helper = read('tools', 'browser-host.mjs')
  assert.match(helper, /UNSTAGED_TAURI_CONFIG = '\{"bundle":\{"externalBin":\[\],"resources":\[\]\}\}'/)
  assert.match(helper, /feature: 'terminal-client', bin: 'sesame-cli'/)
  assert.match(read('tools', 'generate-types.mjs'), /import \{ UNSTAGED_TAURI_CONFIG \} from '\.\/browser-host\.mjs'[\s\S]*TAURI_CONFIG: UNSTAGED_TAURI_CONFIG/, 'generate-types.mjs must build without the staged Windows resource')
  assert.match(read('tools', 'test-browser-host-pipe.mjs'), /"externalBin":\[\],"resources":\[\]/, 'test-browser-host-pipe.mjs must build without the staged Windows resource')
})

test('a Windows uninstall that leaves a program file behind reports it and can run again', () => {
  const code = read('src-tauri', 'nsis', 'installer.nsi')
    .split('\n')
    .filter((line) => !/^\s*;/.test(line))
    .join('\n')
  const section = (name) => code.match(new RegExp(`Section ${name}\\b([\\s\\S]*?)\\nSectionEnd`))[1]
  const install = section('Install')
  const uninstall = section('Uninstall')
  for (const body of [install, uninstall]) {
    assert.match(body, /!insertmacro SESAME_WAIT_FOR_SHELL_TO_RELEASE "\$INSTDIR\\\$\{MAINBINARYNAME\}\.exe"\n\s*!insertmacro CheckIfAppIsRunning "\$INSTDIR\\\$\{MAINBINARYNAME\}\.exe"/, 'the running app check no longer waits for Explorer to let go of the program')
  }

  const wait = code.match(/!macro SESAME_WAIT_FOR_SHELL_TO_RELEASE\b([\s\S]*?)!macroend/)
  assert.ok(wait, 'the template has no wait for Explorer')
  assert.doesNotMatch(wait[1], /RmShutdown|Abort|Quit|MessageBox|Delete|Exec|Write/, 'the wait does more than look')
  assert.match(wait[1], /\$\{If\} \$1 <> \$\{RmExplorer\}\s+\$\{AndIf\} \$1 <> \$\{RmCritical\}\s+StrCpy \$5 "app"/, 'the wait holds off the running app check for something other than Explorer or a critical system process')
  assert.match(wait[1], /\$\{If\} \$6 >= 100\s+\$\{ExitDo\}/, 'the wait for Explorer is unbounded')

  const remove = code.match(/!macro SESAME_REMOVE_PROGRAM_FILE\b([\s\S]*?)!macroend/)
  assert.ok(remove, 'the template has no checked program file removal')
  assert.match(remove[1], /Delete "\$\{path\}"\s+\$\{IfNot\} \$\{FileExists\} "\$\{path\}"\s+\$\{ExitDo\}/)
  assert.match(remove[1], /\$\{If\} \$0 >= 100\s+StrCpy \$SesameProgramLeft 1/, 'a program file that stays is not reported, or the retry is unbounded')
  assert.doesNotMatch(remove[1], /REBOOTOK|Abort|RMDir/i)

  assert.doesNotMatch(uninstall.replace('Delete "$INSTDIR\\uninstall.exe"', ''), /^\s*Delete "\$INSTDIR/m, 'a program file is deleted without checking that it went')
  assert.equal((uninstall.match(/!insertmacro SESAME_REMOVE_PROGRAM_FILE /g) ?? []).length, 3, 'the main program, the resources and the external binaries must each be removed with a check')
  assert.match(uninstall, /\$\{If\} \$SesameProgramLeft <> 1\s+!if "\$\{INSTALLMODE\}" == "both"\s+DeleteRegKey SHCTX "\$\{UNINSTKEY\}"[\s\S]*?!endif\s+\$\{EndIf\}/, 'the uninstall key goes even when the program stays')
  assert.match(uninstall, /\$\{If\} \$UpdateMode <> 1\s+\$\{AndIf\} \$SesameProgramLeft <> 1\s+DeleteRegKey SHCTX "\$\{MANUPRODUCTKEY\}"/, 'the install location record goes even when the program stays')
  assert.equal((uninstall.match(/DeleteRegKey (?:SHCTX|HKLM|HKCU) "\$\{(?:UNINSTKEY|MANUPRODUCTKEY)\}"/g) ?? []).length, 4)
})
