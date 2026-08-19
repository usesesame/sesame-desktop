import assert from 'node:assert/strict'
import { createHash, webcrypto } from 'node:crypto'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { execFileSync } from 'node:child_process'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const root = dirname(dirname(fileURLToPath(import.meta.url)))

const scriptsOf = (...parts) =>
  new Set(Object.keys(JSON.parse(readFileSync(join(root, ...parts), 'utf8')).scripts ?? {}))

const rootScripts = scriptsOf('package.json')
const nested = [
  ['backend', scriptsOf('backend', 'package.json')],
  ['admin', scriptsOf('admin', 'package.json')],
  ['website', scriptsOf('website', 'package.json')],
  ['account', scriptsOf('account', 'package.json')],
  [join('extensions', 'sesame'), scriptsOf('extensions', 'sesame', 'package.json')],
]

const IGNORED_DIRECTORIES = new Set([
  'node_modules', '.git', 'dist', 'target', 'test-results', '.svelte-kit', 'build',
  'release-artifacts', 'release-evidence',
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

const EXTRACTION_RECORDS = new Map()

test('every npm command the documentation gives can actually be run', () => {
  const offenders = []
  for (const path of filesMatching(/\.md$/)) {
    const location = relative(root, path)
    const prefix = nested.find(([name]) => location.startsWith(name + sep))?.[0]
      ?? EXTRACTION_RECORDS.get(location)
    const local = prefix === '*'
      ? new Set(nested.flatMap(([, scripts]) => [...scripts]))
      : nested.find(([name]) => name === prefix)?.[1] ?? new Set()
    for (const match of readFileSync(path, 'utf8').matchAll(/npm(?:\.cmd)? run ([a-z0-9:_-]+)/g)) {
      const name = match[1]
      if (rootScripts.has(name) || local.has(name)) continue
      offenders.push(`${location}: npm run ${name}`)
    }
  }
  assert.deepEqual(
    offenders,
    [],
    `these documented commands do not exist, so following the documentation fails:\n  ${offenders.join('\n  ')}`,
  )
})

test('every npm command the CI workflow runs exists', () => {
  const workflow = readFileSync(join(root, '.github', 'workflows', 'ci.yml'), 'utf8')
  const offenders = []
  const jobs = workflow.slice(workflow.indexOf('\njobs:\n') + '\njobs:\n'.length)
  const headers = [...jobs.matchAll(/^ {2}([a-z0-9_-]+):\r?$/gm)]
  for (const [index, header] of headers.entries()) {
    const jobName = header[1]
    const bodyStart = header.index + header[0].length
    const bodyEnd = headers[index + 1]?.index ?? jobs.length
    const body = jobs.slice(bodyStart, bodyEnd)
    const directory = /working-directory:\s*([^\s#]+)/.exec(body)?.[1]?.replaceAll('/', sep)
    const available = nested.find(([prefix]) => directory === prefix)?.[1] ?? rootScripts
    for (const command of body.matchAll(/npm run ([a-z0-9:_-]+)/g)) {
      if (!available.has(command[1])) offenders.push(`${jobName}: npm run ${command[1]}`)
    }
  }
  assert.deepEqual(
    offenders,
    [],
    `CI calls scripts that package.json does not define, which only fails once pushed:\n  ${offenders.join('\n  ')}`,
  )
})

test('the clean workspace gate supplies only non-routable build configuration', () => {
  const scripts = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).scripts
  assert.match(scripts['workspace:check'], /run-workspace-check\.mjs/)
  assert.ok(scripts['workspace:check:configured'])
  const runner = readFileSync(join(root, 'tools', 'run-workspace-check.mjs'), 'utf8')
  assert.match(runner, /\['\/d', '\/s', '\/c', 'npm\.cmd run workspace:check:configured'\]/)
  assert.doesNotMatch(runner, /shell:\s*true/)
  const output = execFileSync(process.execPath, [join(root, 'tools', 'run-workspace-check.mjs'), '--print-environment'], {
    encoding: 'utf8',
    env: {},
  })
  assert.deepEqual(JSON.parse(output), {
    VITE_SESAME_SITE_ORIGIN: 'https://website.test.invalid',
    VITE_SESAME_API_URL: 'https://api.test.invalid',
    VITE_SESAME_PRIVACY_EMAIL: 'privacy@website.test.invalid',
    SESAME_API_BASE_URL: 'https://api.test.invalid',
  })
})

test('the version gate supports a Cargo workspace before the desktop package', () => {
  const cargo = readFileSync(join(root, 'src-tauri', 'Cargo.toml'), 'utf8')
  assert.match(cargo, /^\[workspace\]$/m)
  assert.match(cargo, /^\[package\]$/m)
  assert.doesNotThrow(() => {
    execFileSync(process.execPath, [join(root, 'tools', 'version-contract.mjs'), 'check'], {
      cwd: root,
      encoding: 'utf8',
    })
  })
})

test('the Windows uninstaller removes only Sesame native-host registration', () => {
  const config = JSON.parse(readFileSync(join(root, 'src-tauri', 'tauri.conf.json'), 'utf8'))
  assert.equal(config.bundle.windows.nsis.installerHooks, 'nsis/native-host-uninstall.nsh')
  const hook = readFileSync(join(root, 'src-tauri', 'nsis', 'native-host-uninstall.nsh'), 'utf8')
  assert.match(hook, /NSIS_HOOK_PREUNINSTALL/)
  assert.match(hook, /\$UpdateMode <> 1/)
  assert.match(hook, /Chrome\\NativeMessagingHosts\\app\.usesesame\.browser/)
  assert.match(hook, /Edge\\NativeMessagingHosts\\app\.usesesame\.browser/)
  assert.match(hook, /native-messaging\\app\.usesesame\.browser\.json/)
  assert.doesNotMatch(hook, /vault\.sesame|backups|recovery|HKLM|\$INSTDIR/i)
  assert.doesNotMatch(hook, /RMDir "\$LOCALAPPDATA\\Sesame"/)
})

test('the installer owns its own template and never offers to delete app data', () => {
  // Stock Tauri 2.11.4 NSIS "Delete app data" checkbox recursively deletes %LOCALAPPDATA%, which holds the live vault and every backup.
  const config = JSON.parse(readFileSync(join(root, 'src-tauri', 'tauri.conf.json'), 'utf8'))
  assert.equal(config.bundle.windows.nsis.template, 'nsis/installer.nsi')
  assert.equal(config.bundle.windows.allowDowngrades, false)
  assert.equal(config.bundle.windows.webviewInstallMode.type, 'embedBootstrapper')
  assert.equal(config.bundle.windows.webviewInstallMode.silent, true)
  assert.equal(config.plugins.updater.pubkey, '')

  const installer = readFileSync(join(root, 'src-tauri', 'nsis', 'installer.nsi'), 'utf8')

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
  const cargo = readFileSync(join(root, 'src-tauri', 'Cargo.toml'), 'utf8')
  const desktop = readFileSync(join(root, 'src-tauri', 'src', 'lib.rs'), 'utf8')
  const policy = readFileSync(join(root, 'src-tauri', 'src', 'adapters', 'platform', 'dll_search.rs'), 'utf8')
  const config = JSON.parse(readFileSync(join(root, 'src-tauri', 'tauri.conf.json'), 'utf8'))
  const template = readFileSync(join(root, 'src-tauri', 'nsis', 'installer.nsi'), 'utf8')

  assert.match(cargo, /Win32_System_LibraryLoader/)
  assert.match(policy, /SetDefaultDllDirectories\(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS\)/)
  assert.match(policy, /std::io::Error::last_os_error\(\)/)
  assert.match(desktop, /pub fn run\(\) \{[\s\S]*?dll_search::harden_process\(\)[\s\S]*?prepare_release_webview_environment\(\)/)
  assert.match(desktop, /pub fn run_browser_host\(\) \{[\s\S]*?dll_search::harden_process\(\)[\s\S]*?browser_host::run\(\)/)
  assert.equal(config.bundle.windows.nsis.installMode, 'perMachine')
  assert.match(template, /!if "\$\{INSTALLMODE\}" == "perMachine"\s*\n {2}RequestExecutionLevel admin/)
})

test('the installer never launches an executable through an unquoted path', () => {
  // An unquoted $TEMP path lets a writable "C:\Users\First.exe" run instead of the bootstrapper during elevated installs.
  const installer = readFileSync(join(root, 'src-tauri', 'nsis', 'installer.nsi'), 'utf8')
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

test('nothing in tools/ is left behind unreferenced', () => {
  const workflowDirectory = join(root, '.github', 'workflows')
  const referrers = [
    { name: 'package.json', text: readFileSync(join(root, 'package.json'), 'utf8') },
    ...readdirSync(workflowDirectory).map((name) => ({
      name, text: readFileSync(join(workflowDirectory, name), 'utf8'),
    })),
    ...filesMatching(/\.(mjs|js|ps1)$/, join(root, 'tools')).map((path) => ({
      name: relative(join(root, 'tools'), path),
      text: readFileSync(path, 'utf8'),
    })),
  ]

  const orphans = []
  for (const path of readdirSync(join(root, 'tools'))) {
    if (path.endsWith('-contracts.test.mjs')) continue
    const reachable = referrers.some((referrer) => referrer.name !== path && referrer.text.includes(path))
    if (!reachable) orphans.push(path)
  }
  assert.deepEqual(
    orphans,
    [],
    `these files in tools/ are referenced by nothing:\n  ${orphans.join('\n  ')}`,
  )
})

test('every Docker stack creates its own secrets before it starts', () => {
  const stacks = [
    { location: 'package.json', setup: /ensure-local-api-env\.mjs\s*&&/, compose: 'compose.yaml' },
    { location: 'backend/package.json', setup: /setup\.mjs/, compose: 'deploy/compose/compose.yaml' },
  ]

  for (const stack of stacks) {
    const scripts = JSON.parse(readFileSync(join(root, stack.location), 'utf8')).scripts ?? {}
    const starters = Object.entries(scripts)
      .filter(([, body]) => /docker\s+compose[^&|]*\bup\b/.test(body))
      .map(([name, body]) => ({ name, body }))
    assert.equal(
      starters.length,
      1,
      `${stack.location} should have exactly one script that starts its Compose stack, found ${starters.length}: `
        + starters.map((entry) => entry.name).join(', '),
    )
    const starter = starters[0]
    assert.ok(
      starter.body.includes(stack.compose) || !starter.body.includes('-f'),
      `${stack.location} ${starter.name} does not start ${stack.compose}`,
    )
    const generatesInline = stack.setup.test(starter.body)
    const documented = stack.location === 'backend/package.json'
      && stack.setup.test(scripts.setup ?? '')
      && /npm run setup/.test(readFileSync(join(root, 'backend', 'README.md'), 'utf8'))
    assert.ok(
      generatesInline || documented,
      `${stack.location} ${starter.name} can start Compose without any step that creates its secrets`,
    )
  }
})

test('the browser extension scripts name the shipping extension', () => {
  const scripts = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).scripts
  assert.ok(!Object.keys(scripts).some((name) => name.includes(':next')), 'a `:next` script name is back')
  assert.match(scripts['extension:check'], /extensions\/sesame\b/)
})

test('the browser extension build and tests cannot read a former sibling', () => {
  const extensionRoot = join(root, 'extensions', 'sesame')
  const escapes = []
  const executableFiles = filesMatching(/\.(?:css|js|mjs|svelte|ts)$/, extensionRoot)
  const specifierPatterns = [
    /(?:from\s+|import\s*)['"](\.[^'"]+)['"]/g,
    /new URL\(\s*['"](\.[^'"]+)['"]/g,
    /@import\s+['"](\.[^'"]+)['"]/g,
  ]

  for (const path of executableFiles) {
    const source = readFileSync(path, 'utf8')
    for (const pattern of specifierPatterns) {
      for (const match of source.matchAll(pattern)) {
        const target = resolve(dirname(path), match[1])
        if (target !== extensionRoot && !target.startsWith(extensionRoot + sep)) {
          escapes.push(`${relative(root, path)} -> ${match[1]}`)
        }
      }
    }
  }

  assert.deepEqual(
    escapes,
    [],
    `extension code reaches outside its future-repository subtree:\n  ${escapes.join('\n  ')}`,
  )

  const extensionPackage = JSON.parse(readFileSync(join(extensionRoot, 'package.json'), 'utf8'))
  assert.ok(extensionPackage.scripts.ci)
  assert.ok(extensionPackage.scripts['version:check'])
  assert.ok(extensionPackage.scripts['design:tokens:check'])
  const futureCi = readFileSync(join(extensionRoot, '.github', 'workflows', 'ci.yml'), 'utf8')
  assert.match(futureCi, /node-version-file:\s*\.node-version/)
  assert.match(futureCi, /run:\s*npm ci/)
  assert.match(futureCi, /run:\s*npm run ci/)
})

test('the admin portal build and tests cannot read a former sibling', () => {
  const adminRoot = join(root, 'admin')
  const escapes = []
  const executableFiles = filesMatching(/\.(?:css|js|mjs|svelte|ts)$/, adminRoot)
  const specifierPatterns = [
    /(?:from\s+|import\s*)['"](\.[^'"]+)['"]/g,
    /new URL\(\s*['"](\.[^'"]+)['"]/g,
    /@import\s+['"](\.[^'"]+)['"]/g,
  ]

  for (const path of executableFiles) {
    const source = readFileSync(path, 'utf8')
    for (const pattern of specifierPatterns) {
      for (const match of source.matchAll(pattern)) {
        const target = resolve(dirname(path), match[1])
        if (target !== adminRoot && !target.startsWith(adminRoot + sep)) {
          escapes.push(`${relative(root, path)} -> ${match[1]}`)
        }
      }
    }
  }

  assert.deepEqual(
    escapes,
    [],
    `admin code reaches outside its future-repository subtree:\n  ${escapes.join('\n  ')}`,
  )

  const adminPackage = JSON.parse(readFileSync(join(adminRoot, 'package.json'), 'utf8'))
  assert.ok(adminPackage.scripts.ci)
  assert.ok(adminPackage.scripts['release:check'])
  assert.ok(adminPackage.scripts['design:tokens:check'])
  assert.equal(
    readFileSync(join(adminRoot, 'design', 'tokens.css'), 'utf8'),
    readFileSync(join(root, 'design', 'tokens.css'), 'utf8'),
  )
  const futureCi = readFileSync(join(adminRoot, '.github', 'workflows', 'ci.yml'), 'utf8')
  assert.match(futureCi, /node-version-file:\s*\.node-version/)
  assert.match(futureCi, /cache-dependency-path:\s*package-lock\.json/)
  assert.match(futureCi, /run:\s*npm ci/)
  assert.match(futureCi, /run:\s*npm run ci/)

  const scripts = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).scripts
  for (const name of ['admin:dev', 'admin:build', 'admin:check', 'admin:test']) {
    assert.match(scripts[name], /npm --prefix admin run/)
  }
  const workflow = readFileSync(join(root, '.github', 'workflows', 'ci.yml'), 'utf8')
  assert.match(workflow, /^ {2}admin:\r?$/m)
  assert.match(workflow, /working-directory:\s*admin/)
  assert.match(workflow, /cache-dependency-path:\s*admin\/package-lock\.json/)
})

// Each of the four boundary tests above names the commands it expects. None of
// them noticed that a command's *body* had begun reaching out of its own
// product, because they check the commands they know about rather than every
// command there is. A product whose test command runs a file from a sibling
// directory stops working the moment it becomes its own repository, which is
// the whole property those tests exist to protect.
test('no product command reaches outside its own directory', () => {
  const offenders = []
  for (const product of ['extensions/sesame', 'account', 'admin', 'website', 'backend']) {
    const manifest = JSON.parse(readFileSync(join(root, product, 'package.json'), 'utf8'))
    for (const [name, body] of Object.entries(manifest.scripts ?? {})) {
      // `../` can only leave the product root, and nothing above it travels.
      if (/(^|[\s"'=])\.\.\//.test(body)) offenders.push(`${product} -> ${name}: ${body}`)
    }
  }
  assert.deepEqual(
    offenders,
    [],
    `these commands cannot run once their product is its own repository:\n  ${offenders.join('\n  ')}`,
  )
})

test('the account portal build and tests cannot read a former sibling', () => {
  const accountRoot = join(root, 'account')
  const escapes = []
  const executableFiles = filesMatching(/\.(?:css|js|mjs|svelte|ts)$/, accountRoot)
  const specifierPatterns = [
    /(?:from\s+|import\s*)['"](\.[^'"]+)['"]/g,
    /new URL\(\s*['"](\.[^'"]+)['"]/g,
    /@import\s+['"](\.[^'"]+)['"]/g,
  ]

  for (const path of executableFiles) {
    const source = readFileSync(path, 'utf8')
    for (const pattern of specifierPatterns) {
      for (const match of source.matchAll(pattern)) {
        const target = resolve(dirname(path), match[1])
        if (target !== accountRoot && !target.startsWith(accountRoot + sep)) {
          escapes.push(`${relative(root, path)} -> ${match[1]}`)
        }
      }
    }
  }

  assert.deepEqual(
    escapes,
    [],
    `account portal code reaches outside its future-repository subtree:\n  ${escapes.join('\n  ')}`,
  )

  const accountPackage = JSON.parse(readFileSync(join(accountRoot, 'package.json'), 'utf8'))
  assert.ok(accountPackage.scripts.ci)
  assert.ok(accountPackage.scripts['release:check'])
  assert.ok(accountPackage.scripts['design:tokens:check'])
  assert.equal(
    readFileSync(join(accountRoot, 'design', 'tokens.css'), 'utf8'),
    readFileSync(join(root, 'design', 'tokens.css'), 'utf8'),
  )
  const futureCi = readFileSync(join(accountRoot, '.github', 'workflows', 'ci.yml'), 'utf8')
  assert.match(futureCi, /node-version-file:\s*\.node-version/)
  assert.match(futureCi, /cache-dependency-path:\s*package-lock\.json/)
  assert.match(futureCi, /run:\s*npm ci/)
  assert.match(futureCi, /run:\s*npm run ci/)

  const scripts = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).scripts
  for (const name of ['account:check', 'account:test']) {
    assert.match(scripts[name], /npm --prefix account run/)
  }
  const workflow = readFileSync(join(root, '.github', 'workflows', 'ci.yml'), 'utf8')
  assert.match(workflow, /^ {2}admin:\r?$/m)
  assert.match(workflow, /working-directory:\s*account/)
  assert.match(workflow, /cache-dependency-path:\s*account\/package-lock\.json/)

  // Authentication moved here from the website; nothing reading a session, passkey, or capability may travel back.
  for (const owned of ['auth.ts', 'passkey.ts', 'capabilities.ts']) {
    assert.ok(existsSync(join(accountRoot, 'src', 'lib', owned)), `the portal must own src/lib/${owned}`)
    assert.ok(!existsSync(join(root, 'website', 'src', 'lib', owned)), `the website must not contain src/lib/${owned}`)
  }
  const publicClient = readFileSync(join(root, 'website', 'src', 'lib', 'api.ts'), 'utf8')
  assert.match(publicClient, /credentials: 'omit'/, 'the public site must not send credentials to the API')
  assert.doesNotMatch(publicClient, /X-Sesame-CSRF/, 'the public site performs no unsafe request')
})

test('the website build and tests cannot read a former sibling', () => {
  const websiteRoot = join(root, 'website')
  const escapes = []
  const executableFiles = filesMatching(/\.(?:css|js|mjs|svelte|ts)$/, websiteRoot)
  const specifierPatterns = [
    /(?:from\s+|import\s*)['"](\.[^'"]+)['"]/g,
    /new URL\(\s*['"](\.[^'"]+)['"]/g,
    /@import\s+['"](\.[^'"]+)['"]/g,
  ]

  for (const path of executableFiles) {
    const source = readFileSync(path, 'utf8')
    for (const pattern of specifierPatterns) {
      for (const match of source.matchAll(pattern)) {
        const target = resolve(dirname(path), match[1])
        if (target !== websiteRoot && !target.startsWith(websiteRoot + sep)) {
          escapes.push(`${relative(root, path)} -> ${match[1]}`)
        }
      }
    }
  }

  assert.deepEqual(
    escapes,
    [],
    `website code reaches outside its future-repository subtree:\n  ${escapes.join('\n  ')}`,
  )

  const websitePackage = JSON.parse(readFileSync(join(websiteRoot, 'package.json'), 'utf8'))
  for (const name of ['ci', 'release:check', 'design:tokens:check', 'seo:check']) {
    assert.ok(websitePackage.scripts[name], `website package is missing ${name}`)
  }
  assert.equal(
    readFileSync(join(websiteRoot, 'design', 'tokens.css'), 'utf8'),
    readFileSync(join(root, 'design', 'tokens.css'), 'utf8'),
  )
  const futureCi = readFileSync(join(websiteRoot, '.github', 'workflows', 'ci.yml'), 'utf8')
  assert.match(futureCi, /node-version-file:\s*\.node-version/)
  assert.match(futureCi, /cache-dependency-path:\s*package-lock\.json/)
  assert.match(futureCi, /run:\s*npm ci/)
  assert.match(futureCi, /run:\s*npm run ci/)

  const scripts = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).scripts
  for (const name of ['website:dev', 'website:build', 'website:check', 'website:test']) {
    assert.match(scripts[name], /npm --prefix website run/)
  }
  const workflow = readFileSync(join(root, '.github', 'workflows', 'ci.yml'), 'utf8')
  assert.match(workflow, /^ {2}website:\r?$/m)
  assert.match(workflow, /working-directory:\s*website/)
  assert.match(workflow, /cache-dependency-path:\s*website\/package-lock\.json/)
})

test('the backend build, tests, and generated API contract cannot read a former sibling', () => {
  const backendRoot = join(root, 'backend')
  const backendPackage = JSON.parse(readFileSync(join(backendRoot, 'package.json'), 'utf8'))
  for (const name of ['build', 'vet', 'test', 'test:race', 'openapi:generate', 'openapi:check', 'vuln:check', 'lint', 'ci']) {
    assert.ok(backendPackage.scripts[name], `backend package is missing ${name}`)
  }
  for (const name of ['build', 'vet', 'test', 'test:race', 'vuln:check']) {
    assert.match(backendPackage.scripts[name], /scripts\/run-go\.mjs/)
  }

  const runner = readFileSync(join(backendRoot, 'scripts', 'run-go.mjs'), 'utf8')
  assert.match(runner, /const backendRoot = dirname\(dirname\(fileURLToPath\(import\.meta\.url\)\)\)/)
  assert.match(runner, /cwd: backendRoot/)
  assert.doesNotMatch(runner, /repositoryRoot|['"]\.\.\/\.\./)

  const openapiGenerator = readFileSync(join(backendRoot, 'scripts', 'openapi.mjs'), 'utf8')
  assert.match(backendPackage.scripts['openapi:generate'], /scripts\/openapi\.mjs generate/)
  assert.match(backendPackage.scripts['openapi:check'], /scripts\/openapi\.mjs check/)
  assert.match(backendPackage.scripts.ci, /^npm run openapi:check &&/)
  assert.match(openapiGenerator, /const backendRoot = dirname\(dirname\(fileURLToPath\(import\.meta\.url\)\)\)/)
  assert.doesNotMatch(openapiGenerator, /repositoryRoot|['"]\.\.\/\.\./)

  const openapi = JSON.parse(readFileSync(join(backendRoot, 'openapi', 'openapi.json'), 'utf8'))
  assert.equal(openapi.openapi, '3.1.1')
  assert.deepEqual(openapi['x-sesame-generated-from'], [
    'internal/httpapi/server.go',
    'internal/httpapi/admin_auth.go',
    'internal/httpapi/sync_routes.go',
  ])
  const operations = []
  for (const [path, pathItem] of Object.entries(openapi.paths)) {
    for (const [method, operation] of Object.entries(pathItem)) {
      operations.push({ path, method, operation })
    }
  }
  assert.ok(operations.length > 100, 'the generated API inventory unexpectedly lost most operations')
  assert.equal(openapi['x-sesame-operation-count'], operations.length)
  assert.equal(new Set(operations.map(({ operation }) => operation.operationId)).size, operations.length)
  for (const { path, method, operation } of operations) {
    assert.ok(Array.isArray(operation.security), `${method.toUpperCase()} ${path} has no explicit security contract`)
    assert.ok(operation['x-sesame-auth'], `${method.toUpperCase()} ${path} has no authentication class`)
    assert.ok(operation['x-sesame-availability'], `${method.toUpperCase()} ${path} has no availability class`)
    assert.ok(operation['x-sesame-handler'], `${method.toUpperCase()} ${path} has no owning handler`)
    assert.ok(operation['x-sesame-registration-pattern'], `${method.toUpperCase()} ${path} has no mux registration`)
    assert.ok(!operation.requestBody, `${method.toUpperCase()} ${path} must keep detailed bodies in API.md until closed schemas are generated`)
  }
  const syncOperations = operations.filter(({ path }) => path.startsWith('/v1/sync/'))
  assert.ok(syncOperations.length > 0, 'the built-disabled Sync inventory disappeared')
  for (const { operation } of syncOperations) {
    assert.equal(operation['x-sesame-auth'], 'desktop-token-built-disabled')
    assert.equal(operation['x-sesame-availability'], 'built-disabled')
    assert.deepEqual(operation.tags, ['sync-disabled'])
  }
  assert.deepEqual(Object.keys(openapi.components.schemas), ['ErrorEnvelope'])

  const futureCi = readFileSync(join(backendRoot, '.github', 'workflows', 'ci.yml'), 'utf8')
  assert.match(futureCi, /node-version-file:\s*\.node-version/)
  assert.match(futureCi, /go-version-file:\s*go\.mod/)
  assert.match(futureCi, /cache-dependency-path:\s*package-lock\.json/)
  assert.match(futureCi, /run:\s*npm ci/)
  assert.match(futureCi, /run:\s*npm run ci/)
  assert.match(futureCi, /run:\s*npm run test:race/)
  assert.match(futureCi, /run:\s*npm run vuln:check/)

  const scripts = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).scripts
  assert.match(scripts['backend:test'], /npm --prefix backend run test/)
  assert.match(scripts['lint:go'], /npm --prefix backend run lint/)
  const workflow = readFileSync(join(root, '.github', 'workflows', 'ci.yml'), 'utf8')
  assert.match(workflow, /^ {2}backend:\r?$/m)
  assert.match(workflow, /working-directory:\s*backend/)
  assert.match(workflow, /cache-dependency-path:\s*backend\/package-lock\.json/)
  assert.match(workflow, /run:\s*npm run ci/)
  assert.match(workflow, /run:\s*npm run test:race/)
  assert.match(workflow, /run:\s*npm run vuln:check/)
})

test('desktop and extension versions are independent contracts', () => {
  const desktopContract = readFileSync(join(root, 'tools', 'version-contract.mjs'), 'utf8')
  assert.doesNotMatch(desktopContract, /extensions[\\/]sesame/)
  const extensionContract = readFileSync(join(root, 'extensions', 'sesame', 'scripts', 'version-contract.mjs'), 'utf8')
  assert.doesNotMatch(extensionContract, /src-tauri|tauri\.conf|\.\.\//)
})

test('the shipping extension pins its identity and a minimal permission set', () => {
  const pinnedId = 'idbkfhhjnniibleeanchljhakfhecnlg'
  const idFor = (publicKeyBase64) => {
    const digest = createHash('sha256').update(Buffer.from(publicKeyBase64, 'base64')).digest().subarray(0, 16)
    return [...digest].map((byte) => 'abcdefghijklmnop'[byte >> 4] + 'abcdefghijklmnop'[byte & 0x0f]).join('')
  }

  const permissions = new Set(['activeTab', 'nativeMessaging', 'scripting', 'storage'])
  for (const browser of ['chrome', 'edge']) {
    const manifest = JSON.parse(readFileSync(join(root, 'extensions', 'sesame', 'manifests', `${browser}.json`), 'utf8'))
    assert.ok(manifest.key, `${browser} manifest has no pinned extension key`)
    assert.equal(idFor(manifest.key), pinnedId, `${browser} manifest no longer derives the pinned extension id`)
    assert.equal(manifest.manifest_version, 3)
    assert.equal(manifest.background?.type, 'module')
    assert.deepEqual([...manifest.permissions].sort(), [...permissions].sort(), `${browser} manifest permissions drifted from the minimal set`)
    assert.deepEqual(manifest.optional_host_permissions, ['https://*/*'], `${browser} manifest broadened its optional host permission`)
    assert.equal(manifest.web_accessible_resources, undefined, `${browser} manifest exposes web-accessible resources`)
    assert.equal(manifest.content_scripts, undefined, `${browser} manifest injects scripts on every page instead of on demand`)
  }

  const scripts = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).scripts
  assert.match(scripts['release:check'], /extension:release:check/, 'release:check does not build the shipping extension')
})

test('the Chromium-launched native host carries its own MSVC runtime', () => {
  const stage = readFileSync(join(root, 'tools', 'stage-browser-host.ps1'), 'utf8')
  assert.match(stage, /target-feature=\+crt-static/)
  assert.match(stage, /previousRustFlags/)
  assert.match(stage, /Remove-Item Env:\\RUSTFLAGS/)
})

test('local setup derives the capability public key the website needs', () => {
  const setup = readFileSync(join(root, 'tools', 'ensure-local-api-env.mjs'), 'utf8')
  assert.match(
    setup,
    /VITE_SESAME_CAPABILITY_PUBLIC_KEY/,
    '`npm run api:up` no longer writes the capability public key, so every local capability is off',
  )
  assert.match(
    setup,
    /createPublicKey/,
    'the public key must be derived from the signing seed, not invented',
  )
})

test('the desktop linking page names the condition that is actually blocking', () => {
  const page = readFileSync(join(root, 'account', 'src', 'pages', 'AccountPage.svelte'), 'utf8')
  const gate = page.match(/\$: desktopLinkReady = Boolean\(([^)]*\))\)/)
  assert.ok(gate, 'desktopLinkReady is no longer a single expression this test can read')

  const conditions = ['emailVerified', 'betaGranted', 'capabilityConfig', 'desktopLinking']
  for (const condition of conditions) {
    assert.ok(gate[1].includes(condition), `the gate no longer checks ${condition}`)
  }
  const blocker = page.match(/\$: desktopLinkBlocker =([\s\S]*?)\n\n/)
  assert.ok(blocker, 'desktopLinkBlocker is gone, so the page cannot explain what is blocking')
  for (const condition of ['emailVerified', 'betaGranted', 'capabilityConfig']) {
    assert.ok(
      blocker[1].includes(condition),
      `the blocker message does not distinguish ${condition}, so it will blame the wrong gate`,
    )
  }
})

test('the Sync preview API signs with the local key, not a throwaway one', () => {
  const runner = readFileSync(join(root, 'tools', 'run-sync-preview-api.mjs'), 'utf8')
  const required = runner.match(/const required = \[([\s\S]*?)\]/)
  assert.ok(required, 'the preview API runner no longer lists required secrets')
  assert.match(
    required[1],
    /SESAME_CAPABILITY_SIGNING_KEY/,
    'the preview API may start without the signing key, so its capability document cannot be verified',
  )
})

test('the Sync preview API and the desktop agree on one port', () => {
  const api = readFileSync(join(root, 'tools', 'run-sync-preview-api.mjs'), 'utf8')
  const desktop = readFileSync(join(root, 'tools', 'run-sync-preview-desktop.mjs'), 'utf8')
  const port = api.match(/SESAME_API_ADDR:[^']*'127\.0\.0\.1:(\d+)'/)
  assert.ok(port, 'the preview API no longer names a default port this test can read')

  assert.ok(
    !desktop.includes('SESAME_API_BASE_URL'),
    'the desktop runner overrides the API URL again, which invalidates an existing account link',
  )
  const example = readFileSync(join(root, 'src-tauri', '.env.example'), 'utf8')
  assert.ok(
    example.includes(port[1]) || readFileSync(join(root, 'tools', 'ensure-local-api-env.mjs'), 'utf8').includes(port[1]),
    `nothing points the desktop at port ${port[1]}, where the preview API listens`,
  )
})

test('the installed-app test bridge is excluded from normal desktop builds', () => {
  const cargo = readFileSync(join(root, 'src-tauri', 'Cargo.toml'), 'utf8')
  const rust = readFileSync(join(root, 'src-tauri', 'src', 'lib.rs'), 'utf8')
  const frontend = readFileSync(join(root, 'src', 'main.ts'), 'utf8')

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

test('shipping webviews do not expose embedded Edge inspection surfaces', () => {
  const shell = readFileSync(join(root, 'src-tauri', 'src', 'adapters', 'platform', 'desktop_shell.rs'), 'utf8')
  const rust = readFileSync(join(root, 'src-tauri', 'src', 'lib.rs'), 'utf8')
  const capability = readFileSync(join(root, 'src-tauri', 'capabilities', 'default.json'), 'utf8')
  const main = readFileSync(join(root, 'src', 'main.ts'), 'utf8')
  const quickAccess = readFileSync(join(root, 'src', 'quick-access-main.ts'), 'utf8')

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
    const manifest = readFileSync(join(before, 'data-files.csv'), 'utf8')
    assert.match(manifest, /"relativePath","length","lastWriteTimeUtc","sha256"/)
    assert.match(manifest, /"vault\.sesame"/)
    assert.match(manifest, /"native-messaging\\app\.usesesame\.browser\.json"/)
    assert.doesNotMatch(manifest, /EBWebView|sesame\.log/)
    assert.doesNotMatch(manifest, /"Count","Keys","Values"/)
    const policy = JSON.parse(readFileSync(join(before, 'collector-policy.json'), 'utf8').replace(/^\uFEFF/, ''))
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

test('repository-root VM evidence and scratch directories are ignored', () => {
  const ignore = readFileSync(join(root, '.gitignore'), 'utf8')
  assert.match(ignore, /sesame-\*-vm-\*\.zip/)
  assert.match(ignore, /backend\/\.tmp\//)
})

test('each desktop webview gets only the Tauri permissions its imports need', () => {
  const main = JSON.parse(readFileSync(join(root, 'src-tauri', 'capabilities', 'default.json'), 'utf8'))
  const quick = JSON.parse(readFileSync(join(root, 'src-tauri', 'capabilities', 'quick-access.json'), 'utf8'))
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
    assert.ok(!capability.permissions.some((permission) => typeof permission === 'string' && permission.startsWith('opener:')), `${capability.identifier} regained frontend URL-launch authority`)
  }

  const packageJson = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
  assert.ok(!packageJson.dependencies['@tauri-apps/plugin-opener'], 'the renderer regained the opener client')
  const vaultClient = readFileSync(join(root, 'src', 'lib', 'vault.ts'), 'utf8')
  assert.doesNotMatch(vaultClient, /@tauri-apps\/plugin-opener|openUrl\(/)
  assert.match(vaultClient, /invoke\('open_external_url', \{ url, purpose \}\)/)
  const externalUrl = readFileSync(join(root, 'src-tauri', 'src', 'adapters', 'platform', 'external_url.rs'), 'utf8')
  assert.match(externalUrl, /matches!\(parsed\.scheme\(\), "http" \| "https"\)/)
  assert.match(externalUrl, /parsed\.username\(\)\.is_empty\(\)/)
  assert.match(externalUrl, /parsed\.password\(\)\.is_some\(\)/)
  assert.match(externalUrl, /window\.label\(\) != "main"/)
  assert.match(externalUrl, /entry_owns_url\(entry, &parsed\)/)
  assert.match(externalUrl, /support_url_matches\(&parsed, option_env!\("VITE_SESAME_SITE_ORIGIN"\)\)/)
  assert.match(externalUrl, /requested\.path\(\) != "\/support"/)
  assert.match(externalUrl, /"appVersion" \| "diagnosticCode" \| "browserIntegration" \| "requestId"/)

  const config = JSON.parse(readFileSync(join(root, 'src-tauri', 'tauri.conf.json'), 'utf8'))
  assert.ok(config.app.security.capabilities.includes('quick-access-capability'), 'the quick-access capability is not enabled')

  const build = readFileSync(join(root, 'src-tauri', 'build.rs'), 'utf8')
  assert.match(build, /app_manifest\(tauri_build::AppManifest::new\(\)\)/, 'custom application commands are still implicitly available')

  const permissions = readFileSync(join(root, 'src-tauri', 'permissions', 'desktop.toml'), 'utf8')
  const quickPermission = permissions.match(/identifier = "quick-access"([\s\S]*?)(?=\n\[\[permission\]\]|$)/)
  assert.ok(quickPermission, 'the dedicated quick-access application permission is missing')
  assert.deepEqual(
    [...quickPermission[1].matchAll(/"([a-z0-9_]+)"/g)].map((match) => match[1]),
    [
      'get_quick_access_status',
      'search_quick_access_entries',
      'get_quick_access_secret',
      'arm_clipboard_clear',
      'clear_clipboard_if_unchanged',
    ],
  )

  const handler = readFileSync(join(root, 'src-tauri', 'src', 'lib.rs'), 'utf8')
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

  const quickView = readFileSync(join(root, 'src', 'lib', 'ui', 'QuickAccessView.svelte'), 'utf8')
  assert.doesNotMatch(quickView, /unlockVault|unlockWithPin|getVaultStatus|getLoginCard|WebsiteIcon|readSiteIcons/)
  assert.match(quickView, /getQuickAccessStatus/)
  assert.match(quickView, /searchQuickAccessEntries/)
  assert.match(quickView, /getQuickAccessSecret/)
  const quickCommands = readFileSync(join(root, 'src-tauri', 'src', 'commands', 'quick_access.rs'), 'utf8')
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

  const adapterRoot = readFileSync(join(root, 'src-tauri', 'src', 'adapters', 'mod.rs'), 'utf8')
  assert.match(adapterRoot, /mod network;/)
  assert.match(adapterRoot, /mod platform;/)
})

test('desktop updates use an account-independent signed static manifest', () => {
  const updater = readFileSync(join(root, 'src-tauri', 'src', 'commands', 'updater.rs'), 'utf8')
  const publicUpdates = readFileSync(join(root, 'src-tauri', 'src', 'adapters', 'network', 'public_updates.rs'), 'utf8')
  const build = readFileSync(join(root, 'src-tauri', 'build.rs'), 'utf8')
  const settings = readFileSync(join(root, 'src', 'lib', 'ui', 'SettingsView.svelte'), 'utf8')
  const app = readFileSync(join(root, 'src', 'App.svelte'), 'utf8')
  const settingsController = readFileSync(join(root, 'src', 'lib', 'controllers', 'settings-controller.ts'), 'utf8')
  const manifestTool = readFileSync(join(root, 'tools', 'create-static-update-manifest.mjs'), 'utf8')
  const workflow = readFileSync(join(root, '.github', 'workflows', 'release-early-access.yml'), 'utf8')

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
  assert.match(manifestTool, /windows-\$\{candidate\.architecture\}-nsis/)
  assert.match(manifestTool, /candidateReceipt/)
  assert.match(manifestTool, /SESAME_PUBLIC_UPDATE_ARTIFACT_URL/)
  assert.match(workflow, /create-static-update-manifest\.mjs \$candidate release-handoff\/latest\.json/)
  assert.match(workflow, /SESAME_RELEASE_CANDIDATE_PUBLIC_KEY/)
  assert.doesNotMatch(workflow, /gh release create|softprops\/action-gh-release/)
})

test('the updater VM lab is ephemeral, loopback-only, and cannot alter shipping transport', () => {
  const prepare = readFileSync(join(root, 'tools', 'prepare-updater-vm-lab.mjs'), 'utf8')
  const serve = readFileSync(join(root, 'tools', 'serve-updater-vm-lab.mjs'), 'utf8')
  const verify = readFileSync(join(root, 'tools', 'verify-updater-vm-lab.mjs'), 'utf8')
  const shippingConfig = readFileSync(join(root, 'src-tauri', 'tauri.conf.json'), 'utf8')

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

// Diagnostics are gated through fixed-code allowlists; these tests bind the allowlists to the actual call sites (DIAG-001).

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
  const diagnostics = readFileSync(join(root, 'src-tauri', 'src', 'diagnostics.rs'), 'utf8')
  const allowedOperation = allowlistOf(diagnostics, 'allowed_operation')
  const allowedCode = allowlistOf(diagnostics, 'allowed_code')
  const allowedBrowserHost = allowlistOf(diagnostics, 'allowed_browser_host_code')
  const offenders = []

  for (const path of filesMatching(/\.(ts|svelte)$/, join(root, 'src'))) {
    const text = readFileSync(path, 'utf8')
    for (const site of callSites(text, 'recordDiagnostic')) {
      const [operation, code] = stringLiterals(site.slice)
      const where = `${relative(root, path)}:${locationOf(text, site.index)}`
      if (operation && !allowedOperation.has(operation)) {
        offenders.push(`${where} emits operation ${operation}`)
      }
      if (code && !allowedCode.has(code)) {
        offenders.push(`${where} emits code ${code}`)
      }
    }
  }

  const settings = readFileSync(join(root, 'src', 'lib', 'controllers', 'settings-controller.ts'), 'utf8')
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
      const code = stringLiterals(site.slice, false)[0]
      if (code && !allowedBrowserHost.has(code)) {
        offenders.push(`${relative(root, path)}:${locationOf(text, site.index)} emits code ${code}`)
      }
    }
  }

  assert.deepEqual(offenders, [], `diagnostic codes emitted outside the allowlists are rejected and never written:\n  ${offenders.join('\n  ')}`)
})

test('every allowlisted diagnostic code has an explicit severity classification', () => {
  const diagnostics = readFileSync(join(root, 'src-tauri', 'src', 'diagnostics.rs'), 'utf8')
  const allowed = new Set([
    ...allowlistOf(diagnostics, 'allowed_code'),
    ...allowlistOf(diagnostics, 'allowed_browser_host_code'),
  ])
  const classified = severityCodes(diagnostics)
  const missing = [...allowed].filter((code) => !classified.has(code)).sort()
  assert.deepEqual(missing, [], `allowlisted codes with no explicit severity default to info and are pruned after a day:\n  ${missing.join('\n  ')}`)
})

test('the account test build verifies the signed-capability browser fixture', async () => {
  const fixture = JSON.parse(readFileSync(join(root, 'account', 'tests', 'fixtures', 'signed-capability.json'), 'utf8'))
  const localCi = readFileSync(join(root, 'tools', 'run-ci-local.mjs'), 'utf8')
  const testKey = fixture.publicKey
  const ciKey = localCi.match(/VITE_SESAME_CAPABILITY_PUBLIC_KEY:\s*'([^']+)'/)?.[1]
  assert.ok(testKey && ciKey, 'a test capability key is no longer defined in both the fixture and CI')
  assert.equal(testKey, ciKey, 'the signed-capability fixture and run-ci-local.mjs use different test capability keys')

  const payload = fixture.payload
  const signature = fixture.signature
  assert.ok(payload && signature, 'the signed-capability fixture changed shape')

  const decode = (value) => {
    const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((value.length + 3) % 4)
    return Buffer.from(padded, 'base64')
  }
  const key = await webcrypto.subtle.importKey('raw', decode(testKey), { name: 'Ed25519' }, false, ['verify'])
  const verified = await webcrypto.subtle.verify('Ed25519', key, decode(signature), decode(payload))
  assert.ok(verified, 'the built-site capability key does not verify the signed-capability fixture, so the account-flow tests cannot pass')
})
