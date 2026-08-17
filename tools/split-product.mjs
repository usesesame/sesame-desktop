import { spawnSync } from 'node:child_process'
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { repositoryFiles } from './repository-files.mjs'

const root = dirname(dirname(fileURLToPath(import.meta.url)))

const PRODUCTS = {
  extension: {
    repository: 'usesesame/sesame-browser-extension',
    copy: [['extensions/sesame', '']],
    required: [
      '.gitignore', '.gitattributes', '.node-version', 'LICENSE', 'README.md', 'SECURITY.md',
      'CONTRIBUTING.md', 'package.json', 'package-lock.json', 'eslint.config.js',
      'tsconfig.json', '.github/workflows/ci.yml', '.github/CODEOWNERS',
      'contracts/browser/v1/SOURCE.json', 'contracts/native-host.json',
    ],
    forbidden: [/\.rs$/, /^Cargo\.toml$/],
    verify: ['npm ci', 'npm run release:check'],
  },
  server: {
    repository: 'usesesame/sesame-server',
    copy: [['backend', ''], ['admin', 'web/admin'], ['account', 'web/account']],
    required: [
      // A standalone clone has no parent ignore list to fall back on, so a
      // missing .gitignore here means the first `git add -A` commits
      // node_modules and Go build output.
      '.gitignore', '.gitattributes',
      'README.md', 'SECURITY.md', 'go.mod', 'go.sum', 'package.json',
      'package-lock.json', 'Dockerfile', 'scripts/setup.mjs',
      'deploy/compose/compose.yaml', 'openapi/openapi.json', '.github/CODEOWNERS',
      'web/account/package.json', 'web/account/Dockerfile',
      'web/admin/package.json', 'web/admin/Dockerfile',
    ],
    forbidden: [/\.rs$/, /^Cargo\.toml$/],
    verify: ['npm install --no-audit --no-fund', 'npm run setup'],
  },
  website: {
    repository: 'usesesame/sesame-website',
    copy: [['website', '']],
    required: [
      '.gitignore', '.gitattributes', '.node-version', 'LICENSE', 'README.md', 'SECURITY.md',
      'package.json', 'package-lock.json', 'eslint.config.js', 'tsconfig.json',
      '.github/workflows/ci.yml', '.github/CODEOWNERS',
    ],
    forbiddenContent: [
      ['auth', /\bsignIn\b|\bsignOut\b|loadAuthState/],
      ['session', /credentials:\s*'include'/],
      ['CSRF', /X-Sesame-CSRF/],
      ['passkey', /navigator\.credentials/],
      ['signing', /privateKey|signingKey\b|subtle\.sign/],
    ],
    verify: ['npm ci', 'npm run ci'],
  },
  desktop: {
    repository: 'usesesame/sesame-desktop',
    copyEverythingExcept: ['extensions', 'backend', 'admin', 'account', 'website'],
    required: [
      '.gitignore', '.gitattributes', '.node-version', 'LICENSE', 'README.md', 'CONTRIBUTING.md',
      'package.json', 'package-lock.json', 'desktop-boundary.json',
      'src-tauri/src/adapters/platform/browser_host.rs',
      '.github/workflows/ci.yml', '.github/CODEOWNERS',
    ],
    verify: ['npm ci', 'npm run desktop:ci'],
  },
}

const argv = process.argv.slice(2)
const flags = new Set(argv.filter((value) => value.startsWith('--')))
const [name, target] = argv.filter((value) => !value.startsWith('--'))
const product = PRODUCTS[name]
if (!product || !target) {
  console.error(`Usage: node tools/split-product.mjs <${Object.keys(PRODUCTS).join('|')}> <destination> [--verify] [--force]`)
  process.exit(2)
}
const destination = resolve(target)

const CLEAN_BUILD_ENVIRONMENT = {
  VITE_SESAME_SITE_ORIGIN: 'https://website.test.invalid',
  VITE_SESAME_API_URL: 'https://api.test.invalid',
  VITE_SESAME_ACCOUNT_URL: 'https://account.test.invalid',
  VITE_SESAME_PRIVACY_EMAIL: 'privacy@website.test.invalid',
  VITE_SESAME_CAPABILITY_PUBLIC_KEY: 'A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg',
  SESAME_API_BASE_URL: 'https://api.test.invalid',
}

function run(command, cwd) {
  const result = spawnSync(command, {
    cwd,
    env: { ...CLEAN_BUILD_ENVIRONMENT, ...process.env },
    encoding: 'utf8',
    stdio: 'inherit',
    shell: true,
  })
  if (result.status !== 0) throw new Error(`${command} failed in ${cwd}`)
}

function gitIgnoredFiles(files) {
  if (files.length === 0) return new Set()
  const result = spawnSync('git', ['check-ignore', '--stdin', '-z'], {
    cwd: root,
    input: files.join('\0'),
    encoding: 'utf8',
  })
  if (result.error || result.status === 128) return new Set()
  return new Set(result.stdout.split('\0').filter(Boolean))
}

const failures = []
const check = (condition, message) => {
  if (!condition) failures.push(message)
}

if (existsSync(destination) && readdirSync(destination).length > 0) {
  if (!flags.has('--force')) {
    throw new Error(`${destination} already exists and is not empty. Pass --force to replace its contents.`)
  }
  // Replace the contents, never the repository. Once a destination has been
  // initialised and pushed, its .git holds the only copy of that history and
  // its remote; deleting it to refresh the files would be an unrecoverable
  // way to do a routine update.
  for (const entry of readdirSync(destination)) {
    if (entry === '.git') continue
    rmSync(join(destination, entry), { recursive: true, force: true })
  }
  if (existsSync(join(destination, '.git'))) {
    console.log('Kept the existing .git: this refreshes the working tree, and leaves history and remotes alone.')
  }
}
mkdirSync(destination, { recursive: true })

const all = repositoryFiles('*')
const ignored = gitIgnoredFiles(all)
if (ignored.size > 0) {
  console.log(`Leaving ${ignored.size} git-ignored file(s) behind: ${[...ignored].sort().join(', ')}`)
}
const included = all.filter((file) => !ignored.has(file))
let copied = 0
if (product.copyEverythingExcept) {
  for (const file of included) {
    if (product.copyEverythingExcept.some((skip) => file === skip || file.startsWith(`${skip}/`))) continue
    const to = join(destination, file.split('/').join(sep))
    mkdirSync(dirname(to), { recursive: true })
    cpSync(join(root, file.split('/').join(sep)), to)
    copied += 1
  }
} else {
  for (const [from, into] of product.copy) {
    for (const file of included) {
      if (file !== from && !file.startsWith(`${from}/`)) continue
      const within = file.slice(from.length + 1)
      const to = join(destination, into.split('/').join(sep), within.split('/').join(sep))
      mkdirSync(dirname(to), { recursive: true })
      cpSync(join(root, file.split('/').join(sep)), to)
      copied += 1
    }
  }
}
console.log(`Copied ${copied} files into ${destination}`)

if (name === 'desktop') {
  const workflows = join(destination, '.github', 'workflows')
  const future = join(workflows, 'future-desktop.yml')
  if (existsSync(future)) {
    cpSync(future, join(workflows, 'ci.yml'))
    rmSync(future)
    const manifest = join(destination, 'desktop-boundary.json')
    writeFileSync(manifest, readFileSync(manifest, 'utf8')
      .replace('.github/workflows/future-desktop.yml', '.github/workflows/ci.yml'), 'utf8')
  }
  for (const file of readdirSync(workflows)) {
    const body = readFileSync(join(workflows, file), 'utf8')
    if (product.copyEverythingExcept.some((moved) => body.includes(`${moved}/`))) {
      rmSync(join(workflows, file))
      console.log(`Removed .github/workflows/${file}: it builds a product that moved.`)
    }
  }

  const manifestPath = join(destination, 'package.json')
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
  const reaches = (command, seen = new Set()) => {
    if (seen.has(command)) return false
    seen.add(command)
    const body = manifest.scripts[command]
    if (!body) return false
    if (product.copyEverythingExcept.some((moved) => new RegExp(`(^|[\\s"'/=])${moved}[/\\s"']`).test(body))) return true
    return [...body.matchAll(/npm run ([a-z0-9:_-]+)/g)].some(([, next]) => reaches(next, seen))
  }
  const pruned = Object.keys(manifest.scripts).filter((command) => reaches(command))
  for (const command of pruned) delete manifest.scripts[command]
  manifest.name = 'sesame-desktop'
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
  console.log(`Removed ${pruned.length} commands that reached a product that moved.`)
}

const landed = repositoryFilesIn(destination)
function repositoryFilesIn(directory) {
  const found = []
  const walk = (current) => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (!['node_modules', '.git', 'dist', 'target'].includes(entry.name)) walk(join(current, entry.name))
        continue
      }
      found.push(relative(directory, join(current, entry.name)).split(sep).join('/'))
    }
  }
  walk(directory)
  return found
}

for (const file of product.required) {
  check(landed.includes(file), `${product.repository} needs ${file}`)
}
for (const pattern of product.forbidden ?? []) {
  const offender = landed.find((file) => pattern.test(file))
  check(!offender, `${offender} must not travel with ${product.repository}`)
}
for (const [label, pattern] of product.forbiddenContent ?? []) {
  for (const file of landed.filter((f) => /\.(ts|svelte|mjs|js)$/.test(f))) {
    check(!pattern.test(readFileSync(join(destination, file.split('/').join(sep)), 'utf8')),
      `${file} still contains ${label} code`)
  }
}
for (const sibling of ['extensions', 'backend', 'admin', 'account', 'website', 'src-tauri']) {
  if (name === 'desktop' && sibling === 'src-tauri') continue
  if (name === 'server' && sibling === 'account') continue
  check(!existsSync(join(destination, sibling)), `${sibling}/ must not travel with ${product.repository}`)
}

if (flags.has('--verify')) {
  console.log(`Verifying in ${destination}, whose parent holds: ${readdirSync(dirname(destination)).join(', ') || 'nothing else'}`)
  for (const command of product.verify) run(command, destination)
}

console.log('')
console.log(`${product.repository}: ${landed.length} files`)
console.log('Nothing was deleted here, and no repository was created or pushed.')

if (failures.length > 0) {
  console.error('')
  console.error('Split gate failed:')
  for (const failure of failures) console.error(`  - ${failure}`)
  process.exit(1)
}
console.log('Split gate passed.')
