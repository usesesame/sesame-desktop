import { spawnSync } from 'node:child_process'

export function executableSuffix() {
  return process.platform === 'win32' ? '.exe' : ''
}

export function hostTargetTriple() {
  const probe = spawnSync('rustc', ['-vV'], { encoding: 'utf8', shell: false })
  if (probe.status !== 0) {
    throw new Error('Rust did not report a target triple.')
  }
  const line = probe.stdout.split(/\r?\n/).find((entry) => entry.startsWith('host:'))
  if (!line) {
    throw new Error('Rust did not report a target triple.')
  }
  return line.slice('host:'.length).trim()
}

export function buildBrowserHost({ manifest, release }) {
  // tauri-build validates every declared sidecar, and this is the command that
  // produces the one it would look for.
  const environment = { ...process.env, TAURI_CONFIG: '{"bundle":{"externalBin":[]}}' }

  // Chromium launches the host directly and a clean Windows machine has no
  // VCRUNTIME140.dll. glibc targets cannot link the C runtime statically.
  if (process.platform === 'win32' && hostTargetTriple().endsWith('-msvc')) {
    const existing = process.env.RUSTFLAGS?.trim()
    environment.RUSTFLAGS = existing
      ? `${existing} -C target-feature=+crt-static`
      : '-C target-feature=+crt-static'
  }

  const args = ['build', '--manifest-path', manifest]
  if (release) args.push('--release')
  args.push('--features', 'browser-helper-dev', '--bin', 'sesame-browser-host')

  const build = spawnSync('cargo', args, { stdio: 'inherit', env: environment, shell: false })
  if (build.status !== 0) {
    throw new Error('The Sesame browser host build failed.')
  }
}
