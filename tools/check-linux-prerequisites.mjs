#!/usr/bin/env node
import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import process from 'node:process'

if (process.platform !== 'linux') {
  process.stderr.write('Linux desktop prerequisites can only be checked on Linux.\n')
  process.exit(1)
}

const bundle = process.argv.includes('--bundle')
const commands = ['cargo', 'rustc', 'pkg-config', 'cc', 'make', 'file', 'curl', 'wget', 'xdg-open', 'secret-tool']
if (bundle) commands.push('patchelf', 'dpkg-deb', 'rpmbuild')
const packages = ['webkit2gtk-4.1', 'javascriptcoregtk-4.1', 'libsoup-3.0', 'gtk+-3.0', 'ayatana-appindicator3-0.1', 'librsvg-2.0', 'dbus-1']
const missing = []

for (const command of commands) {
  const result = spawnSync(command, ['--version'], { stdio: 'ignore', shell: false })
  if (result.error?.code === 'ENOENT') missing.push(`command: ${command}`)
}

for (const packageName of packages) {
  const result = spawnSync('pkg-config', ['--exists', packageName], { stdio: 'ignore', shell: false })
  if (result.status !== 0) missing.push(`pkg-config: ${packageName}`)
}

if (missing.length > 0) {
  process.stderr.write(`Missing Linux desktop prerequisites:\n${missing.map((item) => `  ${item}`).join('\n')}\n`)
  if (existsSync('/etc/arch-release')) {
    process.stderr.write('Install Arch development prerequisites:\n  sudo pacman -S --needed webkit2gtk-4.1 base-devel curl wget file openssl libayatana-appindicator librsvg libsecret xdg-utils\n')
    if (bundle) process.stderr.write('Install Arch packaging prerequisites:\n  sudo pacman -S --needed patchelf dpkg rpm-tools\n')
  }
  process.exit(1)
}

process.stdout.write('Linux desktop prerequisites are available.\n')
