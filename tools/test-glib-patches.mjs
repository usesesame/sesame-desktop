import { spawnSync } from 'node:child_process'

if (process.platform !== 'linux') {
  process.stdout.write('The vendored glib patches only exist in Linux builds, so there is nothing to test on this system.\n')
  process.exit(0)
}

const result = spawnSync(
  'cargo',
  ['test', '--manifest-path', 'src-tauri/Cargo.toml', '--release', '--test', 'glib_patch', '--locked'],
  { stdio: 'inherit' },
)
process.exit(result.status ?? 1)
