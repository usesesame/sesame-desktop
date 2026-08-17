import { spawn } from 'node:child_process'

const cleanBuildEnvironment = {
  VITE_SESAME_SITE_ORIGIN: 'https://website.test.invalid',
  VITE_SESAME_API_URL: 'https://api.test.invalid',
  VITE_SESAME_ACCOUNT_URL: 'https://account.test.invalid',
  VITE_SESAME_PRIVACY_EMAIL: 'privacy@website.test.invalid',
  // Test-only keypair; production requires an explicitly configured deployment key.
  VITE_SESAME_CAPABILITY_PUBLIC_KEY: 'A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg',
  SESAME_API_BASE_URL: 'https://api.test.invalid',
}

const windows = process.platform === 'win32'
const child = spawn(
  windows ? (process.env.ComSpec ?? 'cmd.exe') : 'npm',
  windows ? ['/d', '/s', '/c', 'npm.cmd run ci:local:configured'] : ['run', 'ci:local:configured'],
  { env: { ...cleanBuildEnvironment, ...process.env }, stdio: 'inherit' },
)
child.on('error', () => { process.exitCode = 1 })
child.on('exit', (code, signal) => { process.exitCode = code ?? (signal ? 1 : 0) })
