// Fresh-checkout defaults; production website builds must receive deployment-owned origins.
import { spawn } from 'node:child_process'

export const cleanBuildEnvironment = Object.freeze({
  VITE_SESAME_SITE_ORIGIN: 'https://website.test.invalid',
  VITE_SESAME_API_URL: 'https://api.test.invalid',
  VITE_SESAME_PRIVACY_EMAIL: 'privacy@website.test.invalid',
  SESAME_API_BASE_URL: 'https://api.test.invalid',
})

export function withCleanBuildEnvironment(environment = process.env) {
  return {
    ...cleanBuildEnvironment,
    ...environment,
  }
}

if (process.argv[2] === '--print-environment') {
  process.stdout.write(`${JSON.stringify(withCleanBuildEnvironment({}))}\n`)
} else {
  const windows = process.platform === 'win32'
  const command = windows ? (process.env.ComSpec ?? 'cmd.exe') : 'npm'
  const args = windows
    ? ['/d', '/s', '/c', 'npm.cmd run workspace:check:configured']
    : ['run', 'workspace:check:configured']
  const child = spawn(command, args, {
    env: withCleanBuildEnvironment(),
    stdio: 'inherit',
  })
  child.on('error', (error) => {
    console.error(`Could not start the workspace check: ${error.message}`)
    process.exitCode = 1
  })
  child.on('exit', (code, signal) => {
    process.exitCode = code ?? (signal ? 1 : 0)
  })
}
