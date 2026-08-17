// Prints a skip notice for a test suite that does not exist yet, and
// optionally runs a build command first so the gate still exercises the build.
// Usage: node skip-with-message.mjs "<suite name>" ["<command to run first>"]
import { spawnSync } from 'node:child_process'
import process from 'node:process'

const [name, buildCommand] = process.argv.slice(2)
if (buildCommand) {
  const result = spawnSync(buildCommand, { shell: true, stdio: 'inherit' })
  if (result.status !== 0) process.exit(result.status ?? 1)
}
console.log(`no ${name} tests exist yet, skipping`)
