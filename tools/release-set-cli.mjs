import { readFile, writeFile } from 'node:fs/promises'

import { discoverLinuxPackages } from './release-platforms/linux.mjs'
import { discoverWindowsPackages } from './release-platforms/windows.mjs'
import { reconcileReleaseSet, verifyReleaseSet } from './release-set.mjs'

const [command, ...args] = process.argv.slice(2)

if (command === 'discover') {
  const [platform, bundleRoot, architecture, output] = args
  if (!platform || !bundleRoot || !architecture || !output) throw new Error('Usage: release-set-cli.mjs discover <platform> <bundle-root> <architecture> <output>')
  const packages = platform === 'windows'
    ? await discoverWindowsPackages(bundleRoot, architecture)
    : platform === 'linux'
      ? await discoverLinuxPackages(bundleRoot, architecture)
      : (() => { throw new Error('Platform must be windows or linux.') })()
  await writeFile(output, `${JSON.stringify({ platform, architecture, packages }, null, 2)}\n`)
} else if (command === 'verify') {
  const [candidatePath] = args
  if (!candidatePath) throw new Error('Usage: release-set-cli.mjs verify <candidate>')
  verifyReleaseSet(JSON.parse(await readFile(candidatePath, 'utf8')))
} else if (command === 'reconcile') {
  const [expectedPath, actualPath] = args
  if (!expectedPath || !actualPath) throw new Error('Usage: release-set-cli.mjs reconcile <expected> <actual>')
  const result = reconcileReleaseSet(JSON.parse(await readFile(expectedPath, 'utf8')), JSON.parse(await readFile(actualPath, 'utf8')))
  process.stdout.write(`${JSON.stringify(result)}\n`)
  if (!result.complete) process.exitCode = 1
} else {
  throw new Error('Usage: release-set-cli.mjs <discover|verify|reconcile> ...')
}
