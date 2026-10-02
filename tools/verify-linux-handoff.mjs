import { validateLinuxHandoffPackageBytes } from './linux-release-evidence.mjs'

const [directory, manifestFilename] = process.argv.slice(2)
if (!directory || !manifestFilename) {
  console.error('Usage: node tools/verify-linux-handoff.mjs <handoff-directory> <manifest-filename>')
  process.exit(2)
}
try {
  const manifest = await validateLinuxHandoffPackageBytes(directory, manifestFilename)
  process.stdout.write(`Verified ${manifest.artifacts.length} Linux packages and both lifecycle records against ${manifestFilename}.\n`)
} catch (error) {
  console.error(`Linux handoff verification failed: ${error.message}`)
  process.exit(1)
}
