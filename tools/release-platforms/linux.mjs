import { readdir } from 'node:fs/promises'
import path from 'node:path'

export const linuxFormats = ['appimage', 'deb', 'rpm']

const formatDirectories = {
  appimage: { directory: 'appimage', suffix: '.AppImage' },
  deb: { directory: 'deb', suffix: '.deb' },
  rpm: { directory: 'rpm', suffix: '.rpm' },
}

export async function discoverLinuxPackages(bundleRoot, architecture) {
  const packages = []
  for (const format of linuxFormats) {
    const definition = formatDirectories[format]
    const directory = path.resolve(bundleRoot, definition.directory)
    const entries = await readdir(directory, { withFileTypes: true })
    const matches = entries
      .filter((entry) => entry.isFile() && entry.name.endsWith(definition.suffix))
      .map((entry) => path.join(directory, entry.name))
      .sort()
    if (matches.length !== 1) {
      throw new Error(`Linux release discovery found ${matches.length} ${format} packages, expected exactly one.`)
    }
    packages.push({ format, architecture, path: matches[0], updaterCapable: false })
  }
  return packages
}
