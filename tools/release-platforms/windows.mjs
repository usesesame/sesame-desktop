import { readdir, stat } from 'node:fs/promises'
import path from 'node:path'

export const windowsFormats = ['nsis']

export async function discoverWindowsPackages(bundleRoot, architecture) {
  const directory = path.resolve(bundleRoot, 'nsis')
  const entries = await readdir(directory, { withFileTypes: true })
  const installers = entries
    .filter((entry) => entry.isFile() && entry.name.endsWith('-setup.exe'))
    .map((entry) => path.join(directory, entry.name))
    .sort()
  if (installers.length !== 1) {
    throw new Error(`Windows release discovery found ${installers.length} NSIS installers, expected exactly one.`)
  }
  const updaterSignaturePath = `${installers[0]}.sig`
  try {
    if (!(await stat(updaterSignaturePath)).isFile()) throw new Error()
  } catch {
    throw new Error('Windows release discovery did not find a regular NSIS updater signature file.')
  }
  return [{
    format: 'nsis',
    architecture,
    path: installers[0],
    updaterCapable: true,
    updaterSignaturePath,
  }]
}
