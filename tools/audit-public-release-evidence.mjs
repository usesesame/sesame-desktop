import { readFile, readdir, stat } from 'node:fs/promises'
import path from 'node:path'

const [directoryInput] = process.argv.slice(2)
if (!directoryInput) throw new Error('Usage: node tools/audit-public-release-evidence.mjs <public-evidence-directory>')
const root = path.resolve(directoryInput)
const files = await readdir(root)
const forbiddenExtensions = new Set(['.exe', '.sig', '.zip', '.sesame', '.pem', '.key', '.pfx', '.p12'])
const forbiddenText = [
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i,
  /TAURI_SIGNING_PRIVATE_KEY/i,
  /SESAME_RELEASE_CANDIDATE_SIGNING_KEY/i,
  /SESAME_RELEASE_CANDIDATE_TOKEN/i,
  /SESAME_RELEASES_REPOSITORY_TOKEN/i,
  /(?:master[_ -]?password|recovery[_ -]?kit|totp[_ -]?seed)\s*[:=]/i,
  /https?:\/\/(?:localhost|127\.0\.0\.1|[^/\s]+\.internal)(?:[/:\s]|$)/i,
]
for (const filename of files) {
  const location = path.join(root, filename)
  if (!(await stat(location)).isFile()) throw new Error(`Public evidence contains a non-file entry: ${filename}`)
  if (forbiddenExtensions.has(path.extname(filename).toLowerCase())) throw new Error(`Public evidence contains a forbidden file type: ${filename}`)
  const bytes = await readFile(location)
  if (bytes.includes(0)) throw new Error(`Public evidence contains an unexpected binary file: ${filename}`)
  const text = bytes.toString('utf8')
  for (const pattern of forbiddenText) if (pattern.test(text)) throw new Error(`Public evidence contains forbidden material in ${filename}.`)
}
process.stdout.write(`Audited ${files.length} public release evidence files.\n`)
