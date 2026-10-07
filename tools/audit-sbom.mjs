import { readFileSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(import.meta.dirname, '..')
const osvEndpoint = 'https://api.osv.dev/v1/query'

export const defaultSbomPath = (base = root) => {
  const version = JSON.parse(readFileSync(path.join(base, 'package.json'), 'utf8')).version
  const directory = process.env.SESAME_SBOM_OUTPUT_DIR
    ? path.resolve(process.env.SESAME_SBOM_OUTPUT_DIR)
    : path.join(base, 'release-evidence')
  return path.join(directory, `sesame-${version}.cdx.json`)
}

export const queryOsv = async (purl) => {
  const response = await fetch(osvEndpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ package: { purl } }),
  })
  if (!response.ok) throw new Error(`OSV query for ${purl} failed with HTTP ${response.status}`)
  const body = await response.json()
  return body.vulns ?? []
}

const purlType = (purl) => purl.slice('pkg:'.length).split('/')[0]

export const collectAdvisories = async (bom, { query = queryOsv, concurrency = 8 } = {}) => {
  const components = Array.isArray(bom.components) ? bom.components : []
  const queried = components.filter(
    (component) => typeof component.purl === 'string' && component.purl.length > 0,
  )
  const byEcosystem = {}
  for (const component of queried) {
    const type = purlType(component.purl)
    byEcosystem[type] = (byEcosystem[type] ?? 0) + 1
  }
  const results = new Array(queried.length)
  let cursor = 0
  const worker = async () => {
    while (cursor < queried.length) {
      const index = cursor
      cursor += 1
      const component = queried[index]
      results[index] = { component, vulnerabilities: await query(component.purl) }
    }
  }
  const workers = Math.max(1, Math.min(concurrency, queried.length))
  await Promise.all(Array.from({ length: workers }, () => worker()))
  const vulnerable = results
    .filter((entry) => entry.vulnerabilities.length > 0)
    .map((entry) => ({
      name: entry.component.name,
      version: entry.component.version,
      purl: entry.component.purl,
      ids: entry.vulnerabilities.map((vulnerability) => vulnerability.id).filter(Boolean),
    }))
  return {
    total: components.length,
    queried: queried.length,
    skipped: components.length - queried.length,
    byEcosystem,
    vulnerable,
  }
}

export const auditSbom = async (bom, options) => {
  const report = await collectAdvisories(bom, options)
  if (report.vulnerable.length > 0) {
    const lines = report.vulnerable.map(
      (component) => `${component.name}@${component.version}: ${component.ids.join(', ')}`,
    )
    const error = new Error(`The SBOM lists components with OSV advisories:\n${lines.join('\n')}`)
    error.report = report
    throw error
  }
  return report
}

const argument = (name) => {
  const index = process.argv.indexOf(name)
  return index === -1 ? undefined : process.argv[index + 1]
}

const main = async () => {
  const sbomPath = path.resolve(argument('--sbom') ?? defaultSbomPath())
  const bom = JSON.parse(await readFile(sbomPath, 'utf8'))
  const report = await collectAdvisories(bom)
  const ecosystems = Object.entries(report.byEcosystem)
    .map(([type, count]) => `${type} ${count}`)
    .join(', ')
  process.stdout.write(`Audited ${sbomPath}\n`)
  process.stdout.write(
    `Queried ${report.queried} of ${report.total} components against OSV (${report.skipped} without a purl; ${ecosystems}).\n`,
  )
  if (report.vulnerable.length > 0) {
    for (const component of report.vulnerable) {
      process.stdout.write(`${component.name}@${component.version}: ${component.ids.join(', ')}\n`)
    }
    process.exitCode = 1
    return
  }
  process.stdout.write('No OSV advisories found.\n')
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main()
}
