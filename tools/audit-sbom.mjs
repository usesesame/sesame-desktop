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
const hasPurl = (component) => typeof component.purl === 'string' && component.purl.length > 0

const ecosystemCounts = (components) => {
  const counts = {}
  for (const component of components) {
    const type = purlType(component.purl)
    counts[type] = (counts[type] ?? 0) + 1
  }
  return counts
}

const queryComponents = async (entries, { query, concurrency }) => {
  const results = new Array(entries.length)
  let cursor = 0
  const worker = async () => {
    while (cursor < entries.length) {
      const index = cursor
      cursor += 1
      const entry = entries[index]
      results[index] = { ...entry, vulnerabilities: await query(entry.component.purl) }
    }
  }
  const workers = Math.max(1, Math.min(concurrency, entries.length))
  await Promise.all(Array.from({ length: workers }, () => worker()))
  return results
}

const advisoryList = (results) =>
  results
    .filter((entry) => entry.vulnerabilities.length > 0)
    .map((entry) => ({
      name: entry.component.name,
      version: entry.component.version,
      purl: entry.component.purl,
      ids: entry.vulnerabilities.map((vulnerability) => vulnerability.id).filter(Boolean),
    }))

const publicAdvisory = (entry) => ({
  label: entry.label,
  name: entry.name,
  version: entry.version,
  purl: entry.purl,
  ids: entry.ids,
})

export const collectAdvisories = async (bom, { query = queryOsv, concurrency = 8 } = {}) => {
  const components = Array.isArray(bom.components) ? bom.components : []
  const queried = components.filter(hasPurl)
  const results = await queryComponents(queried.map((component) => ({ component })), { query, concurrency })
  return {
    total: components.length,
    queried: queried.length,
    skipped: components.length - queried.length,
    byEcosystem: ecosystemCounts(queried),
    vulnerable: advisoryList(results),
  }
}

export const collectSbomAdvisories = async (sources, { query = queryOsv, concurrency = 8 } = {}) => {
  const entries = []
  const summaries = []
  for (const [index, source] of sources.entries()) {
    const components = Array.isArray(source.bom?.components) ? source.bom.components : []
    const queried = components.filter(hasPurl)
    summaries.push({
      label: source.label ?? null,
      total: components.length,
      queried: queried.length,
      skipped: components.length - queried.length,
      byEcosystem: ecosystemCounts(queried),
    })
    for (const component of queried) entries.push({ sourceIndex: index, component })
  }
  const results = await queryComponents(entries, { query, concurrency })
  const vulnerable = results
    .filter((entry) => entry.vulnerabilities.length > 0)
    .map((entry) => ({
      sourceIndex: entry.sourceIndex,
      label: summaries[entry.sourceIndex].label,
      name: entry.component.name,
      version: entry.component.version,
      purl: entry.component.purl,
      ids: entry.vulnerabilities.map((vulnerability) => vulnerability.id).filter(Boolean),
    }))
  const byEcosystem = {}
  for (const summary of summaries) {
    for (const [type, count] of Object.entries(summary.byEcosystem)) {
      byEcosystem[type] = (byEcosystem[type] ?? 0) + count
    }
  }
  return {
    sources: summaries.map((summary, index) => ({
      ...summary,
      vulnerable: vulnerable
        .filter((entry) => entry.sourceIndex === index)
        .map(publicAdvisory),
    })),
    total: summaries.reduce((sum, summary) => sum + summary.total, 0),
    queried: summaries.reduce((sum, summary) => sum + summary.queried, 0),
    skipped: summaries.reduce((sum, summary) => sum + summary.skipped, 0),
    byEcosystem,
    vulnerable: vulnerable.map(publicAdvisory),
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

export const auditSboms = async (sources, options) => {
  const report = await collectSbomAdvisories(sources, options)
  if (report.vulnerable.length > 0) {
    const lines = report.vulnerable.map(
      (component) =>
        `${component.label ? `${component.label}: ` : ''}${component.name}@${component.version}: ${component.ids.join(', ')}`,
    )
    const error = new Error(`The SBOMs list components with OSV advisories:\n${lines.join('\n')}`)
    error.report = report
    throw error
  }
  return report
}

const sbomPaths = () => {
  const paths = []
  for (let index = 0; index < process.argv.length; index += 1) {
    if (process.argv[index] === '--sbom' && process.argv[index + 1]) paths.push(process.argv[index + 1])
  }
  return paths.length > 0 ? paths : [defaultSbomPath()]
}

const formatEcosystems = (byEcosystem) =>
  Object.entries(byEcosystem)
    .map(([type, count]) => `${type} ${count}`)
    .join(', ')

const main = async () => {
  const sources = []
  for (const sbomPath of sbomPaths()) {
    const resolved = path.resolve(sbomPath)
    sources.push({ label: resolved, bom: JSON.parse(await readFile(resolved, 'utf8')) })
  }
  const report = await collectSbomAdvisories(sources)
  for (const source of report.sources) {
    process.stdout.write(`Audited ${source.label}\n`)
    process.stdout.write(
      `Queried ${source.queried} of ${source.total} components (${source.skipped} without a purl; ${formatEcosystems(source.byEcosystem)}).\n`,
    )
  }
  if (report.sources.length > 1) {
    process.stdout.write(
      `Combined: queried ${report.queried} of ${report.total} components against OSV (${report.skipped} without a purl; ${formatEcosystems(report.byEcosystem)}).\n`,
    )
  }
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
