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

export const allowlistPath = path.join(root, 'tools', 'sbom-advisory-allowlist.json')

const MAX_ALLOWLIST_DAYS = 90
const isoDate = /^\d{4}-\d{2}-\d{2}$/
const ubuntuRelease = /^Ubuntu:\d{2}\.\d{2}(:LTS)?$/
const waitingPriorities = new Set(['negligible', 'low', 'medium'])
const dayNumber = (value) => Date.parse(`${value}T00:00:00Z`) / 86_400_000
const isCalendarDate = (value) => {
  if (!isoDate.test(value ?? '')) return false
  const parsed = new Date(`${value}T00:00:00Z`)
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value
}

const requireReviewWindow = (entry, kind) => {
  if (!isCalendarDate(entry.reviewed) || !isCalendarDate(entry.expires)) {
    throw new Error(`Every ${kind} needs a reviewed date and an expiry date as YYYY-MM-DD: ${JSON.stringify(entry)}`)
  }
  const days = dayNumber(entry.expires) - dayNumber(entry.reviewed)
  if (!(days > 0 && days <= MAX_ALLOWLIST_DAYS)) {
    throw new Error(`Every ${kind} must expire within ${MAX_ALLOWLIST_DAYS} days after it was reviewed: ${JSON.stringify(entry)}`)
  }
}

const requireText = (entry, fields, kind) => {
  for (const field of fields) {
    if (typeof entry[field] !== 'string' || entry[field].length === 0) {
      throw new Error(`Every ${kind} needs ${fields.join(', ')}: ${JSON.stringify(entry)}`)
    }
  }
}

export const loadAllowlist = (file = allowlistPath) => {
  const parsed = JSON.parse(readFileSync(file, 'utf8'))
  const entries = Array.isArray(parsed.entries) ? parsed.entries : []
  for (const entry of entries) {
    requireText(entry, ['id', 'package', 'reason', 'reviewed'], 'allowlist entry')
    requireReviewWindow(entry, 'allowlist entry')
  }
  return entries
}

export const loadUnfixedLibraryRules = (file = allowlistPath) => {
  const section = JSON.parse(readFileSync(file, 'utf8')).awaitingUbuntuFix
  if (section === undefined) return { release: null, libraries: [] }
  const libraries = Array.isArray(section.libraries) ? section.libraries : []
  if (!ubuntuRelease.test(section.release ?? '')) {
    throw new Error('The libraries that wait on an Ubuntu fix need the Ubuntu release the AppImage is built on.')
  }
  for (const library of libraries) {
    requireText(library, ['package', 'reason', 'reviewed'], 'library rule')
    requireReviewWindow(library, 'library rule')
  }
  return { release: section.release, libraries }
}

const hasFix = (affected) =>
  (affected.ranges ?? []).some((range) => (range.events ?? []).some((event) => 'fixed' in event))

export const awaitsUbuntuFix = (vulnerability, component, release) => {
  if (!component.purl.startsWith('pkg:deb/ubuntu/')) return false
  const priority = (vulnerability.severity ?? []).find((severity) => severity.type === 'Ubuntu')?.score
  if (!waitingPriorities.has(priority)) return false
  const affected = (vulnerability.affected ?? []).filter(
    (entry) => entry.package?.ecosystem === release && entry.package?.name === component.name,
  )
  return affected.length > 0 && !affected.some(hasFix)
}

export const queryOsv = async (purl) => {
  const vulnerabilities = []
  const seenTokens = new Set()
  let pageToken
  do {
    const request = { package: { purl } }
    if (pageToken) request.page_token = pageToken
    const response = await fetch(osvEndpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(request),
    })
    if (!response.ok) throw new Error(`OSV query for ${purl} failed with HTTP ${response.status}`)
    const body = await response.json()
    vulnerabilities.push(...(body.vulns ?? []))
    pageToken = body.next_page_token
    if (pageToken) {
      if (seenTokens.has(pageToken)) {
        throw new Error(`OSV query for ${purl} returned a repeated continuation token`)
      }
      seenTokens.add(pageToken)
    }
  } while (pageToken)
  return vulnerabilities
}

const purlType = (purl) => purl.slice('pkg:'.length).split('/')[0]
const hasPurl = (component) => typeof component.purl === 'string' && component.purl.length > 0
const neverCompiled = (component) =>
  typeof component.purl === 'string' &&
  component.purl.startsWith('pkg:cargo/') &&
  (component.properties ?? []).some(
    (property) => property.name === 'sesame:cargo-build' && property.value === 'never-compiled',
  )
const audited = (component) => hasPurl(component) && !neverCompiled(component)
const propertyValues = (component, name) =>
  (component.properties ?? []).filter((property) => property.name === name).map((property) => property.value)

export const arrivesTransitively = (component) => {
  if (typeof component.purl !== 'string' || !component.purl.startsWith('pkg:cargo/')) return false
  const roles = propertyValues(component, 'sesame:cargo-dependency')
  return roles.length > 0 && roles.every((role) => role === 'transitive')
}

export const resourceExhaustionWeaknesses = new Set(['CWE-1333', 'CWE-400', 'CWE-405', 'CWE-407', 'CWE-770', 'CWE-834'])

export const neverShips = (component) =>
  typeof component.purl === 'string' && component.purl.startsWith('pkg:npm/') && component.scope === 'excluded'

export const onlyResourceExhaustion = (weaknesses) =>
  Array.isArray(weaknesses) &&
  weaknesses.length > 0 &&
  weaknesses.every((weakness) => resourceExhaustionWeaknesses.has(weakness))

const rustsecId = /^RUSTSEC-\d{4}-\d{4,}$/
const isEmptyList = (value) => value === undefined || value === null || (Array.isArray(value) && value.length === 0)

export const onlyUnmaintained = (vulnerability, component) => {
  if (!rustsecId.test(vulnerability.id ?? '')) return false
  if (!isEmptyList(vulnerability.aliases) || !isEmptyList(vulnerability.severity)) return false
  if (!isEmptyList(vulnerability.database_specific?.cwe_ids)) return false
  const affected = vulnerability.affected
  if (!Array.isArray(affected) || affected.length === 0) return false
  return affected.every((entry) => {
    const facts = entry?.database_specific ?? {}
    const effects = entry?.ecosystem_specific ?? {}
    return (
      entry.package?.ecosystem === 'crates.io' &&
      entry.package?.name === component.name &&
      facts.informational === 'unmaintained' &&
      (facts.cvss === undefined || facts.cvss === null) &&
      isEmptyList(facts.categories) &&
      (effects.affected_functions === undefined || effects.affected_functions === null) &&
      isEmptyList(effects.affects?.functions) &&
      isEmptyList(entry.severity)
    )
  })
}

const ecosystemCounts = (components) => {
  const counts = {}
  for (const component of components) {
    const type = purlType(component.purl)
    counts[type] = (counts[type] ?? 0) + 1
  }
  return counts
}

const osvTime = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/

export const isWithdrawn = (vulnerability, now = Date.now()) => {
  const value = vulnerability?.withdrawn
  if (typeof value !== 'string' || !osvTime.test(value)) return false
  const time = Date.parse(value)
  if (!Number.isFinite(time) || new Date(time).toISOString().slice(0, 19) !== value.slice(0, 19)) return false
  return time <= now
}

const queryComponents = async (entries, { query, concurrency, now = Date.now() }) => {
  const results = new Array(entries.length)
  let cursor = 0
  const worker = async () => {
    while (cursor < entries.length) {
      const index = cursor
      cursor += 1
      const entry = entries[index]
      const found = await query(entry.component.purl)
      results[index] = {
        ...entry,
        vulnerabilities: found.filter((vulnerability) => !isWithdrawn(vulnerability, now)),
        withdrawn: found.filter((vulnerability) => isWithdrawn(vulnerability, now)),
      }
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

const withdrawnList = (results) =>
  results
    .filter((entry) => entry.withdrawn.length > 0)
    .map((entry) => ({
      label: entry.label ?? null,
      name: entry.component.name,
      version: entry.component.version,
      purl: entry.component.purl,
      ids: entry.withdrawn.map((vulnerability) => vulnerability.id ?? 'an advisory without an id'),
    }))

const publicAdvisory = (entry) => ({
  label: entry.label,
  name: entry.name,
  version: entry.version,
  purl: entry.purl,
  ids: entry.ids,
})

export const collectAdvisories = async (bom, { query = queryOsv, concurrency = 8, now } = {}) => {
  const components = Array.isArray(bom.components) ? bom.components : []
  const queried = components.filter(audited)
  const results = await queryComponents(queried.map((component) => ({ component })), { query, concurrency, now })
  return {
    total: components.length,
    queried: queried.length,
    skipped: components.filter((component) => !hasPurl(component)).length,
    neverCompiled: components.filter(neverCompiled).length,
    byEcosystem: ecosystemCounts(queried),
    vulnerable: advisoryList(results),
    withdrawn: withdrawnList(results),
  }
}

export const collectSbomAdvisories = async (
  sources,
  {
    query = queryOsv,
    concurrency = 8,
    allowlist: configured = [],
    unfixed = { release: null, libraries: [] },
    today = new Date().toISOString().slice(0, 10),
    now,
  } = {},
) => {
  const lapsed = (rule) => typeof rule.expires === 'string' && rule.expires < today
  const expired = configured.filter(lapsed)
  const allowlist = configured.filter((rule) => !lapsed(rule))
  const expiredLibraries = unfixed.libraries.filter(lapsed)
  const libraries = unfixed.libraries.filter((rule) => !lapsed(rule))
  const entries = []
  const summaries = []
  for (const [index, source] of sources.entries()) {
    const components = Array.isArray(source.bom?.components) ? source.bom.components : []
    const queried = components.filter(audited)
    summaries.push({
      label: source.label ?? null,
      total: components.length,
      queried: queried.length,
      skipped: components.filter((component) => !hasPurl(component)).length,
      neverCompiled: components.filter(neverCompiled).length,
      byEcosystem: ecosystemCounts(queried),
    })
    for (const component of queried) entries.push({ sourceIndex: index, label: source.label ?? null, component })
  }
  const results = await queryComponents(entries, { query, concurrency, now })
  const usedRules = new Set()
  const usedLibraries = new Set()
  const coverage = (component, vulnerability) => {
    const rule = allowlist.find((entry) => entry.id === vulnerability.id && entry.package === component.name)
    if (rule) {
      usedRules.add(rule)
      return 'reviewed'
    }
    const library = libraries.find((entry) => entry.package === component.name)
    if (library && awaitsUbuntuFix(vulnerability, component, unfixed.release)) {
      usedLibraries.add(library)
      return 'waiting'
    }
    if (arrivesTransitively(component) && onlyUnmaintained(vulnerability, component)) return 'unmaintained'
    if (neverShips(component) && onlyResourceExhaustion(vulnerability.database_specific?.cwe_ids)) return 'build-tool'
    return null
  }
  const vulnerable = results
    .filter((entry) => entry.vulnerabilities.length > 0)
    .map((entry) => {
      const identified = entry.vulnerabilities.filter((vulnerability) => vulnerability.id)
      const covered = identified.map((vulnerability) => coverage(entry.component, vulnerability))
      return {
        sourceIndex: entry.sourceIndex,
        label: summaries[entry.sourceIndex].label,
        name: entry.component.name,
        version: entry.component.version,
        purl: entry.component.purl,
        ids: identified.map((vulnerability) => vulnerability.id),
        pulledInBy: propertyValues(entry.component, 'sesame:cargo-pulled-in-by').join(', '),
        weaknesses: Object.fromEntries(identified.map((vulnerability) => [vulnerability.id, vulnerability.database_specific?.cwe_ids])),
        idsCoveredBy: (kind) => identified.filter((_, index) => covered[index] === kind).map((vulnerability) => vulnerability.id),
        cleared: covered.length > 0 && covered.every(Boolean),
      }
    })
  const byEcosystem = {}
  for (const summary of summaries) {
    for (const [type, count] of Object.entries(summary.byEcosystem)) {
      byEcosystem[type] = (byEcosystem[type] ?? 0) + count
    }
  }
  const allowed = vulnerable.filter((entry) => entry.cleared)
  const fatal = vulnerable.filter((entry) => !entry.cleared)
  const unused = allowlist.filter((rule) => !usedRules.has(rule))
  const unusedLibraries = libraries.filter((rule) => !usedLibraries.has(rule))
  const withIds = (entries, pick) =>
    entries.map((entry) => ({ ...publicAdvisory(entry), ids: pick(entry) })).filter((entry) => entry.ids.length > 0)
  const waiting = withIds(vulnerable, (entry) => entry.idsCoveredBy('waiting'))
  const reviewed = withIds(allowed, (entry) => entry.idsCoveredBy('reviewed'))
  const unmaintained = vulnerable
    .map((entry) => ({ ...publicAdvisory(entry), ids: entry.idsCoveredBy('unmaintained'), pulledInBy: entry.pulledInBy }))
    .filter((entry) => entry.ids.length > 0)
  const buildTools = vulnerable
    .map((entry) => {
      const ids = entry.idsCoveredBy('build-tool')
      return { ...publicAdvisory(entry), ids, weaknesses: [...new Set(ids.flatMap((id) => entry.weaknesses[id]))].sort() }
    })
    .filter((entry) => entry.ids.length > 0)
  return {
    sources: summaries.map((summary, index) => ({
      ...summary,
      vulnerable: fatal
        .filter((entry) => entry.sourceIndex === index)
        .map(publicAdvisory),
    })),
    total: summaries.reduce((sum, summary) => sum + summary.total, 0),
    queried: summaries.reduce((sum, summary) => sum + summary.queried, 0),
    skipped: summaries.reduce((sum, summary) => sum + summary.skipped, 0),
    neverCompiled: summaries.reduce((sum, summary) => sum + summary.neverCompiled, 0),
    byEcosystem,
    vulnerable: fatal.map(publicAdvisory),
    withdrawn: withdrawnList(results),
    allowed: allowed.map(publicAdvisory),
    reviewed,
    waiting,
    unmaintained,
    buildTools,
    unused,
    unusedLibraries,
    expired,
    expiredLibraries,
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

export const auditSboms = async (sources, options = {}) => {
  const report = await collectSbomAdvisories(sources, {
    allowlist: loadAllowlist(),
    unfixed: loadUnfixedLibraryRules(),
    ...options,
  })
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
  const report = await collectSbomAdvisories(sources, {
    allowlist: loadAllowlist(),
    unfixed: loadUnfixedLibraryRules(),
  })
  for (const source of report.sources) {
    process.stdout.write(`Audited ${source.label}\n`)
    process.stdout.write(
      `Queried ${source.queried} of ${source.total} components (${source.skipped} without a purl; ${formatEcosystems(source.byEcosystem)}).\n`,
    )
    if (source.neverCompiled > 0) {
      process.stdout.write(
        `Left out ${source.neverCompiled} crates that the lock file lists and no build compiles.\n`,
      )
    }
  }
  if (report.sources.length > 1) {
    process.stdout.write(
      `Combined: queried ${report.queried} of ${report.total} components against OSV (${report.skipped} without a purl; ${formatEcosystems(report.byEcosystem)}).\n`,
    )
  }
  const withdrawnCount = report.withdrawn.reduce((sum, component) => sum + component.ids.length, 0)
  process.stdout.write(`Left out ${withdrawnCount} advisories that their publisher withdrew.\n`)
  for (const component of report.withdrawn) {
    process.stdout.write(`Withdrawn: ${component.name}@${component.version}: ${component.ids.join(', ')}\n`)
  }
  for (const component of report.reviewed) {
    process.stdout.write(
      `Allowed by review: ${component.name}@${component.version}: ${component.ids.join(', ')}\n`,
    )
  }
  for (const component of report.waiting) {
    process.stdout.write(
      `Waiting on an Ubuntu fix: ${component.name}@${component.version}: ${component.ids.join(', ')}\n`,
    )
  }
  for (const component of report.unmaintained) {
    process.stdout.write(
      `Unmaintained crate that only arrives through ${component.pulledInBy}: ${component.name}@${component.version}: ${component.ids.join(', ')}\n`,
    )
  }
  for (const component of report.buildTools) {
    process.stdout.write(
      `Resource exhaustion in a build tool that never ships: ${component.name}@${component.version}: ${component.ids.join(', ')} with ${component.weaknesses.join(', ')}\n`,
    )
  }
  for (const rule of report.expiredLibraries) {
    process.stdout.write(
      `Expired library rule: ${rule.package} expired on ${rule.expires}, review it again.\n`,
    )
  }
  for (const rule of report.unusedLibraries) {
    process.stdout.write(`Unused library rule: ${rule.package}, remove it or say why it stays.\n`)
  }
  for (const rule of report.expired) {
    process.stdout.write(
      `Expired allowlist entry: ${rule.id} for ${rule.package} expired on ${rule.expires}, review it again.\n`,
    )
  }
  for (const rule of report.unused) {
    process.stdout.write(
      `Unused allowlist entry: ${rule.id} for ${rule.package}, remove it or say why it stays.\n`,
    )
  }
  if (report.vulnerable.length > 0) {
    for (const component of report.vulnerable) {
      process.stdout.write(`${component.name}@${component.version}: ${component.ids.join(', ')}\n`)
    }
    process.exitCode = 1
    return
  }
  process.stdout.write(
    report.allowed.length > 0 ? 'No unallowed OSV advisories found.\n' : 'No OSV advisories found.\n',
  )
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main()
}
