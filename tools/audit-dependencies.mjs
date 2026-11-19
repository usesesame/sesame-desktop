import { execFile } from 'node:child_process'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

const root = path.resolve(import.meta.dirname, '..')

export const exceptionsPath = path.join(root, 'tools', 'advisory-exceptions.json')

const MAX_EXCEPTION_DAYS = 30
const FAILING_NPM_SEVERITIES = new Set(['high', 'critical'])
const isoDate = /^\d{4}-\d{2}-\d{2}$/
const advisoryId = /^(?:GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|RUSTSEC-\d{4}-\d{4})$/
const dayNumber = (value) => Date.parse(`${value}T00:00:00Z`) / 86_400_000
const isCalendarDate = (value) =>
  isoDate.test(value) && Number.isFinite(dayNumber(value)) && new Date(`${value}T00:00:00Z`).toISOString().startsWith(value)

export const validateExceptions = (document, today) => {
  if (!document || typeof document !== 'object' || Array.isArray(document) || !Array.isArray(document.entries)) {
    throw new Error('The advisory exceptions file must hold an "entries" array.')
  }
  const seen = new Set()
  for (const entry of document.entries) {
    const shown = JSON.stringify(entry)
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new Error(`Every advisory exception must be an object: ${shown}`)
    }
    if (Object.keys(entry).sort().join(',') !== 'expires,id,package,reason,reviewed') {
      throw new Error(`Every advisory exception has exactly an id, a package, a reason, a reviewed date and an expiry date: ${shown}`)
    }
    if (typeof entry.id !== 'string' || !advisoryId.test(entry.id)) {
      throw new Error(`An advisory exception must name a GHSA or RUSTSEC advisory: ${shown}`)
    }
    for (const field of ['package', 'reason']) {
      if (typeof entry[field] !== 'string' || entry[field].trim().length === 0) {
        throw new Error(`An advisory exception needs a ${field}: ${shown}`)
      }
    }
    if (!isCalendarDate(entry.reviewed) || !isCalendarDate(entry.expires)) {
      throw new Error(`An advisory exception needs a reviewed date and an expiry date as YYYY-MM-DD: ${shown}`)
    }
    if (dayNumber(entry.reviewed) > dayNumber(today)) {
      throw new Error(`An advisory exception cannot be reviewed after today: ${shown}`)
    }
    const days = dayNumber(entry.expires) - dayNumber(entry.reviewed)
    if (!(days > 0 && days <= MAX_EXCEPTION_DAYS)) {
      throw new Error(`An advisory exception must expire within ${MAX_EXCEPTION_DAYS} days after it was reviewed: ${shown}`)
    }
    if (entry.expires < today) {
      throw new Error(`The advisory exception for ${entry.id} in ${entry.package} expired on ${entry.expires}. Fix the dependency or review the exception again.`)
    }
    const key = `${entry.package}|${entry.id}`
    if (seen.has(key)) throw new Error(`The advisory exception for ${entry.id} in ${entry.package} is listed twice.`)
    seen.add(key)
  }
  return document.entries
}

export const loadExceptions = (today, file = exceptionsPath) =>
  validateExceptions(JSON.parse(readFileSync(file, 'utf8')), today)

export const npmFindings = (report) => {
  if (!report || typeof report !== 'object' || report.error || !report.vulnerabilities || typeof report.vulnerabilities !== 'object') {
    const summary = report?.error?.summary ? `: ${report.error.summary}` : ''
    throw new Error(`npm audit did not return a report${summary}.`)
  }
  const findings = new Map()
  for (const vulnerability of Object.values(report.vulnerabilities)) {
    for (const source of Array.isArray(vulnerability?.via) ? vulnerability.via : []) {
      if (!source || typeof source !== 'object' || !FAILING_NPM_SEVERITIES.has(source.severity)) continue
      const id = String(source.url ?? '').match(/GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}/)?.[0] ?? `npm advisory ${source.source}`
      findings.set(`${source.name}|${id}`, {
        ecosystem: 'npm',
        id,
        package: source.name,
        severity: source.severity,
        title: source.title ?? '',
        url: source.url ?? '',
      })
    }
  }
  return [...findings.values()]
}

export const cargoFindings = (report) => {
  const list = report?.vulnerabilities?.list
  if (!Array.isArray(list)) throw new Error('cargo audit did not return a report.')
  return list.map(({ advisory, package: crate }) => ({
    ecosystem: 'cargo',
    id: advisory?.id ?? 'unknown RUSTSEC advisory',
    package: crate?.name ?? 'unknown crate',
    severity: 'vulnerability',
    title: advisory?.title ?? '',
    url: advisory?.url ?? '',
  }))
}

export const evaluateFindings = (findings, exceptions) => {
  const matches = (finding, entry) => entry.id === finding.id && entry.package === finding.package
  const accepted = []
  const blocking = []
  for (const finding of findings) {
    const entry = exceptions.find((candidate) => matches(finding, candidate))
    if (entry) accepted.push({ ...finding, expires: entry.expires })
    else blocking.push(finding)
  }
  const unused = exceptions.filter((entry) => !findings.some((finding) => matches(finding, entry)))
  return { accepted, blocking, unused }
}

const run = promisify(execFile)

export const auditRetryDelaysMs = [2000, 5000, 15000]

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
const networkCodes = new Set(['ECONNREFUSED', 'ECONNRESET', 'EAI_AGAIN', 'ENETUNREACH', 'ENOTFOUND', 'EPIPE', 'ETIMEDOUT', 'FETCH_ERROR'])

const transient = (message) => Object.assign(new Error(message), { transient: true })

export const registryUnavailable = (report) => {
  if (!report || typeof report !== 'object' || report.vulnerabilities) return false
  if (Number.isInteger(report.statusCode)) return report.statusCode >= 500
  if (report.error) {
    const code = report.error.code
    return typeof code === 'string' && (/^E5\d\d$/.test(code) || networkCodes.has(code))
  }
  return typeof report.message === 'string'
}

export const retryTransient = async (attempt, { delaysMs = auditRetryDelaysMs, wait = sleep } = {}) => {
  for (let index = 0; ; index += 1) {
    try {
      return await attempt()
    } catch (error) {
      if (!error.transient || index >= delaysMs.length) throw error
      await wait(delaysMs[index])
    }
  }
}

export const reportFrom = async (command, args, cwd) => {
  try {
    const { stdout } = await run(command, args, { cwd, maxBuffer: 64 * 1024 * 1024 })
    return JSON.parse(stdout)
  } catch (error) {
    if (error instanceof SyntaxError || error.code === 'ENOENT') throw error
    if (typeof error.stdout === 'string' && error.stdout.trim().length > 0) return JSON.parse(error.stdout)
    throw transient(`${command} produced no report: ${String(error.stderr ?? error.message).trim().split('\n')[0]}`)
  }
}

const auditReport = (command, args, cwd, options) =>
  retryTransient(async () => {
    const report = await reportFrom(command, args, cwd)
    if (command === 'npm' && registryUnavailable(report)) {
      throw transient(`npm audit could not reach the registry: ${report.error?.summary ?? report.message ?? report.statusCode}`)
    }
    return report
  }, options)

const main = async () => {
  const today = new Date().toISOString().slice(0, 10)
  const exceptions = loadExceptions(today)
  const findings = [
    ...npmFindings(await auditReport('npm', ['audit', '--json'], root)),
    ...cargoFindings(await auditReport('cargo', ['audit', '--json', '--file', 'src-tauri/Cargo.lock'], root)),
  ]
  const { accepted, blocking, unused } = evaluateFindings(findings, exceptions)
  for (const finding of accepted) {
    console.log(`Accepted until ${finding.expires}: ${finding.id} in ${finding.ecosystem} package ${finding.package}.`)
  }
  for (const entry of unused) {
    console.log(`No longer reported, so the exception can be removed: ${entry.id} in ${entry.package}.`)
  }
  for (const finding of blocking) {
    console.error(`${finding.severity} ${finding.id} in ${finding.ecosystem} package ${finding.package}: ${finding.title} ${finding.url}`.trim())
  }
  if (blocking.length > 0) {
    console.error(`Fix these advisories or add a reviewed exception to ${path.relative(root, exceptionsPath)}.`)
    process.exitCode = 1
    return
  }
  console.log('No unaccepted npm advisory at high or above and no unaccepted Rust vulnerability.')
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error.message)
    process.exitCode = 1
  })
}
