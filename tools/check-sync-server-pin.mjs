import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

export const PIN_LIMITS = { commits: 40, days: 14 }

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const PIN_FILE = join('src-tauri', 'contracts', 'sync', 'server-pin.json')
const MILLISECONDS_PER_DAY = 86_400_000

export function daysBetween(olderDate, newerDate) {
  const older = Date.parse(olderDate)
  const newer = Date.parse(newerDate)
  if (Number.isNaN(older) || Number.isNaN(newer)) throw new Error('A commit date could not be read.')
  return Math.max(0, Math.floor((newer - older) / MILLISECONDS_PER_DAY))
}

export function judgePin({ commit, branch, repository, status, aheadBy, pinDate, headDate }, limits = PIN_LIMITS) {
  const move = `Move the pin by setting "commit" in ${PIN_FILE.replaceAll('\\', '/')} to a recent ${repository} ${branch} commit, then let the Sync round trips run against it.`
  if (status !== 'ahead' && status !== 'identical') {
    return { ok: false, message: `The pinned commit ${commit} is not an ancestor of ${repository} ${branch}, and GitHub reports the comparison as ${status}. ${move}` }
  }
  const days = daysBetween(pinDate, headDate)
  const behind = `The pinned commit ${commit} is ${aheadBy} commits and ${days} days behind ${repository} ${branch}`
  if (aheadBy > limits.commits || days > limits.days) {
    return { ok: false, message: `${behind}, past the limit of ${limits.commits} commits or ${limits.days} days. ${move}` }
  }
  return { ok: true, message: `${behind}, within the limit of ${limits.commits} commits or ${limits.days} days.` }
}

export async function fetchPinState({ repository, commit, branch }, fetchJson) {
  const compare = await fetchJson(`/repos/${repository}/compare/${commit}...${branch}`)
  const head = await fetchJson(`/repos/${repository}/commits/${branch}`)
  return {
    commit,
    branch,
    repository,
    status: compare.status,
    aheadBy: compare.ahead_by,
    pinDate: compare.base_commit.commit.committer.date,
    headDate: head.commit.committer.date,
  }
}

function githubFetchJson(token) {
  return async (path) => {
    const headers = { accept: 'application/vnd.github+json', 'user-agent': 'sesame-desktop-pin-check' }
    if (token) headers.authorization = `Bearer ${token}`
    const response = await fetch(`https://api.github.com${path}`, { headers })
    if (!response.ok) throw new Error(`GitHub answered ${response.status} for ${path}`)
    return response.json()
  }
}

async function main() {
  const pin = JSON.parse(readFileSync(join(root, PIN_FILE), 'utf8'))
  const state = await fetchPinState({ repository: pin.repository, commit: pin.commit, branch: 'main' }, githubFetchJson(process.env.GITHUB_TOKEN))
  const verdict = judgePin(state)
  process.stdout.write(`${verdict.message}\n`)
  if (!verdict.ok) process.exit(1)
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`)
    process.exit(1)
  })
}
