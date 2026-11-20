import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

import { PIN_LIMITS, daysBetween, fetchPinState, judgePin } from './check-sync-server-pin.mjs'

const repository = 'usesesame/sesame-server'
const commit = 'd075444b601ca6fdcb00d5c6251a4207ebbff82c'
const state = (overrides) => ({
  repository,
  commit,
  branch: 'main',
  status: 'ahead',
  aheadBy: 10,
  pinDate: '2026-11-01T10:00:00Z',
  headDate: '2026-11-05T10:00:00Z',
  ...overrides,
})

test('the limits are one pair of numbers in one place', () => {
  assert.deepEqual(PIN_LIMITS, { commits: 40, days: 14 })
  const workflow = readFileSync('.github/workflows/sync-server-nightly.yml', 'utf8')
  assert.ok(!/\b(40|14)\b/.test(workflow.replace(/[0-9a-f]{40}/g, '')), 'the workflow must not repeat the limits')
})

test('days between two commits count whole days and never go negative', () => {
  assert.equal(daysBetween('2026-11-01T10:00:00Z', '2026-11-05T09:59:59Z'), 3)
  assert.equal(daysBetween('2026-11-01T10:00:00Z', '2026-11-05T10:00:00Z'), 4)
  assert.equal(daysBetween('2026-11-05T10:00:00Z', '2026-11-01T10:00:00Z'), 0)
  assert.throws(() => daysBetween('yesterday', '2026-11-01T10:00:00Z'), /date/)
})

test('a pin inside both limits passes and says how far behind it is', () => {
  const verdict = judgePin(state({ aheadBy: 40, headDate: '2026-11-15T10:00:00Z' }))
  assert.equal(verdict.ok, true)
  assert.match(verdict.message, /40 commits and 14 days behind usesesame\/sesame-server main/)
})

test('a pin past the commit limit fails and says how to move it', () => {
  const verdict = judgePin(state({ aheadBy: 41 }))
  assert.equal(verdict.ok, false)
  assert.match(verdict.message, /41 commits and 4 days behind/)
  assert.match(verdict.message, /past the limit of 40 commits or 14 days/)
  assert.match(verdict.message, /setting "commit" in src-tauri\/contracts\/sync\/server-pin\.json/)
})

test('a pin past the day limit fails even when few commits landed', () => {
  const verdict = judgePin(state({ aheadBy: 3, headDate: '2026-11-16T10:01:00Z' }))
  assert.equal(verdict.ok, false)
  assert.match(verdict.message, /3 commits and 15 days behind/)
})

test('a pin that is not on main fails whatever its age', () => {
  for (const status of ['diverged', 'behind']) {
    const verdict = judgePin(state({ status, aheadBy: 0 }))
    assert.equal(verdict.ok, false, status)
    assert.match(verdict.message, new RegExp(`not an ancestor of ${repository} main, and GitHub reports the comparison as ${status}`))
  }
})

test('a pin equal to main passes', () => {
  assert.equal(judgePin(state({ status: 'identical', aheadBy: 0, headDate: '2026-11-01T10:00:00Z' })).ok, true)
})

test('the limits can be passed in so the rule is testable', () => {
  assert.equal(judgePin(state({ aheadBy: 5 }), { commits: 4, days: 14 }).ok, false)
  assert.equal(judgePin(state({ aheadBy: 5 }), { commits: 5, days: 14 }).ok, true)
})

test('the pin state comes from the compare and head commit answers', async () => {
  const asked = []
  const answers = {
    [`/repos/${repository}/compare/${commit}...main`]: { status: 'ahead', ahead_by: 57, base_commit: { commit: { committer: { date: '2026-10-25T11:31:34Z' } } } },
    [`/repos/${repository}/commits/main`]: { commit: { committer: { date: '2026-11-19T18:17:38Z' } } },
  }
  const found = await fetchPinState({ repository, commit, branch: 'main' }, async (path) => {
    asked.push(path)
    return answers[path]
  })
  assert.equal(asked.length, 2)
  assert.deepEqual(found, state({ aheadBy: 57, pinDate: '2026-10-25T11:31:34Z', headDate: '2026-11-19T18:17:38Z' }))
  assert.equal(judgePin(found).ok, false)
})

test('the pin file names a full commit the check can compare', () => {
  const pin = JSON.parse(readFileSync('src-tauri/contracts/sync/server-pin.json', 'utf8'))
  assert.equal(pin.repository, repository)
  assert.match(pin.commit, /^[0-9a-f]{40}$/)
})
