import { spawnSync } from 'node:child_process'
import { copyFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { createRequire } from 'node:module'
import { join } from 'node:path'

import { fixturePages } from './browser-fixture-pages.mjs'
import { isLoopbackOrigin } from './extension-station.mjs'

export const fictionalLogin = {
  title: 'Fictional station login',
  username: 'station-user@example.test',
  password: 'fictional-station-pass-1',
}

const nothingFilled = { username: '', password: '' }
const browserCandidates = ['/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome-stable', '/usr/bin/google-chrome']

export async function startFixtureServer() {
  const server = createServer((request, response) => {
    const path = new URL(request.url ?? '/', 'http://127.0.0.1').pathname
    const body = fixturePages[path] ?? 'Not found'
    response.writeHead(fixturePages[path] ? 200 : 404, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
    response.end(body)
  })
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen)
    server.listen(0, '127.0.0.1', resolveListen)
  })
  const { port } = server.address()
  return { origin: `http://127.0.0.1:${port}`, port, close: () => new Promise((resolveClose) => server.close(resolveClose)) }
}

function findBrowser(chromium, environment) {
  const configured = environment.SESAME_BROWSER_TEST_EXECUTABLE
  if (configured) {
    if (existsSync(configured)) return configured
    throw new Error(`SESAME_BROWSER_TEST_EXECUTABLE points at a missing file: ${configured}`)
  }
  const pinned = chromium.executablePath()
  if (pinned && existsSync(pinned)) return pinned
  const found = browserCandidates.find((candidate) => existsSync(candidate))
  if (found) return found
  const discovered = spawnSync('sh', ['-c', 'command -v chromium chromium-browser google-chrome-stable'], { encoding: 'utf8' })
  const first = discovered.stdout.split('\n').map((line) => line.trim()).find(Boolean)
  if (first) return first
  throw new Error('No Chromium executable found. Install one or set SESAME_BROWSER_TEST_EXECUTABLE.')
}

function prepareExtension(extensionDirectory, scratch) {
  const built = join(extensionDirectory, 'dist', 'integration')
  if (!existsSync(built)) throw new Error(`dist/integration is missing: run npm run build:integration in ${extensionDirectory}.`)
  const copy = join(scratch, 'extension')
  cpSync(built, copy, { recursive: true })
  const shipping = JSON.parse(readFileSync(join(extensionDirectory, 'manifests', 'chrome.json'), 'utf8'))
  const manifestPath = join(copy, 'manifest.json')
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
  manifest.key = shipping.key
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2))
  return copy
}

async function injectContentScript(worker, url) {
  return worker.evaluate(async (expected) => {
    const tabs = await chrome.tabs.query({})
    const tab = tabs.find((candidate) => candidate.url === expected)
    if (!tab?.id) return -1
    await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ['content.js'] })
    return tab.id
  }, url)
}

async function pinActiveTab(target, tabId, url) {
  await target.evaluate(({ id, address }) => {
    const scope = globalThis
    scope.sesameOriginalTabQuery ??= chrome.tabs.query
    chrome.tabs.query = async () => [{ id, url: address }]
  }, { id: tabId, address: url })
}

async function unpinActiveTab(target) {
  await target.evaluate(() => {
    const scope = globalThis
    if (scope.sesameOriginalTabQuery) chrome.tabs.query = scope.sesameOriginalTabQuery
    delete scope.sesameOriginalTabQuery
  })
}

async function fieldValues(page) {
  return page.evaluate(() => ({
    username: document.getElementById('username').value,
    password: document.getElementById('password').value,
  }))
}

async function settleUntil(read, accept, timeoutMs) {
  const deadline = Date.now() + timeoutMs
  let value = await read()
  while (!accept(value) && Date.now() < deadline) {
    await new Promise((resolveWait) => setTimeout(resolveWait, 200))
    value = await read()
  }
  return value
}

export async function openJourney({ extensionDirectory, scratch, hostManifest, environment }) {
  const { chromium } = createRequire(join(extensionDirectory, 'package.json'))('playwright-core')
  const profile = mkdtempSync(join(scratch, 'profile-'))
  mkdirSync(join(profile, 'NativeMessagingHosts'), { recursive: true })
  copyFileSync(hostManifest, join(profile, 'NativeMessagingHosts', 'app.usesesame.browser.json'))
  const extensionPath = prepareExtension(extensionDirectory, scratch)
  const context = await chromium.launchPersistentContext(profile, {
    executablePath: findBrowser(chromium, environment),
    env: environment,
    args: [
      '--headless=new',
      '--no-sandbox',
      '--disable-dev-shm-usage',
      `--disable-extensions-except=${extensionPath}`,
      `--load-extension=${extensionPath}`,
    ],
  })
  const worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker', { timeout: 30_000 })
  const extensionId = new URL(worker.url()).host

  async function connect() {
    const popup = await context.newPage()
    try {
      await popup.goto(`chrome-extension://${extensionId}/popup.html`)
      return await popup.evaluate(async () => chrome.runtime.sendMessage({ type: 'sesame:connect', force: true }))
    } finally {
      await popup.close()
    }
  }

  async function attemptFill(url, { waitMs = 20_000 } = {}) {
    const fixture = await context.newPage()
    const popup = await context.newPage()
    try {
      await fixture.goto(url)
      const tabId = await injectContentScript(worker, fixture.url())
      if (tabId < 0) throw new Error(`The extension could not find the tab for ${url}.`)
      await pinActiveTab(worker, tabId, fixture.url())
      await popup.goto(`chrome-extension://${extensionId}/popup.html`)
      await pinActiveTab(popup, tabId, fixture.url())
      const refresh = popup.getByRole('button', { name: /check desktop connection and page again/i })
      await refresh.click()
      await settleUntil(() => refresh.isEnabled(), Boolean, 15_000)
      const button = popup.getByRole('button', { name: 'Fill login', exact: true })
      const offered = await settleUntil(() => button.isVisible(), Boolean, 15_000)
      if (!offered) return { offered: false, feedback: await popup.locator('body').innerText(), values: await fieldValues(fixture), page: fixture, popup }
      await button.click()
      const feedback = popup.locator('.fill-feedback')
      const values = await settleUntil(() => fieldValues(fixture), (current) => current.password !== '', waitMs)
      const text = await settleUntil(
        async () => (await feedback.count() > 0 ? feedback.innerText() : ''),
        (current) => current !== '' && !/waiting for approval/i.test(current),
        values.password === '' ? waitMs : 2_000,
      )
      return { offered: true, feedback: text, values, page: fixture, popup }
    } catch (error) {
      await unpinActiveTab(worker).catch(() => undefined)
      await fixture.close().catch(() => undefined)
      await popup.close().catch(() => undefined)
      throw error
    }
  }

  async function release(attempt) {
    await unpinActiveTab(worker).catch(() => undefined)
    await attempt.popup.close().catch(() => undefined)
    await attempt.page.close().catch(() => undefined)
  }

  async function capture(attempt, path) {
    await attempt.page.screenshot({ path }).catch(() => undefined)
  }

  return { context, connect, attemptFill, release, capture, close: () => context.close() }
}

export function judgeApprovedFill(attempt) {
  if (!attempt.offered) return { ok: false, error: 'The popup never offered Fill login.' }
  if (attempt.values.username !== fictionalLogin.username) return { ok: false, error: 'The username field did not receive the saved username.' }
  if (attempt.values.password !== fictionalLogin.password) return { ok: false, error: 'The password field did not receive the saved password.' }
  return { ok: true }
}

export function promptCount(approver, origin) {
  return [...approver.approvals, ...approver.refusals].filter((entry) => entry.origin === origin).length
}

export function judgeRefusedFill(attempt, promptsBefore, approver, origin) {
  if (attempt.values.username !== nothingFilled.username || attempt.values.password !== nothingFilled.password) {
    return { ok: false, error: `A field was filled on ${origin}.` }
  }
  if (promptCount(approver, origin) > promptsBefore) return { ok: false, error: `The desktop asked for approval for ${origin}.` }
  if (!/no (saved )?login/i.test(attempt.feedback)) return { ok: false, error: `The popup did not report that no login matched: ${attempt.feedback.slice(0, 200)}` }
  return { ok: true, value: { feedback: attempt.feedback.slice(0, 160) } }
}

export function stationOriginPolicy(origins) {
  const ports = origins.map((origin) => Number(new URL(origin).port))
  return (origin) => isLoopbackOrigin(origin, ports)
}
