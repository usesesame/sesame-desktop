import { clearWebsiteIconCache, getWebsiteIcon } from './vault'

const resolvedIcons = new Map<string, string>()
const pendingIcons = new Map<string, Promise<string>>()
interface QueuedRequest {
  run: () => void
  cancel: () => void
}

const requestQueue: QueuedRequest[] = []
const idleWaiters: Array<() => void> = []
const MAX_CONCURRENT_REQUESTS = 4
let cacheGeneration = 0
let activeRequests = 0

function cacheKey(site: string) {
  return site.trim().toLowerCase()
}

export function loadWebsiteIcon(site: string): Promise<string> {
  const key = cacheKey(site)
  if (!key || key === 'no website saved') return Promise.resolve('')
  const resolved = resolvedIcons.get(key)
  if (resolved !== undefined) return Promise.resolve(resolved)
  const pending = pendingIcons.get(key)
  if (pending) return pending

  const requestGeneration = cacheGeneration
  const request: Promise<string> = enqueue(async () => {
    if (requestGeneration !== cacheGeneration) return ''
    return getWebsiteIcon(key).then((icon) => icon ?? '').catch(() => '')
  })
    .then((icon) => {
      if (requestGeneration === cacheGeneration) {
        resolvedIcons.set(key, icon)
      }
      return icon
    })
    .finally(() => {
      if (pendingIcons.get(key) === request) pendingIcons.delete(key)
    })
  pendingIcons.set(key, request)
  return request
}

function enqueue(work: () => Promise<string>): Promise<string> {
  return new Promise((resolve) => {
    requestQueue.push({
      cancel: () => resolve(''),
      run: () => {
        activeRequests += 1
        void work()
          .then(resolve, () => resolve(''))
          .finally(() => {
            activeRequests -= 1
            drainQueue()
            if (activeRequests === 0) idleWaiters.splice(0).forEach((done) => done())
          })
      },
    })
    drainQueue()
  })
}

function drainQueue() {
  while (activeRequests < MAX_CONCURRENT_REQUESTS && requestQueue.length) requestQueue.shift()?.run()
}

function waitUntilIdle(): Promise<void> {
  if (activeRequests === 0) return Promise.resolve()
  return new Promise((resolve) => idleWaiters.push(resolve))
}

export async function clearCachedWebsiteIcons(): Promise<void> {
  cacheGeneration += 1
  resolvedIcons.clear()
  pendingIcons.clear()
  requestQueue.splice(0).forEach((request) => request.cancel())
  await waitUntilIdle()
  await clearWebsiteIconCache()
}
