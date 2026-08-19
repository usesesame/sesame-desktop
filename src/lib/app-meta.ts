import { getVersion } from '@tauri-apps/api/app'
import { derived, readable } from 'svelte/store'

const embeddedVersion = __SESAME_APP_VERSION__
const hasTauriInternals = typeof window !== 'undefined' &&
  Boolean((window as Window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__)
let resolvedVersion: Promise<string> | undefined

export function resolveAppVersion(): Promise<string> {
  if (!hasTauriInternals) return Promise.resolve(embeddedVersion)
  resolvedVersion ??= getVersion().catch(() => embeddedVersion)
  return resolvedVersion
}

export const appVersion = readable(hasTauriInternals ? '' : embeddedVersion, (set) => {
  if (hasTauriInternals) void resolveAppVersion().then(set)
})

export function channelForVersion(version: string): string {
  const prerelease = /^\d+\.\d+\.\d+-([0-9A-Za-z.-]+)$/.exec(version)?.[1]
  if (prerelease) {
    const label = prerelease.split('.')[0]
    return label.charAt(0).toUpperCase() + label.slice(1)
  }
  if (!/^\d+\.\d+\.\d+$/.test(version)) return ''
  return version.startsWith('0.') ? 'Beta' : 'Stable'
}

export const appChannel = derived(appVersion, channelForVersion)

function configuredSiteOrigin(): string | undefined {
  const value = import.meta.env.VITE_SESAME_SITE_ORIGIN?.trim()
  if (!value) return undefined
  let url: URL
  try { url = new URL(value) } catch { return undefined }
  const loopback = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]'
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
    return undefined
  }
  if (url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    return undefined
  }
  return url.origin
}

const siteOrigin = configuredSiteOrigin()

export const SYNC_STATUS_URL = siteOrigin ? `${siteOrigin}/roadmap#sync` : undefined

/// Sync is not enabled; dev build plus explicit opt-in only.
export const SYNC_PREVIEW_AVAILABLE =
  import.meta.env.DEV && import.meta.env.VITE_SESAME_SYNC_PREVIEW === 'true'
