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
