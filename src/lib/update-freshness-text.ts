import type { DesktopUpdateStatus } from './types'

export function describeFreshness(status: DesktopUpdateStatus): string {
  const freshness = status.freshness
  if (status.available || !freshness) return ''
  if (freshness.state === 'newer_exists') {
    return `Sesame ${freshness.version} is out, but the update information on this device does not list it yet. Download it from the releases page.`
  }
  if (freshness.state === 'unconfirmed') {
    if (freshness.at === undefined) return 'Sesame could not confirm that no update is waiting. Check your connection or the releases page.'
    return `Sesame has not confirmed that no update is waiting since ${new Date(freshness.at * 1000).toLocaleDateString()}. Check your connection or the releases page.`
  }
  return ''
}

export function noUpdateNotice(status: DesktopUpdateStatus): { title: string; message: string } {
  const freshness = status.freshness
  if (freshness?.state === 'newer_exists') return { title: 'A newer Sesame exists', message: describeFreshness(status) }
  if (freshness?.state === 'unconfirmed') return { title: 'Could not confirm updates', message: describeFreshness(status) }
  return { title: 'No update available', message: 'You are running the latest version of Sesame.' }
}
