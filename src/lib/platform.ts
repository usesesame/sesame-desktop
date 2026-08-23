import { writable } from 'svelte/store'

import type { PlatformCapabilities } from './types'
import { getPlatformCapabilities } from './vault'

const unknownHost: PlatformCapabilities = { os: '', pinUnlock: false, biometricUnlock: false, autoType: false, browserIntegration: false, sessionAutoLock: false, accountLinking: false }

export const platformCapabilities = writable<PlatformCapabilities>(unknownHost)

export async function loadPlatformCapabilities(): Promise<void> {
  platformCapabilities.set(await getPlatformCapabilities())
}
