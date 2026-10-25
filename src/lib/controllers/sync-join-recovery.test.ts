/* @vitest-environment jsdom */
import { get } from 'svelte/store'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createSyncController } from './sync-controller'

const core = vi.hoisted(() => ({ invoke: vi.fn() }))
vi.mock('@tauri-apps/api/core', () => core)

const status = (overrides: Record<string, unknown> = {}) => ({
  enrolled: true,
  state: 'approved',
  vaultEpoch: 1,
  revision: 3,
  devices: [{ deviceId: 'd1', label: 'Laptop', state: 'approved', isThisDevice: true, addedIndex: 1, newerKey: false }],
  needsNewKey: false,
  alarm: null,
  confirmedAt: null,
  ...overrides,
})

const idle = { phase: 'idle', halt: '', conflictRevision: 0, pending: false, lastSuccessRevision: 3, consecutiveFailures: 0 }

function answer(responses: Record<string, unknown>) {
  core.invoke.mockImplementation(async (command: string) => {
    if (!(command in responses)) return {}
    const value = responses[command]
    if (value instanceof Error) throw value.message
    return typeof value === 'function' ? (value as () => unknown)() : value
  })
}

describe('joining a synced vault', () => {
  beforeEach(() => { core.invoke.mockReset() })
  it('keeps an interrupted join open and refreshes the saved approval for retry', async () => {
    answer({
      sync_join_with_code: new Error('Sesame could not reach Sesame Sync.'),
      sync_status: status({ enrolled: false, state: 'joining', devices: [] }),
      sync_coordinator_status: idle,
    })
    const sync = createSyncController()
    sync.openJoin()
    await sync.join('K7Q2MHX9PD', 'Phone', 'fictional password')
    expect(get(sync).state).toBe('joining')
    expect(get(sync).joinOpen).toBe(true)
    expect(get(sync).error).toBe('Sesame could not reach Sesame Sync.')
    expect(get(sync).removalRecoveryKit).toBe('')
    await sync.autoSync()
    expect(core.invoke).not.toHaveBeenCalledWith('sync_now')
  })
})
