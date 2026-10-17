import { get } from 'svelte/store'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const invoke = vi.hoisted(() => vi.fn())
vi.mock('@tauri-apps/api/core', () => ({ invoke }))

import { createSyncPreviewController } from './sync-preview-controller'

beforeEach(() => {
  invoke.mockReset()
})

describe('sync status errors', () => {
  it('shows the readable message when the account has no Sync plan', async () => {
    invoke.mockRejectedValue('sync_not_entitled:Sync is not part of your plan.')
    const controller = createSyncPreviewController()

    await controller.refresh()

    expect(get(controller).loadError).toBe('Sync is not part of your plan.')
  })

  it('keeps any other message unchanged', async () => {
    invoke.mockRejectedValue('The server could not be reached.')
    const controller = createSyncPreviewController()

    await controller.refresh()

    expect(get(controller).loadError).toBe('The server could not be reached.')
  })

  it('falls back to a plain sentence for a non-text error', async () => {
    invoke.mockRejectedValue(new Error('boom'))
    const controller = createSyncPreviewController()

    await controller.refresh()

    expect(get(controller).loadError).toBe('Sesame could not read the Sync status.')
  })
})
