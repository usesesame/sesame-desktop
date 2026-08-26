import { describe, expect, it } from 'vitest'
import { get } from 'svelte/store'
import type { AppStores } from '../stores/app-stores'
import type { VaultSnapshot } from '../types'
import { createFeedbackController } from './feedback-controller'
import { createModalController } from './modal-controller'
import { createRecordController, type RecordConfig } from './record-controller'

interface FakeItem {
  id: string
  legacyFields?: never
}

interface FakeInput {
  id?: string
  title: string
}

function fakeSnapshot(): VaultSnapshot {
  return {} as VaultSnapshot
}

function fakeStores(): AppStores {
  const noRequest = { subscribe: () => () => {}, set: () => {}, patch: () => {}, value: () => ({ request: null }) }
  let vaultState = { status: {}, snapshot: null, loginCard: null }
  return {
    vault: {
      subscribe: () => () => {},
      set: (next: typeof vaultState) => { vaultState = next },
      patch: (values: Partial<typeof vaultState>) => { vaultState = { ...vaultState, ...values } },
      value: () => vaultState,
    },
    browserFill: noRequest,
    browserIdentityFill: noRequest,
    browserCardFill: noRequest,
    browserSave: noRequest,
  } as unknown as AppStores
}

function harness(overrides: Partial<RecordConfig<FakeItem, FakeInput>['api']> = {}) {
  const stores = fakeStores()
  const feedback = createFeedbackController()
  const modal = createModalController({ stores, feedback })
  const saved: FakeItem[] = []
  const deleted: string[] = []
  const config: RecordConfig<FakeItem, FakeInput> = {
    editorModal: { kind: 'card-editor' },
    deleteModalKind: 'delete-card',
    deleteModal: (id) => ({ kind: 'delete-card', cardId: id }),
    emptyDraft: () => ({ title: '' }),
    draftFrom: (item) => ({ id: item.id, title: 'loaded' }),
    draftTitle: (draft) => draft.title,
    api: {
      get: async (id) => ({ id }),
      save: async (input) => {
        const id = input.id ?? 'new-id'
        saved.push({ id })
        return { id, snapshot: fakeSnapshot() }
      },
      delete: async (id) => {
        deleted.push(id)
        return { deletedId: id, snapshot: fakeSnapshot() }
      },
      ...overrides,
    },
    copy: {
      addTitle: 'Add a thing',
      editTitle: 'Edit thing',
      savedNotice: (isNew, title) => ({ title: isNew ? 'Thing saved' : 'Thing updated', body: `${title} stored` }),
      deletedNotice: (title) => ({ title: 'Thing deleted', body: `${title} removed` }),
    },
  }
  const controller = createRecordController({ stores, feedback, modal }, config)
  return { controller, feedback, saved, deleted }
}

describe('createRecordController', () => {
  it('opens a fresh draft for a new record', () => {
    const { controller } = harness()
    controller.openNew()
    const state = get(controller.state)
    expect(state.draft).toEqual({ title: '' })
    expect(state.editorTitle).toBe('Add a thing')
  })

  it('loads an existing record into the draft', async () => {
    const { controller } = harness()
    await controller.openEditor('item-1')
    const state = get(controller.state)
    expect(state.draft).toEqual({ id: 'item-1', title: 'loaded' })
    expect(state.editorTitle).toBe('Edit thing')
    expect(state.loading).toBe(false)
  })

  it('saves a new draft and shows the saved notice', async () => {
    const { controller, feedback, saved } = harness()
    controller.openNew()
    controller.setDraft({ title: 'Mine' })
    await controller.save()
    expect(saved).toEqual([{ id: 'new-id' }])
    expect(get(feedback.state).notice).toEqual({ title: 'Thing saved', message: 'Mine stored' })
    expect(get(controller.state).draft).toEqual({ title: '' })
  })

  it('deletes a record and shows the deleted notice', async () => {
    const { controller, feedback, deleted } = harness()
    controller.requestDelete('item-1', 'Mine')
    expect(get(controller.state).deleteCandidate).toEqual({ id: 'item-1', title: 'Mine' })
    await controller.confirmDelete()
    expect(deleted).toEqual(['item-1'])
    expect(get(feedback.state).notice).toEqual({ title: 'Thing deleted', message: 'Mine removed' })
    expect(get(controller.state).deleteCandidate).toBeNull()
  })

  it('reports an error and keeps the candidate on delete failure', async () => {
    const { controller, feedback } = harness({
      delete: async () => { throw new Error('That saved item no longer exists.') },
    })
    controller.requestDelete('item-1', 'Mine')
    await controller.confirmDelete()
    expect(get(controller.state).deleteCandidate).toEqual({ id: 'item-1', title: 'Mine' })
    expect(get(feedback.state).errorMessage).toBe('That saved item no longer exists.')
  })
})
