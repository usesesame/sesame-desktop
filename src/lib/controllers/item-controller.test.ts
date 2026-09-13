import { describe, expect, it } from 'vitest'
import type { AppStores } from '../stores/app-stores'
import type { RecordKind } from '../item-fields'
import { createFeedbackController } from './feedback-controller'
import { createItemController, type RecordEditor } from './item-controller'
import type { LoginController } from './login-controller'

const recordKinds: RecordKind[] = ['identity', 'secure_note', 'card', 'wifi_network', 'ssh_key', 'software_license', 'document', 'custom_record']

function fakeStore<T extends object>(initial: T) {
  let value = initial
  return {
    subscribe: (run: (state: T) => void) => {
      run(value)
      return () => {}
    },
    set: (next: T) => { value = next },
    patch: (values: Partial<T>) => { value = { ...value, ...values } },
    value: () => value,
  }
}

function fakeStores(): AppStores {
  return {
    selection: fakeStore({ activeItemId: null as string | null, activeItemKind: null as string | null }),
    settings: fakeStore({ clipboardClearSeconds: 30 }),
    vault: fakeStore({ status: {}, snapshot: null, loginCard: null }),
  } as unknown as AppStores
}

function harness() {
  const calls: string[] = []
  const editors = Object.fromEntries(recordKinds.map((kind) => [kind, {
    openNew: () => { calls.push(`${kind}:new`) },
    openEditor: (id: string) => { calls.push(`${kind}:edit:${id}`) },
    requestDelete: (id: string, title: string) => { calls.push(`${kind}:delete:${id}:${title}`) },
  }])) as Record<RecordKind, RecordEditor>
  const login = { openEditor: () => { calls.push('login:edit') }, openNew: () => {}, clearSelection: () => {}, selectEntry: async () => {} } as unknown as LoginController
  const controller = createItemController({ stores: fakeStores(), feedback: createFeedbackController(), login, editors })
  return { controller, calls }
}

describe('context menu targets', () => {
  it('opens the editor for the named item while another item is active', async () => {
    const { controller, calls } = harness()
    await controller.openEditorFor('card-1', 'card')
    expect(calls).toEqual(['card:edit:card-1'])
  })

  it('deletes the named item with its own title while another item is active', () => {
    const { controller, calls } = harness()
    controller.requestDeleteFor('card-1', 'card', 'Travel card')
    expect(calls).toEqual(['card:delete:card-1:Travel card'])
  })

  it('leaves login items to the login controller and skips a missing title', async () => {
    const { controller, calls } = harness()
    await controller.openEditorFor('login-1', 'login')
    controller.requestDeleteFor('login-1', 'login', 'Mail')
    controller.requestDeleteFor('card-1', 'card', '')
    expect(calls).toEqual(['login:edit'])
  })
})
