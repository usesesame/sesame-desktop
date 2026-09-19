import { beforeEach, describe, expect, it } from 'vitest'
import { createAppStores } from '../stores/app-stores'
import { createFeedbackController } from './feedback-controller'
import { createModalController, type ModalController } from './modal-controller'

describe('modal controller', () => {
  let modal: ModalController

  beforeEach(() => {
    const stores = createAppStores()
    modal = createModalController({ stores, feedback: createFeedbackController() })
  })

  it('opens a second modal while a folder manager is active', () => {
    expect(modal.open({ kind: 'folder-manager' })).toBe(true)
    expect(modal.open({ kind: 'folder-name' })).toBe(true)
    expect(modal.state.value().active?.kind).toBe('folder-name')
  })

  it('keeps a restore prompt from being replaced and blocks others while it runs', () => {
    expect(modal.open({ kind: 'restore' })).toBe(true)
    expect(modal.open({ kind: 'login-editor' })).toBe(false)
    expect(modal.state.value().active?.kind).toBe('restore')
    expect(modal.open({ kind: 'restore' })).toBe(false)
  })

  it('keeps a delete confirmation on top until it resolves', () => {
    expect(modal.open({ kind: 'delete-login', entryId: 'a' })).toBe(true)
    expect(modal.open({ kind: 'login-editor' })).toBe(false)
    modal.close('delete-login')
    expect(modal.open({ kind: 'login-editor' })).toBe(true)
  })

  it('closes only the matching modal kind', () => {
    expect(modal.open({ kind: 'login-editor' })).toBe(true)
    modal.close('folder-name')
    expect(modal.state.value().active?.kind).toBe('login-editor')
  })
})
