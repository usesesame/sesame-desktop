import type { AppStores } from '../stores/app-stores'
import type { BrowserChangeRequest, BrowserCreateRequest } from '../types'
import {
  getPendingBrowserChange,
  getPendingBrowserCreate,
  previewBrowserChangeRequest,
  previewBrowserCreateRequest,
  resolveBrowserChange,
  resolveBrowserCreate,
  subscribeBrowserChange,
  subscribeBrowserCreate,
} from '../vault'
import { approvalLoop } from './approval-loop'
import type { FeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'

interface BrowserChangeControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  modal: ModalController
  blockingOverlayActive?: () => boolean
  held?: () => boolean
}

export function createBrowserChangeController({ stores, feedback, modal, blockingOverlayActive = () => false, held = () => false }: BrowserChangeControllerOptions) {
  const store = stores.browserChange
  const loop = approvalLoop<BrowserChangeRequest>({
    store,
    held,
    mayShow: modal.browserChangeMayShow,
    initialSelection: (request) => (request.candidates.length === 1 ? request.candidates[0].id : ''),
    decline: (approvalId) => resolveBrowserChange(approvalId, null),
    pending: getPendingBrowserChange,
    subscribe: subscribeBrowserChange,
    preview: previewBrowserChangeRequest,
    listenerFailure: 'change_listener_failed',
  }, stores, blockingOverlayActive)

  async function resolve(loginId: string | null) {
    const current = store.value()
    const request = current.request
    if (!request || current.working) return
    store.patch({ working: true })
    try {
      await resolveBrowserChange(request.approvalId, loginId)
    } catch (error) {
      if (loginId) feedback.setError(error)
    } finally {
      if (store.value().request?.approvalId === request.approvalId) store.patch({ request: null, selectedId: '' })
      store.patch({ working: false })
    }
  }

  return { ...loop, resolve }
}

export function createBrowserCreateController({ stores, feedback, modal, blockingOverlayActive = () => false, held = () => false }: BrowserChangeControllerOptions) {
  const store = stores.browserCreate
  const loop = approvalLoop<BrowserCreateRequest>({
    store,
    held,
    mayShow: modal.browserCreateMayShow,
    initialSelection: () => '',
    decline: (approvalId) => resolveBrowserCreate(approvalId, false),
    pending: getPendingBrowserCreate,
    subscribe: subscribeBrowserCreate,
    preview: previewBrowserCreateRequest,
    listenerFailure: 'create_listener_failed',
  }, stores, blockingOverlayActive)

  async function resolve(approved: boolean) {
    const current = store.value()
    const request = current.request
    if (!request || current.working) return
    store.patch({ working: true })
    try {
      await resolveBrowserCreate(request.approvalId, approved)
    } catch (error) {
      if (approved) feedback.setError(error)
    } finally {
      if (store.value().request?.approvalId === request.approvalId) store.patch({ request: null, selectedId: '' })
      store.patch({ working: false })
    }
  }

  return { ...loop, resolve }
}
