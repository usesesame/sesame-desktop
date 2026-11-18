import type { AppStores } from '../stores/app-stores'
import type { BrowserIdentityFillRequest } from '../types'
import {
  getPendingBrowserIdentityFill,
  resolveBrowserIdentityFill as resolveBrowserIdentityFillRequest,
  subscribeBrowserIdentityFill,
} from '../vault'
import { approvalLoop } from './approval-loop'
import type { FeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'

interface IdentityFillControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  onVaultLocked: () => void
  modal: ModalController
  blockingOverlayActive: () => boolean
}

export function createIdentityFillController({ stores, feedback, onVaultLocked: handleVaultLocked, modal, blockingOverlayActive }: IdentityFillControllerOptions) {
  const { browserIdentityFill } = stores
  const loop = approvalLoop<BrowserIdentityFillRequest>({
    store: browserIdentityFill,
    mayShow: () => modal.identityFillMayShow(),
    offersNothing: (request) => !request.candidates.length,
    initialSelection: (request) => (request.candidates.length === 1 ? request.candidates[0].id : ''),
    decline: (approvalId) => resolveBrowserIdentityFillRequest(approvalId, null),
    pending: getPendingBrowserIdentityFill,
    subscribe: subscribeBrowserIdentityFill,
    preview: () => null,
    listenerFailure: 'identity_fill_listener_failed',
    onVaultLocked: handleVaultLocked,
  }, stores, () => blockingOverlayActive())

  async function resolve(identityId: string | null) {
    const current = browserIdentityFill.value()
    const request = current.request
    if (!request || current.working) return
    browserIdentityFill.patch({ working: true })
    try {
      await resolveBrowserIdentityFillRequest(request.approvalId, identityId)
      if (identityId) feedback.showNotice('Identity approved', `Filled fields on ${request.hostname}.`)
    } catch (error) {
      if (identityId) feedback.setError(error)
    } finally {
      if (browserIdentityFill.value().request?.approvalId === request.approvalId) browserIdentityFill.patch({ request: null, selectedId: '' })
      browserIdentityFill.patch({ working: false })
    }
  }

  return { ...loop, resolve }
}
