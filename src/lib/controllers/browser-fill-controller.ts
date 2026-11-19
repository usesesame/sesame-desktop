import type { AppStores } from '../stores/app-stores'
import type { BrowserFillRequest } from '../types'
import {
  getPendingBrowserFill,
  resolveBrowserFill as resolveBrowserFillRequest,
  subscribeBrowserFill,
} from '../vault'
import { previewBrowserFillRequest } from '../release-record-api'
import { approvalLoop } from './approval-loop'
import type { FeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'

interface BrowserFillControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  onVaultLocked: () => void
  modal: ModalController
  blockingOverlayActive?: () => boolean
  held?: () => boolean
}

export function createBrowserFillController({ stores, feedback, onVaultLocked: handleVaultLocked, modal, blockingOverlayActive = () => false, held = () => false }: BrowserFillControllerOptions) {
  const { browserFill } = stores
  const loop = approvalLoop<BrowserFillRequest>({
    store: browserFill,
    held,
    mayShow: () => modal.browserFillMayShow(),
    offersNothing: (request) => !request.candidates.length,
    initialSelection: (request) => (request.candidates.length === 1 ? request.candidates[0].id : ''),
    decline: (approvalId) => resolveBrowserFillRequest(approvalId, null),
    pending: getPendingBrowserFill,
    subscribe: subscribeBrowserFill,
    preview: previewBrowserFillRequest,
    listenerFailure: 'fill_listener_failed',
    onVaultLocked: handleVaultLocked,
  }, stores, () => blockingOverlayActive())

  async function resolve(loginId: string | null) {
    const current = browserFill.value()
    const request = current.request
    if (!request || current.working) return
    browserFill.patch({ working: true })
    try {
      await resolveBrowserFillRequest(request.approvalId, loginId)
      if (loginId) {
        feedback.showNotice('Login approved', `Filled one login for ${request.hostname}.`)
      }
    } catch (error) {
      if (loginId) feedback.setError(error)
    } finally {
      if (browserFill.value().request?.approvalId === request.approvalId) browserFill.patch({ request: null, selectedId: '' })
      browserFill.patch({ working: false })
    }
  }

  return { ...loop, resolve }
}
