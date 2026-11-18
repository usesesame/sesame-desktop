import type { AppStores } from '../stores/app-stores'
import type { BrowserCardFillRequest } from '../types'
import {
  getPendingBrowserCardFill,
  resolveBrowserCardFill as resolveBrowserCardFillRequest,
  subscribeBrowserCardFill,
} from '../vault'
import { approvalLoop } from './approval-loop'
import type { FeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'

interface CardFillControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  onVaultLocked: () => void
  modal: ModalController
  blockingOverlayActive: () => boolean
}

export function createCardFillController({ stores, feedback, onVaultLocked: handleVaultLocked, modal, blockingOverlayActive }: CardFillControllerOptions) {
  const { browserCardFill } = stores
  const loop = approvalLoop<BrowserCardFillRequest>({
    store: browserCardFill,
    mayShow: () => modal.cardFillMayShow(),
    offersNothing: (request) => !request.candidates.length,
    initialSelection: (request) => (request.candidates.length === 1 ? request.candidates[0].id : ''),
    decline: (approvalId) => resolveBrowserCardFillRequest(approvalId, null),
    pending: getPendingBrowserCardFill,
    subscribe: subscribeBrowserCardFill,
    preview: () => null,
    listenerFailure: 'card_fill_listener_failed',
    onVaultLocked: handleVaultLocked,
  }, stores, () => blockingOverlayActive())

  async function resolve(cardId: string | null) {
    const request = browserCardFill.value().request
    if (!request || browserCardFill.value().working) return
    browserCardFill.patch({ working: true })
    try {
      await resolveBrowserCardFillRequest(request.approvalId, cardId)
      if (cardId) feedback.showNotice('Card approved', `Filled card fields on ${request.hostname}.`)
    } catch (error) {
      if (cardId) feedback.setError(error)
    } finally {
      if (browserCardFill.value().request?.approvalId === request.approvalId) browserCardFill.patch({ request: null, selectedId: '' })
      browserCardFill.patch({ working: false })
    }
  }

  return { resolve, clearSecrets: loop.clearSecrets, start: loop.start }
}
