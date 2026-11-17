import type { AppStores } from '../stores/app-stores'
import type { BrowserTotpFillRequest } from '../types'
import {
  getPendingBrowserTotpFill,
  resolveBrowserTotpFill as resolveBrowserTotpFillRequest,
  subscribeBrowserTotpFill,
} from '../vault'
import { approvalLoop } from './approval-loop'
import type { FeedbackController } from './feedback-controller'
import type { ModalController } from './modal-controller'

interface TotpFillControllerOptions {
  stores: AppStores
  feedback: FeedbackController
  onVaultLocked: () => void
  modal: ModalController
  blockingOverlayActive: () => boolean
}

export function createTotpFillController({ stores, feedback, onVaultLocked: handleVaultLocked, modal, blockingOverlayActive }: TotpFillControllerOptions) {
  const { browserTotpFill } = stores
  const loop = approvalLoop<BrowserTotpFillRequest>({
    store: browserTotpFill,
    mayShow: () => modal.totpFillMayShow(),
    offersNothing: (request) => !request.candidates.length,
    initialSelection: (request) => (request.candidates.length === 1 ? request.candidates[0].id : ''),
    decline: (approvalId) => resolveBrowserTotpFillRequest(approvalId, null),
    pending: getPendingBrowserTotpFill,
    subscribe: subscribeBrowserTotpFill,
    preview: () => null,
    listenerFailure: 'totp_fill_listener_failed',
    onVaultLocked: handleVaultLocked,
  }, stores, () => blockingOverlayActive())

  async function resolve(loginId: string | null) {
    const current = browserTotpFill.value()
    const request = current.request
    if (!request || current.working) return
    browserTotpFill.patch({ working: true })
    try {
      await resolveBrowserTotpFillRequest(request.approvalId, loginId)
      if (loginId) feedback.showNotice('Code approved', `Filled a one-time code on ${request.hostname}.`)
    } catch (error) {
      if (loginId) feedback.setError(error)
    } finally {
      if (browserTotpFill.value().request?.approvalId === request.approvalId) browserTotpFill.patch({ request: null, selectedId: '' })
      browserTotpFill.patch({ working: false })
    }
  }

  return { ...loop, resolve }
}
