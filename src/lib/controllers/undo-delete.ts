import type { AppStores } from '../stores/app-stores'
import { restoreTrashedItem } from '../vault'
import type { FeedbackController, NoticeAction } from './feedback-controller'

export function undoDeleteAction(ids: string[], { stores, feedback }: { stores: AppStores; feedback: FeedbackController }): NoticeAction {
  return {
    label: 'Undo',
    run: () => {
      void restore(ids, stores, feedback)
    },
  }
}

async function restore(ids: string[], stores: AppStores, feedback: FeedbackController) {
  feedback.clearError()
  let restored = 0
  try {
    for (const id of ids) {
      const result = await restoreTrashedItem(id)
      if (!stores.vault.value().status.unlocked) return
      stores.vault.patch({ snapshot: result.snapshot })
      restored += 1
    }
    feedback.showNotice(
      ids.length === 1 ? 'Item restored' : 'Items restored',
      ids.length === 1 ? 'It is back in your vault.' : `${ids.length} items are back in your vault.`,
    )
  } catch (error) {
    if (restored > 0) feedback.setErrorMessage(`Sesame restored ${restored} of ${ids.length} items. The rest are still in Trash.`)
    else feedback.setError(error)
  }
}
