import { grantPresence, PRESENCE_REQUIRED } from '../vault'
import { controllerStore } from './controller-store'
import { messageFor } from './feedback-controller'

export type PresenceIntent = 'reveal-field' | 'copy-field' | 'check-password'

export function createPresenceController() {
  const state = controllerStore({
    open: false,
    intent: 'reveal-field' as PresenceIntent,
    secret: '',
    error: '',
    working: false,
  })
  let retry: (() => Promise<void> | void) | null = null

  function close() {
    retry = null
    state.set({ open: false, intent: 'reveal-field', secret: '', error: '', working: false })
  }

  return {
    state,
    required(error: unknown): boolean {
      return error instanceof Error && error.message === PRESENCE_REQUIRED
    },
    ask(intent: PresenceIntent, run: () => Promise<void> | void) {
      retry = run
      state.set({ open: true, intent, secret: '', error: '', working: false })
    },
    async confirm() {
      const { secret, working } = state.value()
      const run = retry
      if (!secret || !run || working) return
      state.patch({ secret: '', working: true, error: '' })
      try {
        await grantPresence(secret)
      } catch (error) {
        state.patch({ error: messageFor(error), working: false })
        return
      }
      close()
      await run()
    },
    cancel: close,
    clearSecrets: close,
  }
}

export type PresenceController = ReturnType<typeof createPresenceController>
