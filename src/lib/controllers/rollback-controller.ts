import { acceptRollback, getRollbackNotice, lockVault, type RollbackNotice } from '../vault'
import { controllerStore } from './controller-store'

export function createRollbackController() {
  const state = controllerStore({
    notice: null as RollbackNotice | null,
    working: false,
    error: '',
  })

  return {
    state,
    async refresh() {
      try {
        state.patch({ notice: await getRollbackNotice(), error: '' })
      } catch {
        state.patch({ notice: null })
      }
    },
    clear() {
      state.patch({ notice: null, working: false, error: '' })
    },
    async keep() {
      state.patch({ working: true, error: '' })
      try {
        await acceptRollback()
        state.patch({ notice: null })
      } catch (error) {
        state.patch({ error: error instanceof Error ? error.message : 'Sesame could not keep this vault.' })
      } finally {
        state.patch({ working: false })
      }
    },
    async lock() {
      try {
        await lockVault()
      } finally {
        state.patch({ notice: null, working: false, error: '' })
      }
    },
  }
}
