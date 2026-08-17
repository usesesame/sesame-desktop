import type { AppStores } from '../stores/app-stores'
import { controllerStore } from './controller-store'

export type OnboardingStep =
  | 'none'
  | 'recovery-display'
  | 'recovery-verify'
  | 'pin-choice'
  | 'beta-warning'

export interface OnboardingState {
  step: OnboardingStep
  dismissed: boolean
}

export interface OnboardingControllerOptions {
  stores: AppStores
  onOpenPinSetup: () => void
  // Called on verification so a reload cannot skip the recovery kit.
  onRecoveryVerified: () => void
}

export interface OnboardingController {
  state: ReturnType<typeof controllerStore<OnboardingState>>
  startAfterVaultCreation(): void
  startIfNeeded(dismissed: boolean, recoveryVerified: boolean, onboardingRequired?: boolean): void
  advance(): void
  skipTo(step: OnboardingStep): void
  dismiss(): void
  lockCleared(): void
  resetAfterVaultDeletion(): void
}

export function createOnboardingController({ stores, onOpenPinSetup, onRecoveryVerified }: OnboardingControllerOptions): OnboardingController {
  const { vault } = stores
  const state = controllerStore<OnboardingState>({ step: 'none', dismissed: false })

  function startAfterVaultCreation() {
    if (state.value().step !== 'none') return
    state.patch({ step: 'recovery-display', dismissed: false })
  }

  // An unverified vault must resume at recovery-display, never at beta-warning.
  function startIfNeeded(dismissed: boolean, recoveryVerified: boolean, onboardingRequired = false) {
    if (onboardingRequired && vault.value().status.unlocked) {
      const current = state.value()
      if (current.step === 'none' || current.dismissed) {
        state.patch({ step: 'recovery-display', dismissed: false })
      }
      return
    }
    if (dismissed) {
      state.patch({ step: 'none', dismissed: true })
      return
    }
    const current = state.value()
    if (current.step !== 'none' || current.dismissed || !vault.value().status.unlocked) return
    state.patch({ step: recoveryVerified ? 'beta-warning' : 'recovery-display' })
  }

  function advance() {
    const current = state.value().step
    if (current === 'recovery-verify') {
      onRecoveryVerified()
    }
    const next = nextStep(current)
    if (next === 'none') {
      state.patch({ step: 'none', dismissed: true })
    } else {
      state.patch({ step: next })
    }
    if (next === 'pin-choice') {
      onOpenPinSetup()
    }
  }

  function skipTo(step: OnboardingStep) {
    state.patch({ step })
  }

  function dismiss() {
    state.patch({ step: 'none', dismissed: true })
  }

  function lockCleared() {
  }

  function resetAfterVaultDeletion() {
    state.set({ step: 'none', dismissed: false })
  }

  return {
    state,
    startAfterVaultCreation,
    startIfNeeded,
    advance,
    skipTo,
    dismiss,
    lockCleared,
    resetAfterVaultDeletion,
  }
}

function nextStep(step: OnboardingStep): OnboardingStep {
  switch (step) {
    case 'recovery-display':
      return 'recovery-verify'
    case 'recovery-verify':
      return 'pin-choice'
    case 'pin-choice':
      return 'beta-warning'
    case 'beta-warning':
      return 'none'
    default:
      return 'none'
  }
}
