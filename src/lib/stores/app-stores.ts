import { getContext, setContext } from 'svelte'
import { get, writable } from 'svelte/store'
import { generatorEntropy, makePassword, strengthLabel } from '../generator'
import { makePassphrase, passphraseEntropy } from '../passphrase'
import { DEFAULT_SORT_MODE, type SortMode } from '../vault-collections'
import type { BrowserFillRequest, BrowserIdentityFillRequest, BrowserSaveRequest, GeneratorOption, ImportPreview, ImportSource, LoginCard, SecurityFilter, Theme, TotpRefresh, VaultSnapshot, VaultStatus, View } from '../types'
import { refreshTotp } from '../vault'

export interface VaultStoreState {
  status: VaultStatus
  snapshot: VaultSnapshot | null
  loginCard: LoginCard | null
}

export interface SelectionStoreState {
  activeView: View
  activeEntryId: string | null
  searchQuery: string
  sortMode: SortMode
  securityFilter: SecurityFilter
  folderFilter: string | null
  /** Ids only, never a second place vault data lives; cleared on lock. */
  recentEntryIds: string[]
}

export interface ImportStoreState {
  importing: boolean
  source: ImportSource
  sourceMenuOpen: boolean
  preview: ImportPreview | null
  /// Identifies the parsed import Rust holds; its contents never enter the interface.
  importId: string
  fileName: string
  skipExactDuplicates: boolean
}

export interface BrowserFillStoreState {
  request: BrowserFillRequest | null
  selectedId: string
  working: boolean
  syncWorking: boolean
  syncFailed: boolean
}

export interface BrowserIdentityFillStoreState {
  request: BrowserIdentityFillRequest | null
  selectedId: string
  working: boolean
  syncWorking: boolean
  syncFailed: boolean
}

export interface BrowserSaveStoreState {
  request: BrowserSaveRequest | null
  selectedId: string
  working: boolean
  syncWorking: boolean
  syncFailed: boolean
}

export interface SettingsStoreState {
  theme: Theme
  siteIconsEnabled: boolean
  autoLockMinutes: number
  clipboardClearSeconds: number
  keepInTray: boolean
  quickAccessShortcut: string
}

export interface GeneratorStoreState {
  length: number
  password: string
  options: Record<GeneratorOption, boolean>
  avoidAmbiguous: boolean
  entropy: number
  strength: string
  strengthPercent: number
}

export interface PassphraseStoreState {
  wordCount: number
  separator: string
  capitalize: boolean
  includeNumber: boolean
  passphrase: string
  entropy: number
  strength: string
  strengthPercent: number
}

export type RecentGeneration = { value: string; kind: 'password' | 'passphrase' }

export interface RecentGenerationsStoreState {
  items: RecentGeneration[]
}

const MAX_RECENT_GENERATIONS = 5

export interface TotpStoreState {
  remaining: number
  progress: string
  refreshIssue: boolean
}

function generatorSnapshot(state: Omit<GeneratorStoreState, 'entropy' | 'strength' | 'strengthPercent'>): GeneratorStoreState {
  const entropy = generatorEntropy({ length: state.length, options: state.options, avoidAmbiguous: state.avoidAmbiguous })
  return {
    ...state,
    entropy,
    strength: strengthLabel(entropy),
    strengthPercent: state.password ? Math.min(100, Math.max(8, entropy)) : 0,
  }
}

function createGeneratorStore() {
  const store = writable(generatorSnapshot({
    length: 20,
    password: '',
    options: { lowercase: true, uppercase: true, numbers: true, symbols: true },
    avoidAmbiguous: true,
  }))

  function update(mutator: (state: GeneratorStoreState) => GeneratorStoreState) {
    store.update((state) => generatorSnapshot(mutator(state)))
  }

  function generate() {
    update((state) => ({ ...state, password: makePassword({ length: state.length, options: state.options, avoidAmbiguous: state.avoidAmbiguous }) }))
  }

  return {
    subscribe: store.subscribe,
    generate,
    changeLength(change: number) {
      update((state) => ({ ...state, length: Math.min(64, Math.max(12, state.length + change)) }))
      if (get(store).password) generate()
    },
    setLength(length: number) {
      update((state) => ({ ...state, length: Math.min(64, Math.max(12, length)) }))
      if (get(store).password) generate()
    },
    toggleOption(option: GeneratorOption) {
      const state = get(store)
      const enabled = Object.values(state.options).filter(Boolean).length
      if (state.options[option] && enabled === 1) return
      update((current) => ({ ...current, options: { ...current.options, [option]: !current.options[option] } }))
      if (get(store).password) generate()
    },
    toggleAmbiguous() {
      update((state) => ({ ...state, avoidAmbiguous: !state.avoidAmbiguous }))
      if (get(store).password) generate()
    },
    // A plaintext password does not belong outliving a lock.
    clear() {
      update((state) => ({ ...state, password: '' }))
    },
  }
}

function passphraseSnapshot(state: Omit<PassphraseStoreState, 'entropy' | 'strength' | 'strengthPercent'>): PassphraseStoreState {
  const entropy = passphraseEntropy({ wordCount: state.wordCount, separator: state.separator, capitalize: state.capitalize, includeNumber: state.includeNumber })
  return {
    ...state,
    entropy,
    strength: strengthLabel(entropy),
    strengthPercent: state.passphrase ? Math.min(100, Math.max(8, entropy)) : 0,
  }
}

function createPassphraseStore() {
  const store = writable(passphraseSnapshot({
    wordCount: 6,
    separator: '-',
    capitalize: true,
    includeNumber: true,
    passphrase: '',
  }))

  function update(mutator: (state: PassphraseStoreState) => PassphraseStoreState) {
    store.update((state) => passphraseSnapshot(mutator(state)))
  }

  function generate() {
    update((state) => ({ ...state, passphrase: makePassphrase({ wordCount: state.wordCount, separator: state.separator, capitalize: state.capitalize, includeNumber: state.includeNumber }) }))
  }

  return {
    subscribe: store.subscribe,
    generate,
    setWordCount(wordCount: number) {
      update((state) => ({ ...state, wordCount: Math.min(12, Math.max(4, wordCount)) }))
      if (get(store).passphrase) generate()
    },
    changeWordCount(change: number) {
      update((state) => ({ ...state, wordCount: Math.min(12, Math.max(4, state.wordCount + change)) }))
      if (get(store).passphrase) generate()
    },
    setSeparator(separator: string) {
      update((state) => ({ ...state, separator }))
      if (get(store).passphrase) generate()
    },
    toggleCapitalize() {
      update((state) => ({ ...state, capitalize: !state.capitalize }))
      if (get(store).passphrase) generate()
    },
    toggleIncludeNumber() {
      update((state) => ({ ...state, includeNumber: !state.includeNumber }))
      if (get(store).passphrase) generate()
    },
    clear() {
      update((state) => ({ ...state, passphrase: '' }))
    },
  }
}

function createRecentGenerationsStore() {
  const store = writable<RecentGenerationsStoreState>({ items: [] })

  return {
    subscribe: store.subscribe,
    push(item: RecentGeneration) {
      store.update((state) => {
        if (state.items[0]?.value === item.value && state.items[0]?.kind === item.kind) return state
        return { items: [item, ...state.items].slice(0, MAX_RECENT_GENERATIONS) }
      })
    },
    clear() {
      store.set({ items: [] })
    },
  }
}

function createTotpStore() {
  const store = writable<TotpStoreState>({ remaining: 0, progress: '0%', refreshIssue: false })
  let timer: ReturnType<typeof window.setInterval> | undefined
  let expiryAt = 0
  let token = 0
  let refreshing = false
  let failures = 0
  let retryAt = 0
  let activeId = ''
  let applyRefresh: ((result: TotpRefresh) => void) | undefined
  let reportRepeatedFailure: (() => void) | undefined

  function stop() {
    token += 1
    if (timer) window.clearInterval(timer)
    timer = undefined
    expiryAt = 0
    refreshing = false
    failures = 0
    retryAt = 0
    activeId = ''
    applyRefresh = undefined
    reportRepeatedFailure = undefined
    store.set({ remaining: 0, progress: '0%', refreshIssue: false })
  }

  function tick(currentToken: number) {
    if (currentToken !== token || !activeId) return
    const remaining = Math.max(0, Math.ceil((expiryAt - Date.now()) / 1_000))
    store.update((state) => ({ ...state, remaining, progress: `${Math.min(100, Math.max(0, (remaining / 30) * 100))}%` }))
    if (remaining === 0 && !refreshing && Date.now() >= retryAt) void refresh(currentToken)
  }

  async function refresh(currentToken: number) {
    if (currentToken !== token || !activeId) return
    refreshing = true
    try {
      const result = await refreshTotp(activeId)
      if (currentToken !== token) return
      failures = 0
      retryAt = 0
      expiryAt = Date.now() + (result.totpRemaining ?? 30) * 1_000
      store.update((state) => ({ ...state, refreshIssue: false }))
      applyRefresh?.(result)
    } catch {
      if (currentToken !== token) return
      failures += 1
      retryAt = Date.now() + (failures >= 3 ? 5_000 : 1_500)
      store.update((state) => ({ ...state, refreshIssue: failures >= 3 }))
      if (failures === 3) reportRepeatedFailure?.()
    } finally {
      if (currentToken === token) refreshing = false
    }
  }

  return {
    subscribe: store.subscribe,
    start(card: LoginCard, id: string, onRefresh: (result: TotpRefresh) => void, onRepeatedFailure?: () => void) {
      stop()
      if (!card.totpCode) return
      activeId = id
      applyRefresh = onRefresh
      reportRepeatedFailure = onRepeatedFailure
      expiryAt = Date.now() + (card.totpRemaining ?? 30) * 1_000
      const currentToken = token
      tick(currentToken)
      timer = window.setInterval(() => tick(currentToken), 250)
    },
    stop,
  }
}

function patchable<T>(initial: T) {
  const store = writable(initial)
  return {
    subscribe: store.subscribe,
    set: store.set,
    patch(values: Partial<T>) { store.update((state) => ({ ...state, ...values })) },
    value() { return get(store) },
  }
}

export function createAppStores() {
  return {
    vault: patchable<VaultStoreState>({ status: { exists: false, unlocked: false, preview: false, pinUnlockAvailable: false, helloUnlockAvailable: false, onboardingRequired: false, revision: 0 }, snapshot: null, loginCard: null }),
    selection: patchable<SelectionStoreState>({ activeView: 'vault', activeEntryId: null, searchQuery: '', sortMode: DEFAULT_SORT_MODE, securityFilter: null, folderFilter: null, recentEntryIds: [] }),
    totp: createTotpStore(),
    generator: createGeneratorStore(),
    passphrase: createPassphraseStore(),
    recentGenerations: createRecentGenerationsStore(),
    imports: patchable<ImportStoreState>({ importing: false, source: 'bitwarden-csv', sourceMenuOpen: false, preview: null, importId: '', fileName: '', skipExactDuplicates: true }),
    browserFill: patchable<BrowserFillStoreState>({ request: null, selectedId: '', working: false, syncWorking: false, syncFailed: false }),
    browserIdentityFill: patchable<BrowserIdentityFillStoreState>({ request: null, selectedId: '', working: false, syncWorking: false, syncFailed: false }),
    browserSave: patchable<BrowserSaveStoreState>({ request: null, selectedId: '', working: false, syncWorking: false, syncFailed: false }),
    settings: patchable<SettingsStoreState>({ theme: 'auto', siteIconsEnabled: false, autoLockMinutes: 5, clipboardClearSeconds: 30, keepInTray: true, quickAccessShortcut: 'Ctrl+Alt+S' }),
  }
}

export type AppStores = ReturnType<typeof createAppStores>
const APP_STORES = Symbol('sesame-app-stores')

export function provideAppStores(stores: AppStores): AppStores {
  setContext(APP_STORES, stores)
  return stores
}

export function useAppStores(): AppStores {
  const stores = getContext<AppStores>(APP_STORES)
  if (!stores) throw new Error('Sesame app stores are not available in this component.')
  return stores
}
