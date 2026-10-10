/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte'
import { tick } from 'svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { APP_STORES, createAppStores } from '../stores/app-stores'
import type { ImportPreview } from '../types'
import ImportModal from './ImportModal.svelte'

const sources = [
  { value: 'bitwarden-csv', label: 'Bitwarden CSV' },
  { value: 'lastpass-csv', label: 'LastPass CSV' },
] as const

function preview(overrides: Partial<ImportPreview> = {}): ImportPreview {
  return {
    totalEntries: 3,
    exactDuplicates: 0,
    accountConflicts: 0,
    duplicateEntries: 0,
    missingUrls: 0,
    invalidUrls: 0,
    noTotp: 0,
    invalidTotp: 0,
    preservedLegacyFields: 0,
    secureNotes: 0,
    cards: 0,
    identities: 0,
    sshKeys: 0,
    passkeysNotImported: 0,
    intentionallyOmittedItems: 0,
    fidelity: {
      logins: { imported: 3, transformed: 0, legacy: 0, malformed: 0, intentionallyOmitted: 0 },
      secureNotes: { imported: 0, transformed: 0, legacy: 0, malformed: 0, intentionallyOmitted: 0 },
      cards: { imported: 0, transformed: 0, legacy: 0, malformed: 0, intentionallyOmitted: 0 },
      identities: { imported: 0, transformed: 0, legacy: 0, malformed: 0, intentionallyOmitted: 0 },
      sshKeys: { imported: 0, transformed: 0, legacy: 0, malformed: 0, intentionallyOmitted: 0 },
      passkeys: { imported: 0, transformed: 0, legacy: 0, malformed: 0, intentionallyOmitted: 0 },
      unsupportedItems: { imported: 0, transformed: 0, legacy: 0, malformed: 0, intentionallyOmitted: 0 },
    },
    ...overrides,
  }
}

beforeEach(() => {
  if (!document.getElementById('app')) {
    const root = document.createElement('div')
    root.id = 'app'
    document.body.appendChild(root)
  }
})

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
})

function renderImport(overrides: Record<string, unknown> = {}) {
  const stores = createAppStores()
  const props = {
    importSources: sources,
    onClose: vi.fn(),
    onChooseSource: vi.fn(),
    onHandleImport: vi.fn(),
    onResetImport: vi.fn(),
    onConfirmImport: vi.fn(),
    ...overrides,
  }
  render(ImportModal, { props, context: new Map([[APP_STORES, stores]]) } as never)
  return { stores, props }
}

test('choosing an export file starts the local read', async () => {
  const { props } = renderImport()

  expect(screen.getByText('Reads it on this device before changing your vault.')).toBeTruthy()
  await fireEvent.click(screen.getByRole('button', { name: /Choose export file/ }))
  expect(props.onHandleImport).toHaveBeenCalledTimes(1)
})

test('a read in progress blocks closing and starting another read', async () => {
  const { stores, props } = renderImport()
  stores.imports.patch({ importing: true })
  await tick()

  const picker = screen.getByRole('button', { name: /Reading export…/ }) as HTMLButtonElement
  expect(picker.disabled).toBe(true)

  const close = screen.getByRole('button', { name: 'Close import' }) as HTMLButtonElement
  expect(close.disabled).toBe(true)
  await fireEvent.click(close)
  expect(props.onClose).not.toHaveBeenCalled()
  expect(screen.getByRole('dialog').getAttribute('aria-busy')).toBe('true')
})

test('a preview lists what will change and confirms only on request', async () => {
  const { stores, props } = renderImport()
  stores.imports.patch({
    preview: preview({ accountConflicts: 1, invalidTotp: 1 }),
    fileName: 'fictional-export.csv',
    importId: 'fictional-import',
  })
  await tick()

  expect(screen.getByRole('heading', { name: 'Check this import' })).toBeTruthy()
  expect(screen.getByText(/fictional-export\.csv stays on this device/)).toBeTruthy()
  expect(screen.getByText('3 logins found')).toBeTruthy()
  expect(screen.getByText('Conflicting account details stay separate.')).toBeTruthy()
  expect(screen.getByText('Some values could not be used.')).toBeTruthy()
  expect((screen.getByRole('checkbox') as HTMLInputElement).checked).toBe(true)

  await fireEvent.click(screen.getByRole('button', { name: 'Choose another file' }))
  expect(props.onResetImport).toHaveBeenCalledTimes(1)
  expect(props.onConfirmImport).not.toHaveBeenCalled()

  await fireEvent.click(screen.getByRole('button', { name: 'Add to vault' }))
  expect(props.onConfirmImport).toHaveBeenCalledTimes(1)
})

test('a source is chosen from the list without closing the dialog', async () => {
  const { props } = renderImport()

  await fireEvent.click(screen.getByRole('button', { name: 'Import from' }))
  const option = screen.getByRole('option', { name: 'LastPass CSV' })
  await fireEvent.click(option)

  expect(props.onChooseSource).toHaveBeenCalledWith('lastpass-csv')
  expect(props.onClose).not.toHaveBeenCalled()
  expect(screen.queryByRole('listbox')).toBeNull()
})

test('Escape closes the open source list before it closes the dialog', async () => {
  const { props } = renderImport()

  await fireEvent.click(screen.getByRole('button', { name: 'Import from' }))
  await fireEvent.keyDown(screen.getByRole('option', { name: 'LastPass CSV' }), { key: 'Escape' })

  expect(screen.queryByRole('listbox')).toBeNull()
  expect(props.onClose).not.toHaveBeenCalled()
})
