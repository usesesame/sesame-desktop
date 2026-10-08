/* @vitest-environment jsdom */
import { cleanup, render, screen, within } from '@testing-library/svelte'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { APP_STORES, createAppStores } from '../stores/app-stores'
import type { ImportAccounting, ImportPreview, ImportSource } from '../types'
import ImportModal from './ImportModal.svelte'

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
})

beforeEach(() => {
  const root = document.createElement('div')
  root.id = 'app'
  document.body.appendChild(root)
})

const emptyCounts = { imported: 0, transformed: 0, legacy: 0, malformed: 0, intentionallyOmitted: 0 }

const importSources: Array<{ value: ImportSource; label: string }> = [
  { value: 'bitwarden-json', label: 'Bitwarden JSON (recommended)' },
  { value: 'bitwarden-csv', label: 'Bitwarden CSV' },
  { value: 'aegis-json', label: 'Aegis JSON' },
  { value: '2fas-json', label: '2FAS JSON' },
]

const mixedExport: ImportAccounting = {
  supplied: 6,
  accepted: 2,
  retained: 0,
  unsupported: 2,
  malformed: 2,
  reasons: [
    { reason: 'counterBasedCode', count: 1 },
    { reason: 'steamCode', count: 1 },
    { reason: 'unknownAlgorithm', count: 1 },
    { reason: 'unusableCode', count: 1 },
  ],
}

function preview(accounting: ImportAccounting): ImportPreview {
  return {
    totalEntries: accounting.accepted + accounting.retained,
    exactDuplicates: 0,
    accountConflicts: 0,
    duplicateEntries: 0,
    missingUrls: 2,
    invalidUrls: 0,
    noTotp: 0,
    invalidTotp: 0,
    preservedLegacyFields: 0,
    secureNotes: 0,
    cards: 0,
    identities: 0,
    sshKeys: 0,
    passkeysNotImported: 0,
    intentionallyOmittedItems: accounting.unsupported,
    accounting,
    fidelity: {
      logins: { ...emptyCounts },
      secureNotes: { ...emptyCounts },
      cards: { ...emptyCounts },
      identities: { ...emptyCounts },
      sshKeys: { ...emptyCounts },
      passkeys: { ...emptyCounts },
      unsupportedItems: { ...emptyCounts },
    },
  }
}

function renderModal(state: { source: ImportSource; preview: ImportPreview | null }, overrides: Record<string, unknown> = {}) {
  const stores = createAppStores()
  stores.imports.patch({ source: state.source, preview: state.preview, fileName: 'fictional-export.json', importId: 'fictional-import' })
  const props = {
    importSources,
    onClose: vi.fn(),
    onChooseSource: vi.fn(),
    onHandleImport: vi.fn(),
    onResetImport: vi.fn(),
    onConfirmImport: vi.fn(),
    ...overrides,
  }
  render(ImportModal, { props, context: new Map([[APP_STORES, stores]]) })
  return { stores, props }
}

test('a mixed authenticator export shows every code and why each omitted one was left out', () => {
  renderModal({ source: 'aegis-json', preview: preview(mixedExport) })
  expect(screen.getByText('2 of 6 codes can be added')).toBeTruthy()
  const list = screen.getByRole('region', { name: 'What happens to each code in this file' })
  const rows = within(list).getAllByRole('listitem').map((row) => row.textContent?.replace(/\s+/g, ' ').trim())
  expect(rows).toContain('Added to your vault 2')
  expect(rows.some((row) => row?.startsWith('Not supported by Sesame yet 2'))).toBe(true)
  expect(rows).toContain('Counter-based codes (HOTP) 1')
  expect(rows).toContain('Steam Guard codes 1')
  expect(rows.some((row) => row?.startsWith('Could not be read 2'))).toBe(true)
  expect(rows).toContain('Codes with a hash algorithm Sesame does not recognise 1')
  expect(rows).toContain('Codes whose secret or settings produce no code 1')
  expect(rows).toContain('In this file 6')
})

test('omitted codes come with a plain line to keep the old authenticator', () => {
  renderModal({ source: '2fas-json', preview: preview(mixedExport) })
  const note = screen.getByRole('note')
  expect(note.textContent).toBe('Sesame will not add 4 codes, so they exist only in your old authenticator. Keep it until you have set those codes up again.')
})

test('a single omitted code is described in the singular', () => {
  const accounting: ImportAccounting = { supplied: 3, accepted: 2, retained: 0, unsupported: 1, malformed: 0, reasons: [{ reason: 'steamCode', count: 1 }] }
  renderModal({ source: 'aegis-json', preview: preview(accounting) })
  expect(screen.getByRole('note').textContent).toBe('Sesame will not add 1 code, so it exists only in your old authenticator. Keep it until you have set that code up again.')
})

test('an authenticator export with nothing omitted shows the count and no warning', () => {
  const accounting: ImportAccounting = { supplied: 3, accepted: 3, retained: 0, unsupported: 0, malformed: 0, reasons: [] }
  renderModal({ source: 'aegis-json', preview: preview(accounting) })
  expect(screen.getByText('3 of 3 codes can be added')).toBeTruthy()
  expect(screen.queryByRole('note')).toBeNull()
})

test('a login export with unsupported items names them and keeps the old manager', () => {
  const accounting: ImportAccounting = { supplied: 5, accepted: 3, retained: 1, unsupported: 1, malformed: 0, reasons: [{ reason: 'unsupportedItemType', count: 1 }] }
  renderModal({ source: 'bitwarden-json', preview: preview(accounting) })
  const list = screen.getByRole('region', { name: 'What happens to each item in this file' })
  expect(within(list).getByText('Added, with extra fields kept in Legacy data')).toBeTruthy()
  expect(within(list).getByText('Items of a type Sesame cannot import yet')).toBeTruthy()
  expect(screen.getByRole('note').textContent).toBe('Sesame will not add 1 item, so it exists only in your old password manager. Keep it until you have saved that item somewhere else.')
})

test('a login export with every item accepted adds no accounting list', () => {
  const accounting: ImportAccounting = { supplied: 4, accepted: 4, retained: 0, unsupported: 0, malformed: 0, reasons: [] }
  renderModal({ source: 'bitwarden-json', preview: preview(accounting) })
  expect(screen.queryByRole('region', { name: /What happens to each/ })).toBeNull()
  expect(screen.getByText('4 logins found')).toBeTruthy()
})

test('the Bitwarden CSV choice explains what CSV leaves out and offers JSON', async () => {
  const user = userEvent.setup()
  const { props } = renderModal({ source: 'bitwarden-csv', preview: null })
  expect(screen.getByText(/leaves out custom fields/)).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Import from' }).getAttribute('aria-describedby')).toBe('import-source-note')
  await user.click(screen.getByRole('button', { name: 'Use Bitwarden JSON' }))
  expect(props.onChooseSource).toHaveBeenCalledWith('bitwarden-json')
})

test('the Bitwarden JSON choice carries no CSV warning and the chooser lists it first', async () => {
  const user = userEvent.setup()
  renderModal({ source: 'bitwarden-json', preview: null })
  expect(screen.queryByText(/leaves out custom fields/)).toBeNull()
  await user.click(screen.getByRole('button', { name: 'Import from' }))
  const options = screen.getAllByRole('option').map((option) => option.textContent)
  expect(options.slice(0, 2)).toEqual(['Bitwarden JSON (recommended)', 'Bitwarden CSV'])
})

test('rows with no credentials and unreadable rows are listed as could not be read', () => {
  const accounting: ImportAccounting = {
    supplied: 5,
    accepted: 3,
    retained: 0,
    unsupported: 0,
    malformed: 2,
    reasons: [
      { reason: 'missingCredentials', count: 1 },
      { reason: 'unreadableRow', count: 1 },
    ],
  }
  renderModal({ source: 'bitwarden-json', preview: preview(accounting) })
  const list = screen.getByRole('region', { name: 'What happens to each item in this file' })
  expect(within(list).getByText('Rows with no name, username or password')).toBeTruthy()
  expect(within(list).getByText('Rows Sesame could not read')).toBeTruthy()
  expect(screen.getByRole('note').textContent).toBe('Sesame will not add 2 items, so they exist only in your old password manager. Keep it until you have saved those items somewhere else.')
})
