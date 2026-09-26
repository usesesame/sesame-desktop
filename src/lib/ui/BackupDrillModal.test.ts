/* @vitest-environment jsdom */
import { cleanup, render, screen } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import type { BackupCompatibility, BackupVerification } from '../types'
import BackupDrillModal from './BackupDrillModal.svelte'

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
})

beforeEach(() => {
  const root = document.createElement('div')
  root.id = 'app'
  document.body.appendChild(root)
})

function selection(compatibility: BackupCompatibility) {
  return {
    source: '/tmp/fictional-backup.sesame',
    fileName: 'fictional-backup.sesame',
    formatVersion: compatibility === 'current' ? 10 : 8,
    compatibility,
    setupComplete: true,
  }
}

function verification(compatibility: BackupCompatibility): BackupVerification {
  return {
    ...selection(compatibility),
    vaultName: 'Fictional Story Vault',
    entryCount: 2,
    vaultId: 'fictional-vault',
    revision: 2,
  }
}

function renderDrill(overrides: Record<string, unknown> = {}) {
  return render(BackupDrillModal, {
    onChoose: vi.fn(),
    onVerify: vi.fn(),
    onRestore: vi.fn(),
    onClose: vi.fn(),
    ...overrides,
  })
}

test('an empty drill starts with the file choice', async () => {
  renderDrill()
  await Promise.resolve()
  expect(screen.getByRole('heading', { name: 'Prove your backup opens' })).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Choose backup' })).toBeTruthy()
})

test('a chosen current backup names its format and focuses the secret field', async () => {
  renderDrill({ selection: selection('current') })
  await Promise.resolve()
  expect(screen.getByText('Sesame format 10')).toBeTruthy()
  const secret = screen.getByLabelText('Master password or recovery kit') as HTMLInputElement
  await vi.waitFor(() => expect(document.activeElement).toBe(secret))
})

test('a chosen older backup names the older format', async () => {
  renderDrill({ selection: selection('upgrade') })
  await Promise.resolve()
  expect(screen.getByText('Older Sesame format 8')).toBeTruthy()
})

test('a chosen newer backup names the update action without a secret form', async () => {
  renderDrill({ selection: selection('newer') })
  await Promise.resolve()
  expect(screen.queryByLabelText('Master password or recovery kit')).toBeNull()
  expect(screen.queryByRole('button', { name: 'Verify backup' })).toBeNull()
  expect(screen.getByRole('status').textContent).toContain('Update Sesame')
})

test('a verified current backup confirms the open without an upgrade note', async () => {
  renderDrill({ selection: selection('current'), verification: verification('current') })
  await Promise.resolve()
  const result = screen.getByRole('status')
  expect(result.textContent).toContain('This backup opened successfully.')
  expect(result.textContent).toContain('Sesame format 10')
  expect(screen.getByText(/For a complete drill/)).toBeTruthy()
  expect(screen.queryByText(/upgrades a copy/)).toBeNull()
})

test('a verified older backup says the copy is upgraded and the file is left unchanged', async () => {
  renderDrill({ selection: selection('upgrade'), verification: verification('upgrade') })
  await Promise.resolve()
  expect(screen.getByRole('status').textContent).toContain('Older Sesame format 8')
  const note = screen.getByText(/upgrades a copy to the current format and leaves the selected backup unchanged/)
  expect(note).toBeTruthy()
  expect(note.textContent).not.toMatch(/broken|damaged|corrupt/i)
})

test('a wrong secret announces the backend message without calling the file broken', async () => {
  renderDrill({ selection: selection('current'), secret: 'fictional wrong password', error: 'That master password or recovery kit does not open this backup.' })
  await Promise.resolve()
  const alert = screen.getByRole('alert')
  expect(alert.textContent).toBe('That master password or recovery kit does not open this backup.')
  expect(alert.textContent).not.toMatch(/broken|damaged|corrupt/i)
})

test('an integrity failure announces what failed and the next safe action', async () => {
  renderDrill({ selection: selection('current'), secret: 'fictional master password 01', error: 'The vault data could not be authenticated. Restore a known-good encrypted backup.' })
  await Promise.resolve()
  expect(screen.getByRole('alert').textContent).toBe('The vault data could not be authenticated. Restore a known-good encrypted backup.')
})

test('a working verification marks the dialog busy', async () => {
  renderDrill({ selection: selection('current'), working: true })
  await Promise.resolve()
  expect(screen.getByRole('dialog').getAttribute('aria-busy')).toBe('true')
})
