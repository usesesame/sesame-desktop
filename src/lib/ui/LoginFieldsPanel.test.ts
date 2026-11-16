/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte'
import { afterEach, expect, test, vi } from 'vitest'
import type { CustomFieldEntry } from '../types'
import LoginFieldsPanel from './LoginFieldsPanel.svelte'

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
})

const fields: CustomFieldEntry[] = [
  { label: 'Member number', value: 'fictional-42', kind: 'text' },
  { label: 'Security answer', value: '', kind: 'secret' },
  { label: 'Support PIN', value: '', kind: 'secret' },
]

function renderPanel(overrides: Record<string, unknown> = {}) {
  const props = {
    fields,
    secretFields: ['field:1'],
    revealed: {},
    onCopy: vi.fn(),
    onCopyField: vi.fn(),
    onReveal: vi.fn(),
    onHide: vi.fn(),
    ...overrides,
  }
  render(LoginFieldsPanel, { props } as never)
  return props
}

test('a visible field shows its value and copies it from the card', async () => {
  const props = renderPanel()

  expect(screen.getByText('fictional-42')).toBeTruthy()
  await fireEvent.click(screen.getByRole('button', { name: 'Copy Member number' }))

  expect(props.onCopy).toHaveBeenCalledWith('fictional-42', 'Member number')
})

test('a hidden field stays masked and reveal and copy go through the host by slot', async () => {
  const props = renderPanel()

  expect(screen.getByText('••••••••••••••••')).toBeTruthy()
  await fireEvent.click(screen.getByRole('button', { name: 'Show Security answer' }))
  await fireEvent.click(screen.getByRole('button', { name: 'Copy Security answer' }))

  expect(props.onReveal).toHaveBeenCalledWith('field:1')
  expect(props.onCopyField).toHaveBeenCalledWith('field:1', 'Security answer')
  expect(props.onCopy).not.toHaveBeenCalled()
})

test('a revealed hidden field shows the host value and can be hidden again', async () => {
  const props = renderPanel({ revealed: { 'field:1': 'fictional-hidden-answer' } })

  expect(screen.getByText('fictional-hidden-answer')).toBeTruthy()
  const hide = screen.getByRole('button', { name: 'Hide Security answer' })
  expect(hide.getAttribute('aria-pressed')).toBe('true')
  await fireEvent.click(hide)

  expect(props.onHide).toHaveBeenCalledWith('field:1')
})

test('a hidden field with nothing saved cannot be revealed or copied', () => {
  renderPanel()

  expect((screen.getByRole('button', { name: 'Show Support PIN' }) as HTMLButtonElement).disabled).toBe(true)
  expect((screen.getByRole('button', { name: 'Copy Support PIN' }) as HTMLButtonElement).disabled).toBe(true)
})

test('every icon button has a title matching its label', () => {
  renderPanel()

  for (const button of screen.getAllByRole('button')) {
    expect(button.getAttribute('title')).toBe(button.getAttribute('aria-label'))
  }
})

test('a login without custom fields shows no section', () => {
  renderPanel({ fields: [], secretFields: [] })

  expect(screen.queryByText('Custom fields')).toBeNull()
})
