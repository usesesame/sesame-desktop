/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte'
import { afterEach, expect, test, vi } from 'vitest'
import type { ItemDetail as ItemDetailShape } from '../item-fields'
import ItemDetail from './ItemDetail.svelte'

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
})

const detail: ItemDetailShape = {
  title: 'Fictional card',
  subtitle: 'Fictional brand',
  fields: [
    { label: 'Cardholder', value: 'Casey Example', secret: false, multiline: false, icon: 'user' },
    { label: 'Card number', value: '', secret: true, secretKey: 'number', multiline: false, icon: 'card' },
  ],
  notes: '',
  tags: [],
  attachments: [],
  legacyFields: [{ label: 'Old PIN', value: '', secret: true }],
  favourite: false,
}

function renderDetail(overrides: Record<string, unknown> = {}) {
  const props = {
    kind: 'card',
    detail,
    folders: [],
    revealed: {},
    onCopy: vi.fn(),
    onCopyField: vi.fn(),
    onReveal: vi.fn(),
    onHide: vi.fn(),
    onToggleFavourite: vi.fn(),
    onEdit: vi.fn(),
    onDelete: vi.fn(),
    onMove: vi.fn(),
    onShowTag: vi.fn(),
    ...overrides,
  }
  render(ItemDetail, { props } as never)
  return props
}

test('a secret stays concealed and showing it asks the host', async () => {
  const props = renderDetail()

  expect(screen.getByText('••••••••••••••••')).toBeTruthy()
  await fireEvent.click(screen.getByRole('button', { name: 'Show Card number' }))

  expect(props.onReveal).toHaveBeenCalledWith('number')
})

test('a revealed secret shows the value the host returned and can be hidden', async () => {
  const props = renderDetail({ revealed: { number: 'fictional-card-number' } })

  expect(screen.getByText('fictional-card-number')).toBeTruthy()
  await fireEvent.click(screen.getByRole('button', { name: 'Hide Card number' }))

  expect(props.onHide).toHaveBeenCalledWith('number')
})

test('copying a secret goes through the host by key and a plain field copies its own value', async () => {
  const props = renderDetail()

  await fireEvent.click(screen.getByRole('button', { name: 'Copy Card number' }))
  await fireEvent.click(screen.getByRole('button', { name: 'Copy Cardholder' }))

  expect(props.onCopyField).toHaveBeenCalledWith('number', 'Card number')
  expect(props.onCopy).toHaveBeenCalledTimes(1)
  expect(props.onCopy).toHaveBeenCalledWith('Casey Example', 'Cardholder')
})

test('a secret legacy value copies through the host by position', async () => {
  const props = renderDetail()

  await fireEvent.click(screen.getByRole('button', { name: 'Copy' }))

  expect(props.onCopyField).toHaveBeenCalledWith('legacy:0', 'Old PIN')
})
