/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte'
import { afterEach, expect, test, vi } from 'vitest'
import KeptSecret from './KeptSecret.svelte'

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
})

test('a kept secret with nothing typed says the saved value stays and offers to remove it', async () => {
  const onChange = vi.fn()
  render(KeptSecret, { props: { draft: { keptSecrets: ['number'] }, key: 'number', typed: '', onChange } })

  expect(screen.getByText(/A saved value stays as it is/)).toBeTruthy()
  await fireEvent.click(screen.getByRole('button', { name: 'Remove it' }))

  expect(onChange).toHaveBeenCalledWith({ keptSecrets: [] })
  expect(screen.getByText(/removed when you save/)).toBeTruthy()
})

test('removing a saved value can be undone before saving', async () => {
  const onChange = vi.fn()
  render(KeptSecret, { props: { draft: { keptSecrets: ['number', 'securityCode'] }, key: 'number', typed: '', onChange } })

  await fireEvent.click(screen.getByRole('button', { name: 'Remove it' }))
  await fireEvent.click(screen.getByRole('button', { name: 'Keep it' }))

  expect(onChange).toHaveBeenLastCalledWith({ keptSecrets: ['number', 'securityCode', 'number'] })
})

test('a typed value hides the hint because it replaces the saved one', () => {
  render(KeptSecret, { props: { draft: { keptSecrets: ['number'] }, key: 'number', typed: '4242', onChange: vi.fn() } })

  expect(screen.queryByText(/A saved value stays/)).toBeNull()
})

test('a secret that was never saved shows no hint', () => {
  render(KeptSecret, { props: { draft: { keptSecrets: [] }, key: 'number', typed: '', onChange: vi.fn() } })

  expect(screen.queryByText(/A saved value stays/)).toBeNull()
})

test('a different secret kept on the same item does not show this field a hint', () => {
  render(KeptSecret, { props: { draft: { keptSecrets: ['securityCode'] }, key: 'number', typed: '', onChange: vi.fn() } })

  expect(screen.queryByText(/A saved value stays/)).toBeNull()
})
