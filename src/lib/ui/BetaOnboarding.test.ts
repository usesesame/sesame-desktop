/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import BetaOnboarding from './BetaOnboarding.svelte'

beforeEach(() => {
  const root = document.createElement('div')
  root.id = 'app'
  document.body.appendChild(root)
})

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
})

function renderOnboarding() {
  const props = { onContinue: vi.fn(), onImport: vi.fn(), onAddLogin: vi.fn(), onOpenBackups: vi.fn() }
  render(BetaOnboarding, { props })
  return props
}

test('the last setup screen offers the three first steps and one primary action', () => {
  renderOnboarding()

  expect(screen.getByRole('heading', { name: 'Your vault is ready' })).toBeTruthy()
  expect(screen.getByText('Bring in your logins')).toBeTruthy()
  expect(screen.getByText('Save one login you use')).toBeTruthy()
  expect(screen.getByText('Back up and prove it opens')).toBeTruthy()
  expect(document.querySelectorAll('.primary-button')).toHaveLength(1)
})

test('each step starts its own action and nothing else', async () => {
  const props = renderOnboarding()

  await fireEvent.click(screen.getByRole('button', { name: 'Import' }))
  await fireEvent.click(screen.getByRole('button', { name: 'Add a login' }))
  await fireEvent.click(screen.getByRole('button', { name: 'Open backups' }))

  expect(props.onImport).toHaveBeenCalledTimes(1)
  expect(props.onAddLogin).toHaveBeenCalledTimes(1)
  expect(props.onOpenBackups).toHaveBeenCalledTimes(1)
  expect(props.onContinue).not.toHaveBeenCalled()
})

test('continue closes the screen', async () => {
  const props = renderOnboarding()

  await fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
  expect(props.onContinue).toHaveBeenCalledTimes(1)
})

test('the screen makes no promise the app cannot keep', () => {
  renderOnboarding()

  expect(screen.queryByText(/audited|secure|safe from/i)).toBeNull()
  expect(screen.getByText(/keep the old one until you have checked/i)).toBeTruthy()
})
