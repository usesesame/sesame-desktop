/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte'
import { afterEach, expect, test, vi } from 'vitest'
import RecoveryKitScreen from './RecoveryKitScreen.svelte'

const KIT = 'M4K7Q-8WZP2-31HVT-6RB9N-XYQ5D'
const TWO_GROUP_KIT = 'AAAAA-BBBBB'

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
})

function renderDisplay(overrides: Record<string, unknown> = {}) {
  const onContinue = vi.fn()
  render(RecoveryKitScreen, { props: { recoveryKit: KIT, onContinue, ...overrides } } as never)
  return {
    onContinue,
    continueButton: screen.getByRole('button', { name: 'Continue' }) as HTMLButtonElement,
  }
}

function renderVerify(overrides: Record<string, unknown> = {}) {
  const onContinue = vi.fn()
  const onViewKit = vi.fn()
  render(RecoveryKitScreen, {
    props: { recoveryKit: TWO_GROUP_KIT, verifyMode: true, onContinue, onViewKit, ...overrides },
  } as never)
  return {
    onContinue,
    onViewKit,
    first: screen.getByLabelText('Group 1') as HTMLInputElement,
    second: screen.getByLabelText('Group 2') as HTMLInputElement,
  }
}

async function submitGroups(first: HTMLInputElement, second: HTMLInputElement, firstValue: string, secondValue: string) {
  await fireEvent.input(first, { target: { value: firstValue } })
  await fireEvent.input(second, { target: { value: secondValue } })
  await fireEvent.click(screen.getByRole('button', { name: 'Verify' }))
}

test('the vault stays closed until the saved kit is confirmed', async () => {
  const { onContinue, continueButton } = renderDisplay()
  expect(screen.getByText(/M4K7Q/)).toBeTruthy()
  expect(continueButton.disabled).toBe(true)

  await fireEvent.click(continueButton)
  expect(onContinue).not.toHaveBeenCalled()

  await fireEvent.click(screen.getByRole('checkbox'))
  expect(continueButton.disabled).toBe(false)

  await fireEvent.click(continueButton)
  expect(onContinue).toHaveBeenCalledTimes(1)
})

test('a failed save names the problem and leaves the confirmation gate closed', async () => {
  const onSaveToFile = vi.fn().mockRejectedValue(new Error('fictional disk failure'))
  const { continueButton } = renderDisplay({ onSaveToFile })

  await fireEvent.click(screen.getByRole('button', { name: 'Save to a file' }))

  const alert = await screen.findByRole('alert')
  expect(alert.textContent).toBe('Sesame could not save the recovery kit to a file. Try again, or write it down instead.')
  expect(screen.queryByRole('status')).toBeNull()
  expect(continueButton.disabled).toBe(true)

  await fireEvent.click(screen.getByRole('checkbox'))
  expect(continueButton.disabled).toBe(false)
})

test('a saved file is named with the reminder to move it away', async () => {
  const onSaveToFile = vi.fn().mockResolvedValue('sesame-recovery-kit.txt')
  renderDisplay({ onSaveToFile })

  await fireEvent.click(screen.getByRole('button', { name: 'Save to a file' }))

  const status = await screen.findByRole('status')
  expect(status.textContent).toBe('Saved as sesame-recovery-kit.txt. Move it somewhere Sesame cannot reach.')
  expect(screen.queryByRole('alert')).toBeNull()
})

test('verification does not show the kit again and rejects groups that do not match', async () => {
  const { onContinue, first, second } = renderVerify()
  expect(screen.getByRole('heading', { name: 'Verify your kit' })).toBeTruthy()
  expect(screen.queryByText(/AAAAA/)).toBeNull()

  await submitGroups(first, second, 'ZZZZZ', 'ZZZZZ')

  expect(onContinue).not.toHaveBeenCalled()
  expect((await screen.findByRole('alert')).textContent).toBe('One or more groups do not match. Check your written kit and try again.')
  expect(first.getAttribute('aria-invalid')).toBe('true')
  expect(second.getAttribute('aria-invalid')).toBe('true')
})

test('matching groups confirm the kit and continue', async () => {
  const { onContinue, first, second } = renderVerify()

  await submitGroups(first, second, 'aaaaa', ' bbbbb ')

  expect(onContinue).toHaveBeenCalledTimes(1)
  expect(screen.queryByRole('alert')).toBeNull()
})

test('start over clears the entered groups and the error', async () => {
  const { first, second } = renderVerify()
  await submitGroups(first, second, 'ZZZZZ', 'ZZZZZ')
  await screen.findByRole('alert')

  await fireEvent.click(screen.getByRole('button', { name: 'Start over' }))

  expect(first.value).toBe('')
  expect(second.value).toBe('')
  expect(screen.queryByRole('alert')).toBeNull()
})

test('five failed attempts offer the kit again and change the message', async () => {
  const { onContinue, onViewKit, first, second } = renderVerify()

  for (let attempt = 0; attempt < 5; attempt += 1) {
    await submitGroups(first, second, 'ZZZZZ', 'ZZZZZ')
  }

  expect(onContinue).not.toHaveBeenCalled()
  expect((await screen.findByRole('alert')).textContent).toBe('These groups still do not match. Look at your written kit again before trying once more.')

  await fireEvent.click(screen.getByRole('button', { name: 'View my kit again' }))
  expect(onViewKit).toHaveBeenCalledTimes(1)
})
