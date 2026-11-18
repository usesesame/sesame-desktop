/* @vitest-environment jsdom */
import { cleanup, render } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import ModalShell from './ModalShell.svelte'
import SyncEnableModal from './SyncEnableModal.svelte'
import SyncJoinModal from './SyncJoinModal.svelte'

let now = 0

beforeEach(() => {
  now += 10_000
  vi.spyOn(performance, 'now').mockImplementation(() => now)
  if (!document.getElementById('app')) {
    const root = document.createElement('div')
    root.id = 'app'
    document.body.appendChild(root)
  }
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const enable = { open: true, onCancel: vi.fn(), onEnable: vi.fn() }
const join = { open: true, onCancel: vi.fn(), onJoin: vi.fn() }

function steady(): boolean[] {
  return [...document.querySelectorAll('[data-modal-shell]')].map((shell) => shell.classList.contains('modal-backdrop-steady'))
}

test('a dialog that opens on its own fades its backdrop in', async () => {
  render(SyncEnableModal, enable)
  await Promise.resolve()
  expect(steady()).toEqual([false])
})

test('a dialog that replaces another one keeps the backdrop steady instead of fading it in from nothing', async () => {
  const first = render(SyncEnableModal, enable)
  await Promise.resolve()
  first.unmount()
  now += 20
  render(SyncJoinModal, join)
  await Promise.resolve()
  expect(steady()).toEqual([true])
})

test('a dialog that opens over another one that stays open does not fade a second backdrop in', async () => {
  render(SyncEnableModal, enable)
  await Promise.resolve()
  render(SyncJoinModal, join)
  await Promise.resolve()
  expect(steady()).toEqual([false, true])
})

test('a dialog that opens well after the last one closed fades in again', async () => {
  const first = render(SyncEnableModal, enable)
  await Promise.resolve()
  first.unmount()
  now += 1_000
  render(SyncJoinModal, join)
  await Promise.resolve()
  expect(steady()).toEqual([false])
})

test('a dialog is shown only once it sits in the app root, so its entrance runs once from there', async () => {
  render(SyncEnableModal, enable)
  await Promise.resolve()
  const shell = document.querySelector('[data-modal-shell]') as HTMLElement
  expect(shell.parentElement).toBe(document.getElementById('app'))
  expect(shell.classList.contains('modal-backdrop-pending')).toBe(false)
})

test('a shell that is opened after it was created is moved and shown the same way', async () => {
  const rendered = render(ModalShell, { open: false, onClose: vi.fn() })
  await Promise.resolve()
  expect(document.querySelector('[data-modal-shell]')).toBeNull()
  await rendered.rerender({ open: true, onClose: vi.fn() })
  await Promise.resolve()
  const shell = document.querySelector('[data-modal-shell]') as HTMLElement
  expect(shell.parentElement).toBe(document.getElementById('app'))
  expect(shell.classList.contains('modal-backdrop-pending')).toBe(false)
})

test('a dialog that opens while an approval is showing waits behind it and appears once it closes', async () => {
  const approval = render(ModalShell, { approval: true, onClose: vi.fn() })
  await Promise.resolve()
  const notice = vi.fn()
  render(ModalShell, { onClose: notice })
  await Promise.resolve()
  expect(document.querySelectorAll('[data-modal-shell]')).toHaveLength(1)
  window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
  expect(notice).not.toHaveBeenCalled()
  approval.unmount()
  await Promise.resolve()
  await Promise.resolve()
  expect(document.querySelectorAll('[data-modal-shell]')).toHaveLength(1)
  expect(document.querySelector('.modal-backdrop-pending')).toBeNull()
})

test('an approval ignores a click on its backdrop and Escape until it has stayed in place for a moment', async () => {
  vi.useFakeTimers()
  try {
    const onClose = vi.fn()
    render(ModalShell, { approval: true, onClose })
    await vi.advanceTimersByTimeAsync(0)
    const shell = document.querySelector('[data-modal-shell]') as HTMLElement
    shell.click()
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    await vi.advanceTimersByTimeAsync(700)
    shell.click()
    expect(onClose).not.toHaveBeenCalled()
    window.dispatchEvent(new Event('resize'))
    await vi.advanceTimersByTimeAsync(700)
    shell.click()
    expect(onClose).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(100)
    shell.click()
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    expect(onClose).toHaveBeenCalledTimes(2)
  } finally {
    vi.useRealTimers()
  }
})
