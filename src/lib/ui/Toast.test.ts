/* @vitest-environment jsdom */
import { fireEvent, render, screen } from '@testing-library/svelte'
import { afterEach, describe, expect, it, vi } from 'vitest'
import Toast from './Toast.svelte'

afterEach(() => document.body.replaceChildren())

function renderToast() {
  const onHold = vi.fn()
  const onResume = vi.fn()
  render(Toast, {
    notice: { title: 'Copied', message: 'Fictional message' },
    errorMessage: '',
    onDismissNotice: vi.fn(),
    onDismissError: vi.fn(),
    onHold,
    onResume,
  })
  return { onHold, onResume, toast: screen.getByRole('status') }
}

describe('Toast', () => {
  it('holds the notice while the pointer is over it and releases it when the pointer leaves', async () => {
    const { toast, onHold, onResume } = renderToast()
    await fireEvent.mouseEnter(toast)
    expect(onHold).toHaveBeenCalledOnce()
    await fireEvent.mouseLeave(toast)
    expect(onResume).toHaveBeenCalledOnce()
  })

  it('holds the notice while a control inside it has keyboard focus', async () => {
    const { onHold, onResume } = renderToast()
    const dismiss = screen.getByRole('button', { name: 'Dismiss notification' })
    await fireEvent.focusIn(dismiss)
    expect(onHold).toHaveBeenCalledOnce()
    await fireEvent.focusOut(dismiss)
    expect(onResume).toHaveBeenCalledOnce()
  })
})
