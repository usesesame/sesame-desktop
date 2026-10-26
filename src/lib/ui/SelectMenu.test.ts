/* @vitest-environment jsdom */
import { fireEvent, render, screen } from '@testing-library/svelte'
import { afterEach, describe, expect, it, vi } from 'vitest'
import SelectMenu from './SelectMenu.svelte'

const OPTIONS = [
  { value: 'a', label: 'Alpha' },
  { value: 'b', label: 'Beta' },
]

function renderMenu() {
  return render(SelectMenu, { value: 'a', options: OPTIONS, label: 'Sort order', onChange: vi.fn() })
}

afterEach(() => document.body.replaceChildren())

describe('SelectMenu', () => {
  it('closes only the menu when Escape is pressed on an option', async () => {
    const outer = vi.fn()
    window.addEventListener('keydown', outer)
    renderMenu()
    await fireEvent.click(screen.getByRole('button', { name: /Sort order/ }))
    const option = screen.getByRole('option', { name: 'Beta' })

    await fireEvent.keyDown(option, { key: 'Escape' })

    expect(screen.queryByRole('listbox')).toBeNull()
    expect(outer).not.toHaveBeenCalled()
    window.removeEventListener('keydown', outer)
  })

  it('closes only the menu when Escape is pressed on the open trigger', async () => {
    const outer = vi.fn()
    window.addEventListener('keydown', outer)
    renderMenu()
    const trigger = screen.getByRole('button', { name: /Sort order/ })
    await fireEvent.click(trigger)

    await fireEvent.keyDown(trigger, { key: 'Escape' })

    expect(screen.queryByRole('listbox')).toBeNull()
    expect(outer).not.toHaveBeenCalled()
    window.removeEventListener('keydown', outer)
  })

  it('lets Escape through when the menu is closed', async () => {
    const outer = vi.fn()
    window.addEventListener('keydown', outer)
    renderMenu()

    await fireEvent.keyDown(screen.getByRole('button', { name: /Sort order/ }), { key: 'Escape' })

    expect(outer).toHaveBeenCalledOnce()
    window.removeEventListener('keydown', outer)
  })

  it('names the trigger with its current value', () => {
    renderMenu()
    expect(screen.getByRole('button', { name: 'Sort order: Alpha' })).toBeTruthy()
  })

  it('points aria-controls at the list only while it is open', async () => {
    renderMenu()
    const trigger = screen.getByRole('button', { name: /Sort order/ })
    expect(trigger.getAttribute('aria-controls')).toBeNull()
    await fireEvent.click(trigger)
    const list = screen.getByRole('listbox')
    expect(trigger.getAttribute('aria-controls')).toBe(list.id)
    expect(list.id).not.toBe('')
  })
})
