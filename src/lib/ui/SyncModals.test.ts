/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import SyncConflictModal from './SyncConflictModal.svelte'
import SyncEnableModal from './SyncEnableModal.svelte'
import SyncJoinModal from './SyncJoinModal.svelte'
import SyncPairingModal from './SyncPairingModal.svelte'

beforeEach(() => {
  const root = document.createElement('div')
  root.id = 'app'
  document.body.appendChild(root)
})

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
})

const side = (overrides = {}) => ({ deviceLabel: 'Fictional laptop', revision: 4, changedAt: '', entryCount: 12, ...overrides })

test('the enable screen says plainly that no independent review has happened', () => {
  render(SyncEnableModal, { open: true, onCancel: vi.fn(), onEnable: vi.fn() })
  expect(screen.getByRole('note').textContent).toMatch(/has not had an independent security review/)
  expect(document.body.textContent).not.toMatch(/\b(audited|secure by|production-ready)\b/i)
})

test('enabling Sync explains the backup needed if every approved device is lost', () => {
  render(SyncEnableModal, { open: true, onCancel: vi.fn(), onEnable: vi.fn() })
  expect(document.body.textContent).toMatch(/Keep a vault backup and your recovery kit/)
  expect(document.body.textContent).toMatch(/need an approved device to add another one/)
  expect(document.body.textContent).not.toMatch(/recovery kit is the only way back/)
})

test('turning on Sync needs the recovery kit confirmation and a device name', async () => {
  const onEnable = vi.fn()
  render(SyncEnableModal, { open: true, onCancel: vi.fn(), onEnable })
  const turnOn = screen.getByRole('button', { name: 'Turn on Sync' }) as HTMLButtonElement
  expect(turnOn.disabled).toBe(true)
  await fireEvent.click(screen.getByRole('checkbox'))
  expect(turnOn.disabled).toBe(false)
  const name = screen.getByRole('textbox') as HTMLInputElement
  await fireEvent.input(name, { target: { value: '   ' } })
  expect(turnOn.disabled).toBe(true)
  await fireEvent.input(name, { target: { value: '  Fictional laptop  ' } })
  await fireEvent.click(turnOn)
  expect(onEnable).toHaveBeenCalledWith('Fictional laptop')
})

test('the enable screen locks its controls while working and shows an error', () => {
  render(SyncEnableModal, { open: true, working: true, error: 'The service said no.', onCancel: vi.fn(), onEnable: vi.fn() })
  expect((screen.getByRole('button', { name: 'Cancel' }) as HTMLButtonElement).disabled).toBe(true)
  expect((screen.getByRole('button', { name: 'Turning on Sync…' }) as HTMLButtonElement).disabled).toBe(true)
  expect(screen.getByRole('alert').textContent).toBe('The service said no.')
})

test('joining needs a ten character code, a name and the master password', async () => {
  const onJoin = vi.fn()
  render(SyncJoinModal, { open: true, onCancel: vi.fn(), onJoin })
  const join = screen.getByRole('button', { name: 'Join vault' }) as HTMLButtonElement
  const code = document.querySelector<HTMLInputElement>('input[name="sync-code"]')!
  const password = document.querySelector<HTMLInputElement>('input[name="sync-master-password"]')!
  await fireEvent.input(code, { target: { value: 'ABCDE-FGH' } })
  await fireEvent.input(password, { target: { value: 'fictional master password' } })
  expect(join.disabled).toBe(true)
  await fireEvent.input(code, { target: { value: 'ABCDE-FGHJK' } })
  expect(join.disabled).toBe(false)
  await fireEvent.input(password, { target: { value: '' } })
  expect(join.disabled).toBe(true)
  await fireEvent.input(password, { target: { value: 'fictional master password' } })
  await fireEvent.click(join)
  expect(onJoin).toHaveBeenCalledWith('ABCDE-FGHJK', 'This computer', 'fictional master password')
})

test('joining clears the code and password when the screen closes and reopens', async () => {
  const { rerender } = render(SyncJoinModal, { open: true, onCancel: vi.fn(), onJoin: vi.fn() })
  await fireEvent.input(document.querySelector('input[name="sync-code"]')!, { target: { value: 'ABCDEFGHJK' } })
  await fireEvent.input(document.querySelector('input[name="sync-master-password"]')!, { target: { value: 'fictional master password' } })
  await rerender({ open: false })
  await rerender({ open: true })
  expect((document.querySelector('input[name="sync-code"]') as HTMLInputElement).value).toBe('')
  expect((document.querySelector('input[name="sync-master-password"]') as HTMLInputElement).value).toBe('')
})

test('finishing an approved join needs the master password and no new code', async () => {
  const onJoin = vi.fn()
  render(SyncJoinModal, { open: true, resuming: true, onCancel: vi.fn(), onJoin })
  expect(screen.getByRole('heading', { name: 'Finish joining' })).toBeTruthy()
  expect(document.querySelector('input[name="sync-code"]')).toBeNull()
  expect(document.querySelector('input[name="sync-device-name"]')).toBeNull()
  const finish = screen.getByRole('button', { name: 'Finish joining' }) as HTMLButtonElement
  expect(finish.disabled).toBe(true)
  await fireEvent.input(document.querySelector('input[name="sync-master-password"]')!, { target: { value: 'fictional master password' } })
  expect(finish.disabled).toBe(false)
  await fireEvent.click(finish)
  expect(onJoin).toHaveBeenCalledWith('', 'This computer', 'fictional master password')
})

test('joining shows the wait and the error and cannot be submitted twice', () => {
  render(SyncJoinModal, { open: true, working: true, error: 'The other device did not answer in time.', onCancel: vi.fn(), onJoin: vi.fn() })
  expect(screen.getByRole('status').textContent).toMatch(/Waiting for the other device/)
  expect(screen.getByRole('alert').textContent).toMatch(/did not answer/)
  expect((screen.getByRole('button', { name: 'Joining…' }) as HTMLButtonElement).disabled).toBe(true)
})

test('the pairing code is grouped, counts down and says it never reaches the server', () => {
  render(SyncPairingModal, { open: true, code: 'ABCDEFGHJK', phase: 'waiting', secondsLeft: 125, onClose: vi.fn(), onRetry: vi.fn() })
  expect(screen.getByLabelText('Pairing code').textContent).toBe('ABCDE FGHJK')
  expect(document.body.textContent).toMatch(/expires in 2:05/)
  expect(document.body.textContent).toMatch(/never sent to the server/)
})

test('a finished pairing names the device and offers Done', async () => {
  const onClose = vi.fn()
  render(SyncPairingModal, { open: true, phase: 'done', doneLabel: 'Fictional phone', onClose, onRetry: vi.fn() })
  expect(screen.getByRole('status').textContent).toMatch(/Fictional phone was added to this vault/)
  await fireEvent.click(screen.getByRole('button', { name: 'Done' }))
  expect(onClose).toHaveBeenCalled()
})

test('a failed pairing offers a new code and shows no old one', async () => {
  const onRetry = vi.fn()
  render(SyncPairingModal, { open: true, phase: 'idle', error: 'Pairing was cancelled.', onClose: vi.fn(), onRetry })
  expect(screen.queryByLabelText('Pairing code')).toBeNull()
  await fireEvent.click(screen.getByRole('button', { name: 'Show a new code' }))
  expect(onRetry).toHaveBeenCalled()
})

test('the conflict screen preselects no side and keeps the button off until both sides are read', async () => {
  const onKeep = vi.fn()
  const { rerender } = render(SyncConflictModal, {
    open: true, thisDevice: side(), otherDevice: side({ deviceLabel: 'Fictional phone', revision: 5 }), detailsLoaded: false,
    onCancel: vi.fn(), onKeep,
  })
  const radios = screen.getAllByRole('radio') as HTMLInputElement[]
  expect(radios.map((radio) => radio.checked)).toEqual([false, false])
  const keep = screen.getByRole('button', { name: 'Keep selected version' }) as HTMLButtonElement
  await fireEvent.click(radios[1])
  expect(keep.disabled).toBe(true)
  await rerender({ detailsLoaded: true })
  expect(keep.disabled).toBe(false)
  await fireEvent.click(keep)
  expect(onKeep).toHaveBeenCalledWith('other')
})

test('the conflict screen forgets the choice when it closes', async () => {
  const { rerender } = render(SyncConflictModal, {
    open: true, thisDevice: side(), otherDevice: side({ revision: 5 }), detailsLoaded: true, onCancel: vi.fn(), onKeep: vi.fn(),
  })
  await fireEvent.click(screen.getAllByRole('radio')[0])
  await rerender({ open: false })
  await rerender({ open: true })
  expect((screen.getAllByRole('radio') as HTMLInputElement[]).map((radio) => radio.checked)).toEqual([false, false])
})

test('the conflict screen shows both sides as they are', () => {
  render(SyncConflictModal, {
    open: true, thisDevice: side({ revision: 4, entryCount: 12 }), otherDevice: side({ deviceLabel: 'Fictional phone', revision: 5, entryCount: 14 }),
    detailsLoaded: true, onCancel: vi.fn(), onKeep: vi.fn(),
  })
  expect(document.body.textContent).toMatch(/Revision 4/)
  expect(document.body.textContent).toMatch(/12 logins/)
  expect(document.body.textContent).toMatch(/Fictional phone/)
  expect(document.body.textContent).toMatch(/Revision 5/)
  expect(document.body.textContent).toMatch(/14 logins/)
})

test('Escape does not close the enable screen while Sync is being turned on', async () => {
  const onCancel = vi.fn()
  const view = render(SyncEnableModal, { open: true, working: true, onCancel, onEnable: vi.fn() })
  await Promise.resolve()
  await fireEvent.keyDown(window, { key: 'Escape' })
  expect(onCancel).not.toHaveBeenCalled()
  await view.rerender({ open: true, working: false, onCancel, onEnable: vi.fn() })
  await fireEvent.keyDown(window, { key: 'Escape' })
  expect(onCancel).toHaveBeenCalledOnce()
})

test('Escape does not close the conflict screen while a choice is being applied', async () => {
  const onCancel = vi.fn()
  const view = render(SyncConflictModal, { open: true, thisDevice: side(), otherDevice: side(), working: true, detailsLoaded: true, onCancel, onKeep: vi.fn() })
  await Promise.resolve()
  await fireEvent.keyDown(window, { key: 'Escape' })
  expect(onCancel).not.toHaveBeenCalled()
  await view.rerender({ open: true, thisDevice: side(), otherDevice: side(), working: false, detailsLoaded: true, onCancel, onKeep: vi.fn() })
  await fireEvent.keyDown(window, { key: 'Escape' })
  expect(onCancel).toHaveBeenCalledOnce()
})
