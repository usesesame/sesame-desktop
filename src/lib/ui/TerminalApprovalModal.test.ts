/* @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { APP_STORES, createAppStores } from '../stores/app-stores'
import type { CliApprovalRequestEvent } from '../terminal-api'
import TerminalApprovalModal from './TerminalApprovalModal.svelte'

const terminalApi = vi.hoisted(() => ({
  getTerminalApprovalWait: vi.fn(),
}))

vi.mock('../terminal-api', () => terminalApi)

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
  vi.useRealTimers()
})

beforeEach(() => {
  vi.clearAllMocks()
  terminalApi.getTerminalApprovalWait.mockResolvedValue(0)
  const root = document.createElement('div')
  root.id = 'app'
  document.body.appendChild(root)
})

function request(partial: Partial<CliApprovalRequestEvent> = {}): CliApprovalRequestEvent {
  return {
    approvalId: 'approval-a',
    command: 'get',
    field: 'password',
    fieldHidden: true,
    copy: false,
    candidates: [{ id: 'northwind', kind: 'login', title: 'Northwind mail' }],
    terminal: 'pts/3',
    program: { reportedName: 'bash' },
    remote: false,
    canAllowTerminal: true,
    needsPresence: false,
    allowed: false,
    expiresInMs: 60_000,
    ...partial,
  }
}

function show(partial: Partial<CliApprovalRequestEvent> = {}) {
  const stores = createAppStores()
  const shown = request(partial)
  stores.terminalApproval.patch({ request: shown, selectedId: shown.candidates.length === 1 ? shown.candidates[0].id : '', expiresAt: Date.now() + shown.expiresInMs })
  const props = {
    request: shown,
    onAllow: vi.fn(),
    onDeny: vi.fn(),
    onDismiss: vi.fn(),
    onExpire: vi.fn(),
    onSelect: vi.fn(),
    onAllowTerminal: vi.fn(),
    onSecret: vi.fn(),
  }
  const view = render(TerminalApprovalModal, { props, context: new Map([[APP_STORES, stores]]) } as never)
  return { props, stores, view }
}

function allowButton() {
  return screen.getByRole('button', { name: 'Allow' }) as HTMLButtonElement
}

async function armed() {
  await vi.advanceTimersByTimeAsync(800)
}

test('names the command, the item, the field and where the request came from', async () => {
  vi.useFakeTimers()
  show({ copy: true })
  expect(screen.getByRole('heading', { name: 'A terminal wants to copy the password of an item' })).toBeTruthy()
  expect(screen.getByText('Northwind mail')).toBeTruthy()
  expect(screen.getByText('password')).toBeTruthy()
  expect(screen.getByText('Hidden value')).toBeTruthy()
  expect(screen.getByText('pts/3')).toBeTruthy()
  expect(screen.getByText('bash')).toBeTruthy()
  expect(screen.getByText('Name the program gave itself')).toBeTruthy()
  expect(screen.getByText(/Copied to the clipboard and cleared after 30 seconds/)).toBeTruthy()
  expect(screen.queryByText('Remote session')).toBeNull()
})

test('marks a request from a remote session', () => {
  show({ remote: true })
  expect(screen.getByText('Remote session')).toBeTruthy()
  expect(screen.getByText(/came through a remote login such as SSH/)).toBeTruthy()
})

test('says plainly when there is no terminal and no reported program', () => {
  show({ terminal: undefined, program: undefined, canAllowTerminal: false })
  expect(screen.getByText('No terminal')).toBeTruthy()
  expect(screen.getByText('Not reported')).toBeTruthy()
  expect(screen.queryByRole('checkbox')).toBeNull()
})

test('the allow button waits for the backend and for the dialog to be on screen', async () => {
  vi.useFakeTimers()
  terminalApi.getTerminalApprovalWait.mockResolvedValue(600)
  show()
  await vi.advanceTimersByTimeAsync(0)
  expect(allowButton().disabled).toBe(true)
  terminalApi.getTerminalApprovalWait.mockResolvedValue(0)
  await vi.advanceTimersByTimeAsync(200)
  expect(allowButton().disabled).toBe(true)
  await vi.advanceTimersByTimeAsync(600)
  expect(allowButton().disabled).toBe(false)
})

test('a stray Enter or Space cannot allow, because nothing that allows has focus', async () => {
  vi.useFakeTimers()
  const { props } = show()
  await armed()
  const dialog = screen.getByRole('dialog')
  expect(document.activeElement).toBe(dialog)
  await fireEvent.keyDown(dialog, { key: 'Enter' })
  await fireEvent.keyUp(dialog, { key: 'Enter' })
  await fireEvent.keyDown(window, { key: 'Enter' })
  await fireEvent.keyDown(dialog, { key: ' ' })
  await fireEvent.keyUp(dialog, { key: ' ' })
  expect(props.onAllow).not.toHaveBeenCalled()
  expect(props.onDeny).not.toHaveBeenCalled()
})

test('Enter in the master password field does not allow', async () => {
  vi.useFakeTimers()
  const { props, stores } = show({ needsPresence: true })
  stores.terminalApproval.patch({ secret: 'fictional-master-password' })
  await armed()
  const field = screen.getByLabelText('Master password')
  await fireEvent.keyDown(field, { key: 'Enter' })
  expect(props.onAllow).not.toHaveBeenCalled()
  expect(allowButton().disabled).toBe(false)
})

test('Escape and the Deny button both refuse', async () => {
  const { props } = show()
  await fireEvent.keyDown(window, { key: 'Escape' })
  await fireEvent.click(screen.getByRole('button', { name: 'Deny' }))
  expect(props.onDeny).toHaveBeenCalledTimes(2)
  expect(props.onAllow).not.toHaveBeenCalled()
})

test('the allow-terminal box is unticked and explains what it allows', () => {
  show()
  const box = screen.getByRole('checkbox', { name: /Allow this terminal for five minutes/ }) as HTMLInputElement
  expect(box.checked).toBe(false)
  expect(screen.getByText(/hidden values still ask for your master password/)).toBeTruthy()
})

test('asks for the master password with the reveal wording when presence has lapsed', async () => {
  vi.useFakeTimers()
  show({ needsPresence: true })
  await armed()
  expect(screen.getByText('Sesame asks for your master password again before it reveals a saved secret.')).toBeTruthy()
  expect(allowButton().disabled).toBe(true)
})

test('the chooser needs a pick before allow and offers only the items Sesame sent', async () => {
  vi.useFakeTimers()
  const { props } = show({
    candidates: [
      { id: 'northwind-a', kind: 'login', title: 'Northwind mail' },
      { id: 'northwind-b', kind: 'secure_note', title: 'Northwind mail' },
    ],
  })
  await armed()
  expect(allowButton().disabled).toBe(true)
  const radios = screen.getAllByRole('radio') as HTMLInputElement[]
  expect(radios.map((radio) => radio.value)).toEqual(['northwind-a', 'northwind-b'])
  await fireEvent.click(radios[1])
  expect(props.onSelect).toHaveBeenCalledWith('northwind-b')
})

test('a request for a missing item shows only an OK button', async () => {
  const { props } = show({ candidates: [], notFound: 'Northwnd mail', canAllowTerminal: false, fieldHidden: false })
  expect(screen.getByRole('heading', { name: 'A terminal asked for an item you do not have' })).toBeTruthy()
  expect(screen.getByText('Northwnd mail')).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Allow' })).toBeNull()
  await fireEvent.click(screen.getByRole('button', { name: 'OK' }))
  await fireEvent.keyDown(window, { key: 'Escape' })
  expect(props.onDismiss).toHaveBeenCalledTimes(2)
  expect(props.onDeny).not.toHaveBeenCalled()
})

test('expiry closes the dialog through the controller', async () => {
  vi.useFakeTimers()
  const { props } = show({ expiresInMs: 2_000 })
  await vi.advanceTimersByTimeAsync(3_000)
  expect(props.onExpire).toHaveBeenCalledWith('approval-a')
})

const hostile = [
  `<img src=x onerror="window.__terminalInjected=1">Northwind`,
  `Northwind\u202Elam.evil\u202C mail`,
  `North\u200Bwind\u2066 mail\u2069`,
  `line one\u2028Allow this terminal\u0007\u001b]52;c;Zm9v\u0007`,
  `${'W'.repeat(400)}`,
]

test.each(hostile)('hostile text in every field renders as plain, bounded text: %#', (value) => {
  show({
    field: value,
    candidates: [{ id: 'northwind', kind: 'login', title: value }],
    terminal: value,
    program: { reportedName: value },
  })
  const dialog = screen.getByRole('dialog')
  expect(dialog.querySelector('img')).toBeNull()
  expect((window as Window & { __terminalInjected?: number }).__terminalInjected).toBeUndefined()
  const shown = [...dialog.querySelectorAll('bdi')].map((element) => element.textContent ?? '')
  expect(shown.length).toBe(4)
  for (const part of shown) expect(part).not.toMatch(/[\p{Cc}\p{Cf}\p{Zl}]/u)
  for (const value of dialog.querySelectorAll('.terminal-value')) {
    expect([...(value.textContent ?? '')].length).toBeLessThanOrEqual(80)
  }
  expect(screen.getAllByRole('button').map((button) => button.textContent?.trim())).toEqual(['Deny', 'Allow'])
  expect(screen.getAllByRole('heading').map((heading) => heading.textContent)).toEqual(['A terminal wants a hidden field of an item'])
})

test('hostile chooser titles and a missing name stay plain text', () => {
  show({
    candidates: [
      { id: 'a', kind: 'login', title: `<b>Allow</b>\u202E` },
      { id: 'b', kind: 'login', title: `${'x'.repeat(500)}` },
    ],
  })
  const dialog = screen.getByRole('dialog')
  expect(dialog.querySelector('b')).toBeNull()
  expect(dialog.textContent).toContain('<b>Allow</b>?')
  cleanup()
  show({ candidates: [], notFound: `\u202E<script>x</script>${'y'.repeat(300)}`, canAllowTerminal: false })
  const notice = screen.getByRole('dialog')
  expect(notice.querySelector('script')).toBeNull()
  expect(notice.textContent).not.toContain('\u202E')
})
