/* @vitest-environment jsdom */
import { cleanup, render, screen } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import IssuedRecoveryKitModal from './IssuedRecoveryKitModal.svelte'

afterEach(cleanup)

beforeEach(() => {
  if (!document.getElementById('app')) {
    const root = document.createElement('div')
    root.id = 'app'
    document.body.appendChild(root)
  }
})

const kit = 'FICTI-ONALN-EWKIT-AAAAA-BBBBB'

test('a kept backup folder is called out as still opening with the old kit', async () => {
  render(IssuedRecoveryKitModal, { recoveryKit: kit, backupsPruned: false, onDone: vi.fn() })
  await Promise.resolve()
  expect(screen.getByText(/Backups made before today still open with your old recovery kit\. Delete them or keep them offline\./)).toBeTruthy()
  expect(screen.getByText(/PIN and Windows Hello unlock are off/)).toBeTruthy()
})

test('a pruned backup folder says what was removed and that copies elsewhere still open', async () => {
  render(IssuedRecoveryKitModal, { recoveryKit: kit, backupsPruned: true, backupsRemaining: 0, onDone: vi.fn() })
  await Promise.resolve()
  expect(screen.getByText(/Sesame removed its local backup copies/)).toBeTruthy()
  expect(screen.getByText(/saved elsewhere still open with your old recovery kit/)).toBeTruthy()
})

test('a partly pruned backup folder warns with the number that remain', async () => {
  render(IssuedRecoveryKitModal, { recoveryKit: kit, backupsPruned: true, backupsRemaining: 2, onDone: vi.fn() })
  await Promise.resolve()
  expect(screen.getByRole('alert').textContent).toContain('could not remove 2 local backup copies')
})

test('an unchecked prune result is reported as unknown', async () => {
  render(IssuedRecoveryKitModal, { recoveryKit: kit, backupsPruned: true, backupsRemaining: null, onDone: vi.fn() })
  await Promise.resolve()
  expect(screen.getByRole('alert').textContent).toContain('could not check')
})
