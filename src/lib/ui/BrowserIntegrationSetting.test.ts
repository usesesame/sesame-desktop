/* @vitest-environment jsdom */
import { cleanup, render, screen } from '@testing-library/svelte'
import { afterEach, expect, test, vi } from 'vitest'
import type { BrowserIntegrationStatus } from '../types'
import BrowserIntegrationSetting from './BrowserIntegrationSetting.svelte'

afterEach(cleanup)

const ready: BrowserIntegrationStatus = {
  supported: true,
  hostAvailable: true,
  manifestReady: true,
  chromeRegistered: true,
  edgeRegistered: true,
  firefoxRegistered: true,
  ready: true,
  servedElsewhere: false,
  code: 'ready',
}

const props = { desktopAvailable: true, working: false, onRefresh: vi.fn(), onRepair: vi.fn() }

test('a working connection says that no repair is needed', () => {
  render(BrowserIntegrationSetting, { ...props, status: ready })
  expect(screen.getByText('No repair needed')).toBeTruthy()
  expect(screen.queryByText(/another Sesame/i)).toBeNull()
})

test('a connection that another Sesame already holds says so and does not offer a repair', () => {
  render(BrowserIntegrationSetting, { ...props, status: { ...ready, servedElsewhere: true } })
  expect(screen.getByText('Used by another Sesame')).toBeTruthy()
  expect(screen.getByText(/Another Sesame on this computer already serves the browser extension/)).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Repair connection' })).toBeNull()
})

test('a broken registration is still reported as needing repair when no other Sesame holds it', () => {
  render(BrowserIntegrationSetting, { ...props, status: { ...ready, ready: false, chromeRegistered: false, code: 'registrationMissing' } })
  expect(screen.getByText('Needs repair')).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Repair connection' })).toBeTruthy()
})
