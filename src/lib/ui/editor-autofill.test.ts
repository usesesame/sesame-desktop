/* @vitest-environment jsdom */
import { cleanup, render } from '@testing-library/svelte'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { APP_STORES, createAppStores } from '../stores/app-stores'
import type { CardInput, IdentityInput, LoginInput } from '../types'
import CardEditor from './CardEditor.svelte'
import IdentityEditor from './IdentityEditor.svelte'
import LoginEditor from './LoginEditor.svelte'

vi.mock('../vault', () => ({
  previewMode: false,
  PRESENCE_REQUIRED: 'presenceRequired',
  grantPresence: vi.fn(),
  revealLoginSecret: vi.fn(),
  suggestFieldValues: vi.fn(),
}))

beforeEach(() => {
  if (!document.getElementById('app')) {
    const root = document.createElement('div')
    root.id = 'app'
    document.body.appendChild(root)
  }
})

afterEach(() => {
  cleanup()
  document.body.replaceChildren()
})

const cardDraft: CardInput = {
  id: 'card-a',
  title: 'Fictional card',
  cardholderName: 'Alex Example',
  number: '4242424242424242',
  expiryMonth: '09',
  expiryYear: '2099',
  securityCode: '123',
  brand: 'Visa',
  notes: '',
  tags: [],
}

const identityDraft: IdentityInput = {
  id: 'identity-a',
  label: 'Fictional identity',
  fullName: 'Alex Example',
  email: 'alex@example.test',
  phone: '+1 555 0100',
  addressLine1: '1 Example Street',
  addressLine2: '',
  city: 'Exampleton',
  region: 'EX',
  postalCode: '00000',
  country: 'Exampleland',
  tags: [],
}

const loginDraft: LoginInput = {
  id: 'login-a',
  title: 'Northwind',
  url: 'https://northwind.example.test',
  urls: [],
  tags: [],
  username: 'alpha@example.test',
  email: 'alpha@example.test',
  password: '',
  folder: '',
  totp: undefined,
  backupCodes: [],
  recoveryEmail: 'recovery@example.test',
  recoveryPhone: '+1 555 0101',
  recoveryNotApplicable: false,
  notes: '',
}

function renderWithStores(component: never, props: Record<string, unknown>) {
  return render(component, { props, context: new Map([[APP_STORES, createAppStores()]]) } as never)
}

function textEntryFields() {
  return [...document.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>('input, textarea')]
    .filter((field) => !(field instanceof HTMLInputElement) || !['checkbox', 'radio', 'hidden', 'button', 'submit'].includes(field.type))
}

function expectNoAutofill(expectedNames: string[]) {
  const fields = textEntryFields()
  expect(fields.map((field) => field.name)).toEqual(expect.arrayContaining(expectedNames))
  for (const field of fields) {
    expect(field.getAttribute('autocomplete'), field.name).toBe('off')
  }
}

test('the card editor asks the browser not to autofill or remember any field', () => {
  renderWithStores(CardEditor as never, { cardDraft, onSubmit: vi.fn(), onClose: vi.fn() })
  expectNoAutofill(['card-cardholder', 'card-number', 'card-expiry-month', 'card-expiry-year', 'card-security-code', 'card-network', 'card-notes'])
})

test('the identity editor asks the browser not to autofill or remember any field', () => {
  renderWithStores(IdentityEditor as never, { identityDraft, onSubmit: vi.fn(), onClose: vi.fn() })
  expectNoAutofill(['identity-full-name', 'identity-email', 'identity-phone', 'identity-address-line1', 'identity-address-line2', 'identity-city', 'identity-region', 'identity-postal-code', 'identity-country'])
})

test('the login editor asks the browser not to autofill or remember any field', () => {
  renderWithStores(LoginEditor as never, { loginDraft, onSubmit: vi.fn(), onClose: vi.fn(), onDelete: vi.fn() })
  expectNoAutofill(['login-url', 'login-urls', 'login-username', 'login-email', 'login-password', 'login-recovery-email', 'login-recovery-phone', 'login-notes'])
})
