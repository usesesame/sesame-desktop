import { get } from 'svelte/store'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { AppStores } from '../stores/app-stores'
import { createCardController } from './card-controller'
import { createCustomRecordController } from './custom-record-controller'
import { createFeedbackController } from './feedback-controller'
import { createModalController } from './modal-controller'
import { createSshKeyController } from './ssh-key-controller'

const vaultApi = vi.hoisted(() => ({
  deleteCard: vi.fn(),
  getCard: vi.fn(),
  saveCard: vi.fn(),
  deleteCustomRecord: vi.fn(),
  getCustomRecord: vi.fn(),
  saveCustomRecord: vi.fn(),
  deleteSshKey: vi.fn(),
  getSshKey: vi.fn(),
  saveSshKey: vi.fn(),
  recordDiagnostic: vi.fn(),
}))

vi.mock('../vault', () => ({ ...vaultApi }))

function stores(): AppStores {
  const noRequest = { subscribe: () => () => {}, set: () => {}, patch: () => {}, value: () => ({ request: null }) }
  let vaultState = { status: {}, snapshot: null, loginCard: null }
  return {
    vault: {
      subscribe: () => () => {},
      set: (next: typeof vaultState) => { vaultState = next },
      patch: (values: Partial<typeof vaultState>) => { vaultState = { ...vaultState, ...values } },
      value: () => vaultState,
    },
    browserFill: noRequest,
    browserIdentityFill: noRequest,
    browserCardFill: noRequest,
    browserTotpFill: noRequest,
    browserSave: noRequest,
  } as unknown as AppStores
}

function options() {
  const appStores = stores()
  const feedback = createFeedbackController()
  return { stores: appStores, feedback, modal: createModalController({ stores: appStores, feedback }) }
}

const saved = { id: 'fictional-id', snapshot: {} }

beforeEach(() => {
  vi.clearAllMocks()
  vaultApi.saveCard.mockResolvedValue(saved)
  vaultApi.saveSshKey.mockResolvedValue(saved)
  vaultApi.saveCustomRecord.mockResolvedValue(saved)
})

describe('editing a record never loads its saved secrets', () => {
  it('opens a card with blank secrets and lists the ones that are kept', async () => {
    vaultApi.getCard.mockResolvedValue({
      id: 'card-a', title: 'Fictional card', cardholderName: '', number: '', expiryMonth: '04', expiryYear: '2031', securityCode: '', brand: 'Visa', notes: '', tags: [], secretFields: ['number', 'securityCode'],
    })
    const controller = createCardController(options())

    await controller.openEditor('card-a')

    expect(get(controller.state).draft).toMatchObject({ number: '', securityCode: '', brand: 'Visa', keptSecrets: ['number', 'securityCode'] })
  })

  it('saves the kept keys so the host retains the secrets', async () => {
    vaultApi.getCard.mockResolvedValue({
      id: 'card-a', title: 'Fictional card', cardholderName: '', number: '', expiryMonth: '', expiryYear: '', securityCode: '', brand: '', notes: '', tags: [], secretFields: ['number'],
    })
    const controller = createCardController(options())
    await controller.openEditor('card-a')

    await controller.save()

    expect(vaultApi.saveCard).toHaveBeenCalledWith(expect.objectContaining({ id: 'card-a', number: '', keptSecrets: ['number'] }))
  })

  it('starts a new card with nothing kept', () => {
    const controller = createCardController(options())
    controller.openNew()

    expect(get(controller.state).draft.keptSecrets).toEqual([])
  })

  it('keeps an ssh private key and passphrase by name and ignores legacy keys', async () => {
    vaultApi.getSshKey.mockResolvedValue({
      id: 'key-a', title: 'Fictional key', keyType: 'ed25519', privateKey: '', publicKey: 'ssh-ed25519 FICTIONAL', passphrase: '', notes: '', tags: [], secretFields: ['privateKey', 'passphrase', 'legacy:0'],
    })
    const controller = createSshKeyController(options())

    await controller.openEditor('key-a')

    expect(get(controller.state).draft).toMatchObject({ privateKey: '', passphrase: '', publicKey: 'ssh-ed25519 FICTIONAL', keptSecrets: ['privateKey', 'passphrase'] })
  })

  it('marks each saved custom secret row with the position it came from', async () => {
    vaultApi.getCustomRecord.mockResolvedValue({
      id: 'record-a', title: 'Fictional record', notes: '', tags: [],
      fields: [
        { label: 'Visible', value: 'fictional visible', kind: 'text' },
        { label: 'Hidden', value: '', kind: 'secret' },
      ],
      secretFields: ['field:1'],
    })
    const controller = createCustomRecordController(options())

    await controller.openEditor('record-a')

    expect(get(controller.state).draft.fields).toEqual([
      { label: 'Visible', value: 'fictional visible', kind: 'text' },
      { label: 'Hidden', value: '', kind: 'secret', keptFrom: 1 },
    ])
  })

  it('follows a kept custom secret to its new row and strips the marker before saving', async () => {
    vaultApi.getCustomRecord.mockResolvedValue({
      id: 'record-a', title: 'Fictional record', notes: '', tags: [],
      fields: [
        { label: 'Hidden', value: '', kind: 'secret' },
        { label: 'Visible', value: 'fictional visible', kind: 'text' },
      ],
      secretFields: ['field:0'],
    })
    const controller = createCustomRecordController(options())
    await controller.openEditor('record-a')
    const draft = get(controller.state).draft
    controller.setDraft({ ...draft, fields: [draft.fields[1], draft.fields[0]] })

    await controller.save()

    const sent = vaultApi.saveCustomRecord.mock.calls[0][0]
    expect(sent.keptSecrets).toEqual(['field:1<-0'])
    expect(sent.fields).toEqual([
      { label: 'Visible', value: 'fictional visible', kind: 'text' },
      { label: 'Hidden', value: '', kind: 'secret' },
    ])
  })

  it('does not keep a custom secret that was removed or typed over', async () => {
    vaultApi.getCustomRecord.mockResolvedValue({
      id: 'record-a', title: 'Fictional record', notes: '', tags: [],
      fields: [
        { label: 'Hidden', value: '', kind: 'secret' },
        { label: 'Other', value: '', kind: 'secret' },
      ],
      secretFields: ['field:0', 'field:1'],
    })
    const controller = createCustomRecordController(options())
    await controller.openEditor('record-a')
    const draft = get(controller.state).draft
    controller.setDraft({
      ...draft,
      fields: [
        { label: 'Hidden', value: 'fictional-new-secret', kind: 'secret', keptFrom: 0 } as never,
        { label: 'Other', value: '', kind: 'secret' },
      ],
    })

    await controller.save()

    expect(vaultApi.saveCustomRecord.mock.calls[0][0].keptSecrets).toEqual([])
  })
})
