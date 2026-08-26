import type { WifiNetwork, WifiNetworkInput } from '../types'
import { deleteWifiNetwork, getWifiNetwork, saveWifiNetwork } from '../vault'
import { createRecordController, type RecordControllerOptions } from './record-controller'

function emptyNetworkDraft(): WifiNetworkInput {
  return { title: '', ssid: '', password: '', securityType: '', notes: '', tags: [] }
}

function draftFrom(network: WifiNetwork): WifiNetworkInput {
  const { id, title, ssid, password, securityType, notes, tags } = network
  return { id, title, ssid, password, securityType, notes, tags: tags ?? [] }
}

export function createWifiNetworkController(options: RecordControllerOptions) {
  return createRecordController<WifiNetwork, WifiNetworkInput>(options, {
    editorModal: { kind: 'wifi-network-editor' },
    deleteModalKind: 'delete-wifi-network',
    deleteModal: (id) => ({ kind: 'delete-wifi-network', networkId: id }),
    emptyDraft: emptyNetworkDraft,
    draftFrom,
    draftTitle: (draft) => draft.title.trim(),
    api: { get: getWifiNetwork, save: saveWifiNetwork, delete: deleteWifiNetwork },
    copy: {
      addTitle: 'Add a network',
      editTitle: 'Edit network',
      savedNotice: (isNew, title) => ({ title: isNew ? 'Network saved' : 'Network updated', body: `${title} is stored in your vault.` }),
      deletedNotice: (title) => ({ title: 'Network deleted', body: `${title} was removed from your vault.` }),
    },
  })
}

export type WifiNetworkController = ReturnType<typeof createWifiNetworkController>
