import type { SoftwareLicense, SoftwareLicenseInput } from '../types'
import { deleteSoftwareLicense, getSoftwareLicense, saveSoftwareLicense } from '../vault'
import { createRecordController, type RecordControllerOptions } from './record-controller'

function emptyLicenseDraft(): SoftwareLicenseInput {
  return { title: '', licenseKey: '', productName: '', purchasedFrom: '', purchaseDate: '', notes: '', tags: [] }
}

function draftFrom(license: SoftwareLicense): SoftwareLicenseInput {
  const { id, title, licenseKey, productName, purchasedFrom, purchaseDate, notes, tags } = license
  return { id, title, licenseKey, productName, purchasedFrom, purchaseDate, notes, tags: tags ?? [] }
}

export function createSoftwareLicenseController(options: RecordControllerOptions) {
  return createRecordController<SoftwareLicense, SoftwareLicenseInput>(options, {
    editorModal: { kind: 'software-license-editor' },
    deleteModalKind: 'delete-software-license',
    deleteModal: (id) => ({ kind: 'delete-software-license', licenseId: id }),
    emptyDraft: emptyLicenseDraft,
    draftFrom,
    draftTitle: (draft) => draft.title.trim(),
    api: { get: getSoftwareLicense, save: saveSoftwareLicense, delete: deleteSoftwareLicense },
    copy: {
      addTitle: 'Add a licence',
      editTitle: 'Edit licence',
      savedNotice: (isNew, title) => ({ title: isNew ? 'Licence saved' : 'Licence updated', body: `${title} is stored in your vault.` }),
      deletedNotice: (title) => ({ title: 'Licence deleted', body: `${title} was removed from your vault.` }),
    },
  })
}

export type SoftwareLicenseController = ReturnType<typeof createSoftwareLicenseController>
