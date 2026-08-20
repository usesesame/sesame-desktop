import type { Attachment, Card, CustomRecord, DocumentMetadata, Identity, ItemKind, LegacyField, SecureNote, SoftwareLicense, SshKey, WifiNetwork } from './types'

export type RecordKind = Exclude<ItemKind, 'login'>

export type ItemRecord = Identity | SecureNote | Card | WifiNetwork | SshKey | SoftwareLicense | DocumentMetadata | CustomRecord

export interface ItemField {
  label: string
  value: string
  /** Concealed until revealed, and revealing it starts the hide timer. */
  secret: boolean
  multiline: boolean
  icon: string
}

export interface ItemDetail {
  title: string
  subtitle: string
  fields: ItemField[]
  notes: string
  tags: string[]
  attachments: Attachment[]
  legacyFields: LegacyField[]
  favourite: boolean
  folderId?: string
}

function field(label: string, value: string, icon: string, options: { secret?: boolean; multiline?: boolean } = {}): ItemField | null {
  if (!value?.trim()) return null
  return { label, value, icon, secret: options.secret ?? false, multiline: options.multiline ?? false }
}

function present(fields: (ItemField | null)[]): ItemField[] {
  return fields.filter((entry): entry is ItemField => entry !== null)
}

function identityFields(identity: Identity): ItemField[] {
  return present([
    field('Full name', identity.fullName, 'user'),
    field('Email', identity.email, 'mail'),
    field('Phone', identity.phone, 'phone'),
    field('Address', identity.addressLine1, 'id-card'),
    field('Address line 2', identity.addressLine2, 'id-card'),
    field('City', identity.city, 'id-card'),
    field('Region', identity.region, 'id-card'),
    field('Postal code', identity.postalCode, 'id-card'),
    field('Country', identity.country, 'id-card'),
  ])
}

function cardFields(card: Card): ItemField[] {
  const expiry = [card.expiryMonth, card.expiryYear].filter(Boolean).join('/')
  return present([
    field('Cardholder', card.cardholderName, 'user'),
    field('Card number', card.number, 'card', { secret: true }),
    field('Expiry', expiry, 'card'),
    field('Security code', card.securityCode, 'key', { secret: true }),
    field('Brand', card.brand, 'card'),
  ])
}

function customFields(record: CustomRecord): ItemField[] {
  return present(record.fields.map((entry) => field(entry.label, entry.value, entry.kind === 'secret' ? 'key' : 'custom', { secret: entry.kind === 'secret' })))
}

export function itemDetail(kind: RecordKind, record: ItemRecord): ItemDetail {
  const shared = { attachments: [] as Attachment[], legacyFields: [] as LegacyField[] }
  switch (kind) {
    case 'identity': {
      const identity = record as Identity
      return { ...shared, title: identity.label, subtitle: identity.fullName || identity.email, fields: identityFields(identity), notes: '', tags: identity.tags ?? [], legacyFields: identity.legacyFields ?? [], favourite: identity.favourite, folderId: identity.folderId }
    }
    case 'secure_note': {
      const note = record as SecureNote
      return { ...shared, title: note.title, subtitle: '', fields: present([field('Content', note.content, 'note', { multiline: true })]), notes: '', tags: note.tags ?? [], legacyFields: note.legacyFields ?? [], favourite: note.favourite, folderId: note.folderId }
    }
    case 'card': {
      const card = record as Card
      return { ...shared, title: card.title, subtitle: card.brand, fields: cardFields(card), notes: card.notes, tags: card.tags ?? [], legacyFields: card.legacyFields ?? [], favourite: card.favourite, folderId: card.folderId }
    }
    case 'wifi_network': {
      const network = record as WifiNetwork
      return {
        ...shared,
        title: network.title,
        subtitle: network.ssid,
        fields: present([
          field('Network name', network.ssid, 'wifi'),
          field('Password', network.password, 'key', { secret: true }),
          field('Security', network.securityType, 'shield'),
        ]),
        notes: network.notes,
        tags: network.tags ?? [],
        favourite: network.favourite,
        folderId: network.folderId,
      }
    }
    case 'ssh_key': {
      const key = record as SshKey
      return {
        ...shared,
        title: key.title,
        subtitle: key.keyType,
        fields: present([
          field('Key type', key.keyType, 'key'),
          field('Public key', key.publicKey, 'file-key', { multiline: true }),
          field('Private key', key.privateKey, 'file-key', { secret: true, multiline: true }),
          field('Passphrase', key.passphrase, 'key', { secret: true }),
        ]),
        notes: key.notes,
        tags: key.tags ?? [],
        favourite: key.favourite,
        folderId: key.folderId,
      }
    }
    case 'software_license': {
      const license = record as SoftwareLicense
      return {
        ...shared,
        title: license.title,
        subtitle: license.productName,
        fields: present([
          field('Product', license.productName, 'license'),
          field('Licence key', license.licenseKey, 'key', { secret: true }),
          field('Purchased from', license.purchasedFrom, 'globe'),
          field('Purchase date', license.purchaseDate, 'archive'),
        ]),
        notes: license.notes,
        tags: license.tags ?? [],
        favourite: license.favourite,
        folderId: license.folderId,
      }
    }
    case 'document': {
      const document = record as DocumentMetadata
      return {
        ...shared,
        title: document.title,
        subtitle: document.documentType,
        fields: present([
          field('Type', document.documentType, 'id-card'),
          field('Number', document.documentNumber, 'id-card', { secret: true }),
          field('Issuing authority', document.issuingAuthority, 'shield'),
          field('Issued', document.issueDate, 'archive'),
          field('Expires', document.expiryDate, 'archive'),
        ]),
        notes: document.notes,
        tags: document.tags ?? [],
        attachments: document.attachments ?? [],
        favourite: document.favourite,
        folderId: document.folderId,
      }
    }
    case 'custom_record': {
      const custom = record as CustomRecord
      return { ...shared, title: custom.title, subtitle: '', fields: customFields(custom), notes: custom.notes, tags: custom.tags ?? [], favourite: custom.favourite, folderId: custom.folderId }
    }
  }
}
