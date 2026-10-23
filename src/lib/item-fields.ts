import type { Attachment, Card, CustomRecord, DocumentMetadata, Identity, ItemKind, LegacyField, SecretView, SecureNote, SoftwareLicense, SshKey, WifiNetwork } from './types'

export type RecordKind = Exclude<ItemKind, 'login'>

export type ItemRecord = Identity | SecureNote | Card | WifiNetwork | SshKey | SoftwareLicense | DocumentMetadata | CustomRecord

export type ItemRecordView = SecretView<ItemRecord>

export interface ItemField {
  label: string
  value: string
  secret: boolean
  secretKey?: string
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
  locked: boolean
}

function field(label: string, value: string, icon: string, options: { secret?: boolean; multiline?: boolean } = {}): ItemField | null {
  if (!value?.trim()) return null
  return { label, value, icon, secret: options.secret ?? false, multiline: options.multiline ?? false }
}

function secretField(label: string, key: string, icon: string, present: string[], options: { multiline?: boolean } = {}): ItemField | null {
  if (!present.includes(key)) return null
  return { label, value: '', secret: true, secretKey: key, multiline: options.multiline ?? false, icon }
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

function cardFields(card: SecretView<Card>): ItemField[] {
  const expiry = [card.expiryMonth, card.expiryYear].filter(Boolean).join('/')
  return present([
    field('Cardholder', card.cardholderName, 'user'),
    secretField('Card number', 'number', 'card', card.secretFields),
    field('Expiry', expiry, 'card'),
    secretField('Security code', 'securityCode', 'key', card.secretFields),
    field('Brand', card.brand, 'card'),
  ])
}

function customFields(record: SecretView<CustomRecord>): ItemField[] {
  return present(record.fields.map((entry, index) => entry.kind === 'secret'
    ? secretField(entry.label, `field:${index}`, 'key', record.secretFields)
    : field(entry.label, entry.value, 'custom')))
}

export function itemDetail(kind: RecordKind, record: ItemRecordView): ItemDetail {
  const shared = { attachments: [] as Attachment[], legacyFields: [] as LegacyField[], locked: false }
  switch (kind) {
    case 'identity': {
      const identity = record as SecretView<Identity>
      return { ...shared, title: identity.label, subtitle: identity.fullName || identity.email, fields: identityFields(identity), notes: '', tags: identity.tags ?? [], legacyFields: identity.legacyFields ?? [], favourite: identity.favourite, folderId: identity.folderId }
    }
    case 'secure_note': {
      const note = record as SecretView<SecureNote>
      const locked = note.secretFields.includes('content') || Boolean(note.locked)
      const content = locked ? secretField('Content', 'content', 'note', note.secretFields, { multiline: true }) : field('Content', note.content, 'note', { multiline: true })
      return { ...shared, locked, title: note.title, subtitle: '', fields: present([content]), notes: '', tags: note.tags ?? [], legacyFields: note.legacyFields ?? [], favourite: note.favourite, folderId: note.folderId }
    }
    case 'card': {
      const card = record as SecretView<Card>
      return { ...shared, title: card.title, subtitle: card.brand, fields: cardFields(card), notes: card.notes, tags: card.tags ?? [], legacyFields: card.legacyFields ?? [], favourite: card.favourite, folderId: card.folderId }
    }
    case 'wifi_network': {
      const network = record as SecretView<WifiNetwork>
      return {
        ...shared,
        title: network.title,
        subtitle: network.ssid,
        fields: present([
          field('Network name', network.ssid, 'wifi'),
          secretField('Password', 'password', 'key', network.secretFields),
          field('Security', network.securityType, 'shield'),
        ]),
        notes: network.notes,
        tags: network.tags ?? [],
        favourite: network.favourite,
        folderId: network.folderId,
      }
    }
    case 'ssh_key': {
      const key = record as SecretView<SshKey>
      return {
        ...shared,
        title: key.title,
        subtitle: key.keyType,
        fields: present([
          field('Key type', key.keyType, 'key'),
          field('Public key', key.publicKey, 'file-key', { multiline: true }),
          secretField('Private key', 'privateKey', 'file-key', key.secretFields, { multiline: true }),
          secretField('Passphrase', 'passphrase', 'key', key.secretFields),
        ]),
        notes: key.notes,
        tags: key.tags ?? [],
        favourite: key.favourite,
        folderId: key.folderId,
      }
    }
    case 'software_license': {
      const license = record as SecretView<SoftwareLicense>
      return {
        ...shared,
        title: license.title,
        subtitle: license.productName,
        fields: present([
          field('Product', license.productName, 'license'),
          secretField('Licence key', 'licenseKey', 'key', license.secretFields),
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
      const document = record as SecretView<DocumentMetadata>
      return {
        ...shared,
        title: document.title,
        subtitle: document.documentType,
        fields: present([
          field('Type', document.documentType, 'id-card'),
          secretField('Number', 'documentNumber', 'id-card', document.secretFields),
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
      const custom = record as SecretView<CustomRecord>
      return { ...shared, title: custom.title, subtitle: '', fields: customFields(custom), notes: custom.notes, tags: custom.tags ?? [], favourite: custom.favourite, folderId: custom.folderId }
    }
  }
}
