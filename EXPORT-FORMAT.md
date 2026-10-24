# Complete export format

Settings, then Export and deletion, then Complete export writes one JSON file with every item in your vault. The file is not encrypted, so anyone who can
read it can read every password in it. An encrypted backup is the safer way to
move a vault between Sesame installs.

The file starts with `"format": "sesame-export"` and a `"version"`. This page
describes version 1. A later version may add fields, and it never removes or
renames a field within the same version number.

## Top level

| Field | Content |
| --- | --- |
| `format` | The text `sesame-export`. |
| `version` | The format version, `1`. |
| `exportedAt` | When the file was written, in seconds since 1 January 1970 UTC. |
| `vaultName` | The name of the vault. |
| `folders` | Folders. Each has an `id` and a `name`. |
| `logins` | Saved logins. |
| `identities` | Saved identities. |
| `secureNotes` | Secure notes. |
| `cards` | Payment cards. |
| `wifiNetworks` | Wi-Fi networks. |
| `sshKeys` | SSH keys. |
| `softwareLicenses` | Software licences. |
| `documents` | Documents, with their attachments. |
| `customRecords` | Custom records. |
| `trash` | Items deleted from the vault and not yet removed for good. |

Revision history is not exported.

## Items

Every item has an `id`, a `title` or `label`, the times `createdAt` and
`updatedAt` in seconds since 1 January 1970 UTC, a `revision` counter and a
`favourite` flag. Every item has `tags`, a list of text. An
item that is in a folder has a `folderId` that matches a folder in `folders`. A
field that was never set, such as `folderId` or `lastUsedAt`, is left out.

| List | Fields beyond the common ones |
| --- | --- |
| `logins` | `url`, `urls`, `username`, `email`, `password`, `totp`, `backupCodes`, `recoveryEmail`, `recoveryPhone`, `recoveryNotApplicable`, `notes`, `passwordUpdatedAt`, `importSource`, `legacyFields` |
| `identities` | `fullName`, `email`, `phone`, `addressLine1`, `addressLine2`, `city`, `region`, `postalCode`, `country`, `legacyFields` |
| `secureNotes` | `content`, `locked`, `legacyFields` |
| `cards` | `brand`, `cardholderName`, `number`, `expiryMonth`, `expiryYear`, `securityCode`, `notes`, `legacyFields` |
| `wifiNetworks` | `ssid`, `password`, `securityType`, `notes` |
| `sshKeys` | `keyType`, `publicKey`, `privateKey`, `passphrase`, `notes` |
| `softwareLicenses` | `productName`, `licenseKey`, `purchasedFrom`, `purchaseDate`, `notes` |
| `documents` | `documentType`, `documentNumber`, `issuingAuthority`, `issueDate`, `expiryDate`, `notes`, `attachments` |
| `customRecords` | `fields`, `notes` |

`totp` holds the authenticator secret or `otpauth` address exactly as it was
saved. `legacyFields` is a list of `{ "label", "value", "secret" }` that older
versions of Sesame wrote. `importSource` names the program a login was imported
from and is present only for an imported login. `locked` is present, and true,
only for a secure note that was locked with the master password. The export
still holds the text of a locked note. `fields` in a custom record is a list of
`{ "label", "value", "kind" }`, and a `kind` of `secret` marks a value that Sesame
hides on screen.

## Attachments

An attachment has an `id`, a `filename`, a `contentType`, a `size` and `data`.
`size` is the length of the file in bytes, and `data` holds the file as URL-safe
base64 without padding.

## Trash

Each entry in `trash` is `{ "deletedAt", "item" }`. `deletedAt` is in seconds
since 1 January 1970 UTC. `item` has the fields of the item it was, plus a `kind`
that names its list: `login`, `identity`, `secure_note`, `card`, `wifi_network`,
`ssh_key`, `software_license`, `document` or `custom_record`.
