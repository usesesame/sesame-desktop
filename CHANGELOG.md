# Changelog

Every released version has a section here. The release workflow reads the
section matching the tag and puts it at the top of the GitHub release, so a
release cannot be published without saying what changed in it.

## 0.1.2

- The vault is one list. Logins, cards, notes, identities, Wi-Fi networks, SSH
  keys, licences, documents, and custom records now share a single screen with
  one search, category filters, collections, tags, favourites, and recently
  used items. The separate Items screen and its tab strip are gone; Trash and
  History moved to the sidebar.
- Search covers every kind of saved item, not only logins. Press / or Ctrl+K
  anywhere in Sesame to open it.
- Quick access finds every kind of item and offers only the actions that suit
  it: a password, username, or 2FA code for a login; the number, expiry, or
  security code for a card; the password for a Wi-Fi network; a licence key; a
  chosen identity field; and an SSH public key, with the private key needing a
  second, deliberate confirmation. A note, document, or custom record opens in
  Sesame rather than showing its contents in the search window.
- Favourites, collections, and recently used now work for every kind of item,
  not just logins.
- Importing no longer changes your passwords. Every CSV import trimmed spaces
  off each field, so a password saved with a leading or trailing space arrived
  in your vault without it and no longer opened the account. If you imported
  before this release, check any sign-in that stopped working.
- The site shown beside an entry is now the site. An address saved with a
  user:password@ prefix used to print that password into the list, a query
  string showed whatever token it carried, and an address saved in capitals
  appeared as a separate site from the same one saved in lower case.
- Checking for updates says so when you are already up to date, instead of
  looking like a button that does nothing.
- A new unlock PIN cannot be one repeated digit or six digits in a row. A PIN
  you already use keeps working, so nothing you have set will stop unlocking.
- A backup file is now checked more completely before Sesame acts on it. PIN
  unlock material inside it is validated like every other wrapped key, so a
  damaged backup is refused when you open it rather than failing later with a
  message about Windows.
- Filling in the browser finds the username box on far more sites. It reads
  the placeholder, the accessible label, and the field's own label, instead of
  only its name, and it no longer offers a credential to a search box or a
  one-time-code field. Sign-up forms that hide a decoy field to catch bots are
  left alone.

## 0.1.1

- Sesame can now check for and install its own updates. The 0.1.0 installer
  was built without an update endpoint compiled into it, so it could never
  find a newer version. If you are on 0.1.0, install 0.1.1 by hand once and
  updates will work from then on.
- The sidebar, the unlock screen, and the first-run notice no longer describe
  a private beta. The channel is now read from the version the build carries.

## 0.1.0

- First public Windows build. Local encrypted vault, 9 record types, 15
  import formats, TOTP codes, Windows Hello and PIN unlock, backup, restore,
  and export.
