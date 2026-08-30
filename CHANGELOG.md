# Changelog

Every released version has a section here. The release workflow reads the
section matching the tag and puts it at the top of the GitHub release, so a
release cannot be published without saying what changed in it.

## 0.2.0

- Sesame now runs on Linux. The same vault, record types, unlock methods,
  auto-lock, quick access, backups, and browser integration work on Linux, and
  the build produces deb, rpm, and AppImage packages. Device protection keeps
  its key in the Secret Service, auto-lock follows logind and the desktop
  screensaver, and the browser integration answers over a Unix socket that
  checks the connecting process before serving it. Vault files on Unix carry
  owner-only permissions, and the interface hides what a host cannot do
  instead of failing at the moment someone depends on it.
- Writing a copy of your vault now asks for your master password again.
  Exporting, saving a backup, and producing a recovery kit are checked inside
  the Rust host: Sesame verifies the master password there before it writes
  anything, the approval lasts two minutes, and it disappears when you lock,
  restore, or unlock again. Wrong attempts earn growing waits, from five
  seconds up to five minutes. In earlier builds an unlocked session could be
  driven to write a readable copy of the vault to disk without Sesame asking
  again.
- Secrets no longer travel to the interface in bulk. A login card now says
  whether a password or 2FA seed exists and reveals a password only through
  the same master password check as exports, so showing, copying, and
  breach-checking all ask first. The 2FA seed never arrives with the card at
  all: the editor starts empty, saving with an empty field keeps the stored
  seed, and clearing the field removes it. An unlocked session also no longer
  holds every secret at once: each record is sealed into its own authenticated
  blob behind a redacted index, and Sesame opens one record at a time for
  search, previews, suggestions, and browser fill.
- While Sesame is unlocked, the vault key is kept harder to reach. On Windows
  its memory is locked against the page file and re-encrypted whenever the key
  is not in use, vault code can only touch it through a single guarded call,
  and an operation that crashes cannot leave it exposed. On other systems the
  key is wiped after use. The running process refuses attached debuggers and
  keeps crash reports from carrying heap contents.
- A stolen or damaged vault file now meets an attack suite instead of a happy
  path: relabelled formats, forged setup flags, transplanted key wraps, flipped
  and truncated ciphertext, reused nonces, near-miss passwords, oversized
  backups, and key-derivation settings outside the safe limits must all fail to
  open. The suite adds 43 tests across vault files, the PIN lockout, and
  browser fill, and it caught one real bug: browser fill could offer one
  candidate more than its stated limit.
- Browser fill now handles payment cards alongside logins, under the same
  origin checks and desktop approval. Filling a username also works on far
  more sites: it reads the placeholder, the accessible label, and the field's
  own label, instead of only its name, and it no longer offers a credential to
  a search box or a one-time-code field. Sign-up forms that hide a decoy field
  to catch bots are left alone.
- The interface adopts the shared Sesame design language on both platforms:
  selects, menus, and scrollbars are drawn the same way everywhere.
- Shipped builds contain less that can go wrong: the disabled Sync code now
  compiles only into preview builds, and the desktop build no longer links
  twenty-two unused crates or a second HTTP stack.
- Linux builds keep system-wallet retries deterministic and inside their
  deadline.
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
- Restore shows what went wrong instead of failing silently: errors surface on
  the welcome and restore screens, and you can inspect a backup before any
  vault exists.

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
