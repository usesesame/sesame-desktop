# Changelog

Every released version has a section here. The release workflow reads the
section matching the tag and puts it at the top of the GitHub release, so a
release cannot be published without saying what changed in it.

## 0.3.0

### Account

- Sesame account linking is available on Linux. It uses the desktop Secret
  Service wallet to encrypt the account token with the same device key that
  protects the PIN pepper and local attempt-throttle state, and the setting
  stays hidden on systems without a wallet.
- The release pipeline requires the account capability public key. A tagged
  release fails before the build when it is missing or malformed instead of
  shipping a desktop where every link attempt fails.

### Browser integration

- The browser connection works on Linux from the deb and rpm packages. The
  release gate registers the native host in a scratch home, checks the pinned
  extension origin and the sidecar path, verifies the broker socket is
  private, and completes a request with the live desktop. The package gates
  require an executable `sesame-browser-host` and its startup registration.
- The extension suite can run against the real native host and the running
  desktop on Linux.

### Linux packaging

- The AppImage no longer bundles the Wayland client and cursor libraries, so
  its window renders on hosts with a newer Wayland stack instead of staying
  blank white.
- Publishing tolerates the AppImage file name Tauri produces, so a Linux
  asset no longer stops the Windows publish step of the same release.

### Vault and backups

- Export, restore, and open no longer lose data silently. Partial and
  attachment-losing exports name what was left out, SSH-only Bitwarden
  exports are accepted, document history no longer stores attachment bytes,
  duplicate item ids repair on open, staged vault temporary files are
  cleaned up, and the presence grant drops when the vault locks.
- Backup compatibility is shown before a restore starts.

### Security

- The vault writer bounds the plaintext at the storage limit before it
  serializes, and decrypted payload, key-wrapper, and sealed-record buffers
  are wiped when dropped.

### Interface

- Quick access renders the plain initial block when website icons are denied
  instead of an icon that never loads.
- Modal teardown, opening a second modal while one is active, duplicate tags,
  fields, and URLs, async results that returned to the wrong item, and
  needless whole-window repaints are repaired.
- Settings copy names the local platform instead of assuming a Windows
  desktop.

### Diagnostics and release pipeline

- Card-fill and quick-access diagnostic codes are now on the allowlist and
  every allowlisted code carries a severity, so those events are recorded
  instead of dropped or pruned.
- The cross-repository contract suites run in the desktop gate: workflow
  governance, design tokens, installer hooks, the command surface, and the
  lockfile version check.
- The build uses the TypeScript 7 native compiler beside the TypeScript 6
  API that the lint and Svelte tools consume.

## 0.2.5

### Security

- On Linux the unlocked vault key is now held in memory the kernel has locked
  against swap, and Sesame wipes and releases that page when it locks,
  restores, or exits. If the kernel refuses the memory advice that keeps the
  key out of crash dumps and forked children, Sesame wipes the key and falls
  back to wiped-after-use memory instead of keeping it unlocked, and the copy
  made for that fallback is wiped the moment it is created.
- Vault files are safer to open and save. Opening never truncates a file that
  is already there, saving writes a staged file that is validated and swapped
  in by rename, and a link planted into the vault file's path is removed
  rather than written through.
- A save that would push the vault above its 64 MiB storage limit is refused
  with a message that says the saved vault has not changed.
- Replies to the browser extension must fit the message frame the host
  writes, and request buffers are wiped after use, so an oversized reply is
  refused and request bytes do not linger in memory.
- The parsers that read untrusted bytes, the native browser protocol and the
  sync envelope, run under seeded mutation tests: flipped bits, truncated
  payloads, spliced injections, and type-swapped fields must fail validation
  instead of panicking.
- Every Rust dependency is admitted by name:
  src-tauri/dependency-admission.json records each crate in the build and why
  it is needed, and the gate fails the build when an unlisted crate appears.
- rustls is updated to 0.23.45 for RUSTSEC-2026-0285, and the locked build and
  development dependencies are refreshed.

### Interface

- Sesame self-hosts the display, interface, and code fonts, Fraunces,
  Schibsted Grotesk, and Spline Sans Mono, and applies the refreshed tokens
  across the shell, menus, and views. The entry context menu handles every
  item kind, modals open at the app root so a view container cannot trap
  their backdrop, and the copy is shorter while stating the same facts.

### Update and release pipeline

- The update chain binds the updater receipt to the exact installer. The
  manifest carries the download URL at the top level, and publishing refuses
  to continue when the manifest's URL, SHA-256, or byte count differs from
  the verified candidate.
- Publishing a release is resumable. If a publish is interrupted, the next
  run reconciles what is already public against the verified release set and
  uploads only what is missing, and a leftover asset is tolerated only when
  it matches this release's version.
- A release cannot publish until the packaged app opens every supported
  historical backup, restores it, restarts, and backs up again on both
  Windows and Linux. That restore evidence is produced by the release
  workflow and attached to the release.
- Linux packages ship from the same public release pipeline as the Windows
  installer: deb, rpm, and AppImage builds, each installed, launched, and
  uninstalled in the release gate before publication, and both platform
  lanes publish one shared release instead of two.

## 0.2.4

- Updating from 0.1.1 through 0.2.2 to 0.2.3 failed with a receipt mismatch:
  the 0.2.3 update receipt used a format those versions cannot verify. The
  update manifest again carries the receipt format every released client
  verifies, and the updater accepts both formats from this release on. Update
  to 0.2.4 from any earlier release; an install already on 0.2.3 updates
  manually once.

## 0.2.3

- Restoring a backup from an older Sesame release now upgrades it to the current
  format instead of installing it as it was written. Backups written by 0.1.0
  through 0.2.2 are covered, and the selected backup file is never modified.
- Restore makes a safety copy of your current vault and only replaces it at the
  last step. If any step fails, your vault and the backup are left as they were.
- Restore errors now say what went wrong: a wrong master password, a damaged
  file, or a vault that needs a newer Sesame.

## 0.2.2

- The release chain carries Linux end to end. The desktop app reports its real
  operating system when it registers with the account service, Linux clients
  run update discovery and verify update receipts against the running
  platform, and the release pipeline accepts Linux candidates. Linux packages
  carry no updater manifest target and record that automatic updates are
  unavailable. The server serves update checks for the asking platform and
  answers per-platform latest-release lookups, and the admin release controls
  and the website's builds page show both channels.

## 0.2.1

- Revealing a saved password now asks for the master password in a proper
  dialog instead of an unstyled inline row. The login editor can also show the
  saved password it edits, verified the same way as the vault detail view, and
  saving an untouched password field still keeps the stored one.
- Copy and reveal prompts no longer stack notifications: opening the master
  password dialog does not also raise a "Nothing to copy" notice, and a wrong
  master password reports its error once, inside the dialog that asked for it.

## 0.2.0

- Sesame now runs on Linux. The same vault, record types, unlock methods,
  auto-lock, quick access, backups, and browser integration work on Linux, and
  the build produces deb, rpm, and AppImage packages. The README platform
  table records current Linux validation status. Device protection keeps
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
