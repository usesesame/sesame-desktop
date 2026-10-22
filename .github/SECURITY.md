# Security policy

Sesame is an early password manager. It has not had an independent
security audit, and neither has Sesame Sync, the optional feature that copies
an encrypted vault between your devices. If you find a way to read, alter, or leak vault data, we want
to hear about it before anyone else does.

## Reporting a vulnerability

**Do not open a public issue, discussion, or pull request for a security
problem.** A public report reaches attackers before it reaches users who
hold real credentials in a vault.

Use GitHub private vulnerability reporting: open the repository's **Security**
tab and choose **Report a vulnerability**. That path creates a private advisory
that only the maintainers can see.

If you cannot use GitHub, open a request on the [support
page](https://usesesame.app/support) asking for a security contact. Do not put
vulnerability details in that first message. The support intake deliberately
refuses secret-shaped content, and a wider group reads it than reads an
advisory.

### What to include

- What an attacker gains, in one sentence.
- The version, and how you installed it.
- The steps to reproduce it, in order.
- Whether it needs local access, a running desktop app, an unlocked vault, a
  linked website account, or an installed extension.

### What not to include

Never send a real vault, a password-manager export, a real password, a PIN, a
recovery kit, backup codes, TOTP seeds, or an account token. Use fictional data
in every reproduction. If a report can only be demonstrated with real data, say
so and we will work out a safe way to reproduce it.

### What happens next

- We acknowledge within 5 working days.
- We give an assessment and a rough timeline within 10 working days.
- We tell you when a fix ships and credit you in the advisory unless you prefer
  otherwise.

If you have not heard back in that time, send a follow-up.

## Supported versions

Only the current release receives fixes. Update rather than patch an older
build.

## Scope

In scope:

- The desktop vault core (`src-tauri/`): unlock, key derivation, encryption,
  PIN handling, throttling, backups, restore, import, secure deletion,
  inactivity locking, clipboard handling.
- The desktop interface (`src/`) where it can expose or mishandle vault data.
- The native-messaging host, local transport, and fill approval path under
  `src-tauri/src/bin/`, `src-tauri/src/adapters/platform/`, and
  `src-tauri/src/browser_fill*.rs`.
- Sesame Sync in the desktop app: the signed device list, snapshot headers,
  pairing, key packages, request signatures, and the minimum version check.
  Report server findings in [sesame-server](https://github.com/usesesame/sesame-server).
- The desktop release pipeline: artifact substitution, updater signature
  bypass, installer lifecycle, and rollback behaviour.

Out of scope:

- The browser extension itself, account service, administration portal, and
  public website. Report those in their own repositories. If a finding crosses
  a boundary, report it once and identify both sides.
- Anything documented as not protected against. An attacker who already has
  code execution as the logged-in desktop user, or a compromised operating
  system, is outside the model.
- Optional website icons revealing saved domains to those sites. This is
  documented behaviour of a setting that is off by default.
- Missing hardening with no demonstrated impact: header audits, version
  disclosure, rate limits without a working amplification, and scanner output
  with no exploit path.
- Social engineering of maintainers or beta testers, physical attacks, and
  denial of service through traffic volume.

## Safe harbour

We will not pursue or support legal action against research that:

- stays within the scope above,
- uses only your own accounts and your own test vaults,
- avoids accessing, altering, or retaining anyone else's data,
- avoids degrading the service for other users, and
- gives us reasonable time to ship a fix before public disclosure.

If you are unsure whether something is in bounds, report it and ask. A
good-faith report that turns out to be out of scope is not held against you.

## Known limits

- Sesame keeps a record on this device of the highest revision of your vault
  that it has opened, and it asks you to confirm before it uses an older one,
  including a backup that is older than your vault. A program running as you can
  delete that record, so the warning does not stop someone who can already
  change your files. Restoring a backup onto a device with no vault needs only
  that backup's own master password or recovery kit.
- PIN unlock is a convenience for this device, not a second factor. A program
  running as you can open the device key, and with the vault file it can test
  PINs offline. Each extra PIN digit makes that search ten times longer.
- A lost recovery kit cannot be recovered. A new one can only be issued with
  the master password after a 72-hour wait.
- Sync is off until a person turns it on in Settings. The screen says that no
  independent review has happened. A service that refuses to answer, and a
  vault with a single device, are outside what Sync claims to prevent.
- Sesame cannot protect an unlocked vault from software that controls your
  computer. Malware running as you, or as an administrator, can read the
  app's memory, drive its window, record your keystrokes, or capture the
  screen while a secret is shown.
- Showing or copying a saved secret asks for your master password, and one
  check covers the next two minutes. That covers login passwords, backup
  codes, card numbers and security codes, Wi-Fi passwords, SSH keys and
  passphrases, licence keys, document numbers and secret custom fields. They
  stay in Sesame's native code until you ask, and copying happens there too.
  Login one-time codes, secure note contents and notes show without the
  check, because the window has to display them, and a one-time code expires
  within a minute or so.
- Malware that controls your browser profile can act as the extension. The
  approval prompt in the Sesame window is the last check before a fill.
- On Linux the browser helper trusts whichever program of yours owns its
  private socket, because Sesame hides its own executable from other
  programs. A program running as you that starts before Sesame could receive
  what the helper relays, such as a login you ask Sesame to save. The app
  still checks the helper's executable before it answers.
- Changing the master password or getting a new recovery kit cannot reach
  copies made before the change: exported backups, readable exports,
  operating system backups, cloud-synced folders, and data left on an SSD. A
  copy made before a new kit still opens with the old kit.
- Turning off PIN unlock does not change the vault key. A copy of the vault
  file made while the PIN was on opens later versions for someone who also has
  that PIN and this device's key, until you change the master password or get
  a new recovery kit.
- Anyone who can write to the vault folder can put back an older vault file.
  Sesame does not yet detect that rollback.
- A master password or recovery kit that someone else learns opens any copy
  of your vault file. Keep the recovery kit offline.
- The 72-hour wait for a new recovery kit uses HTTPS time from usesesame.app
  and github.com, so it needs an internet connection. Someone who knows the
  password and keeps access for 72 hours can complete it, and software that
  can add trusted certificates could forge the time. The warning on every
  unlock is the check against both.
- The AppImage sets `GDK_BACKEND=x11`, so on a Wayland desktop its window runs
  through XWayland. Other X11 programs can then observe that window's keyboard
  input and clipboard, which Wayland otherwise isolates. The deb and rpm
  packages do not set this. The setting is kept because the WebKitGTK Wayland
  backend crashed in earlier testing, and it has not been retested on a Wayland
  session.
- The process hardening in Sesame makes the main process non-dumpable and
  refuses to run it with a tracer attached. Linux resets that setting on exec,
  so the WebKit web process that renders decrypted records runs without it.
  Where the system permits a same-user process to attach to that web process,
  that process can read displayed secrets. This waits on the renderer
  isolation work.
- On a Linux desktop that reports no idle time, the automatic lock counts
  activity in the Sesame window, which the interface reports to the app. Code
  running inside the window can report activity and keep the lock from firing,
  but that code can already read everything the window shows. Where GNOME or
  KDE reports idle time, that time is used and the window reports nothing.
