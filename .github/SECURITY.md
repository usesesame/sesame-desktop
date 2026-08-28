# Security policy

Sesame is an early password manager. It has not had an independent
security audit. If you find a way to read, alter, or leak vault data, we want
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

This is a small project. If you have not heard back in the windows above, send
a follow-up rather than assuming the report was received.

## Supported versions

Only the current release receives fixes. The practical guidance is to update
rather than to patch an older build.

| Version | Supported |
| --- | --- |
| Current release | Yes |
| Any earlier build | No. Update instead |

## Scope

In scope:

- The desktop vault core (`src-tauri/`): unlock, key derivation, encryption,
  PIN handling, throttling, backups, restore, import, secure deletion,
  inactivity locking, clipboard handling.
- The desktop interface (`src/`) where it can expose or mishandle vault data.
- The native-messaging host, local transport, and fill approval path under
  `src-tauri/src/bin/`, `src-tauri/src/adapters/platform/`, and
  `src-tauri/src/browser_fill*.rs`.
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

Stated plainly so a report does not spend effort on a known position:

- Sesame has not had an independent security audit.
- The recovery kit cannot be reset or recovered. That is a design decision, not
  a bug.
- Sync is not enabled. Preview-only desktop code is gated by the
  `sync-preview` Cargo feature, which shipping builds do not enable.
