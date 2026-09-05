# Contributing to Sesame

This repository is the Sesame desktop app:

- `src/`: the Svelte interface
- `src-tauri/`: the Tauri host and the Rust vault core
- `design/`: the design tokens every Sesame surface shares
- `tools/`: contract checks, release helpers, and CI scripts
- `.github/`: delivery controls

The rest of Sesame lives in its own repositories, one per trust boundary:

- [sesame-browser-extension](https://github.com/usesesame/sesame-browser-extension):
  the Chrome and Edge extension
- `sesame-server`: the vault-blind Go API, the account portal, and the admin app
- `sesame-website`: the public site

Work on those belongs in those repositories. Keep a pull request here to one
thing. If a change here needs a matching change over there, open both, link
them, and say in each which one merges first.

Talk to the owner before you start, so that two people do not rewrite the same
file from different directions.

## Getting set up

You need Node.js 24.20 and Rust 1.98.0. Windows also needs WebView2. Linux
needs the WebKitGTK, tray, and packaging dependencies listed in
[README.md](README.md).

```bash
npm ci
npm run desktop:ci
```

That passes on a fresh clone with no `.env`, no API running, and no database.
If it fails before you have touched anything, the problem is your toolchain and
not your change.

To run the app while you work:

```bash
npm run tauri:dev:browser
```

On Linux, `npm run desktop:linux:dev` checks the native dependencies before
running the same workflow.

`npm run desktop:dev` runs the same interface in a browser against an
in-memory preview vault. It is quicker for interface work, but it never reaches
the Rust core, so anything touching the vault needs the real app.

## Never commit secrets

Real vaults, password-manager exports, passwords, PINs, recovery kits, backup
codes, TOTP seeds, account tokens, production data, private signing material,
and screenshots showing any of them stay out of the repository and out of pull
requests. Tests and documentation use invented data.

CI scans the full history. If a secret reaches a branch, rotate it. Amending
the commit does not unpublish it.

## Before you open a pull request

Run the checks for what you touched, and paste the commands you actually ran
into the pull request.

| You changed | Run |
| --- | --- |
| `src/` | `npm run desktop:lint:js`, `npm run desktop:check` |
| `src-tauri/` | `npm run desktop:lint:rust`, `npm run desktop:test:rust` |
| `design/` or `tools/` | `npm run desktop:contracts` |
| Anything, while you work | `npm run desktop:test` |
| Anything, before review | `npm run desktop:ci` |

Use the `desktop:` scripts named above. They are the stable public command
surface for this repository.

`npm run desktop:test` is the everyday loop: interface unit tests, vault core
tests, and the contract suites, in one command. `npm run desktop:ci` adds the
production build, the lints, and the Sync preview feature tests.

Unit tests cover the Svelte controllers and Rust vault core. There is no
installed-app lifecycle suite yet. If you change unlock, migration, import,
backup, or the browser fill flow, exercise it by hand and write in the pull
request what you did and what you saw.

If you change what the desktop is allowed to depend on, run `npm run
desktop:boundary:verify`. It copies the files listed in `desktop-boundary.json`
into a temporary directory and runs `npm ci` and `npm run desktop:ci` there,
which is how we know the desktop still stands on its own. CI runs the same
check on a weekly schedule and on demand, so a boundary that breaks quietly
does not stay broken.

## Filling in the pull request template

The security and data boundary section is not a formality. Tick "not
applicable" only when the change cannot affect unlock, encryption, backup,
import, browser messaging, authentication, or audit behaviour. If you had to
stop and think about whether it applies, it applies, so say what changed and
what still holds.

Under Validation, name the commands. "Tested" tells a reviewer nothing.

## Code rules

Lint encodes most of these, so `npm run desktop:lint:js` and `npm run
desktop:lint:rust` are the fastest way to find out whether your change fits.
The reasons behind them:

- No `console` output in the shipped frontend, and no raw error strings, paths,
  domains, or entry identifiers in diagnostics. Diagnostics are made to be
  handed to support, so they carry codes and categories, never contents.
- No `unwrap()` in the Rust vault core. A panic there strands someone in front
  of the one copy of a credential they cannot get any other way.
- The Rust host owns secrets and filesystem access. The interface reaches them
  through Tauri IPC and nothing else.
- No credential persistence in extension storage. The reasoning is in
  [DESIGN.md](https://github.com/usesesame/sesame-browser-extension/blob/main/DESIGN.md)
  in the extension repository.

## Writing interface copy

Write like a desktop tool that respects the reader. Buttons start with a verb
(`Import`, `Copy`, `Create backup`). Labels state the state (`Missing`,
`3 codes stored`). Errors say what failed and what to do next.

Security text states the boundary plainly instead of promising a feeling, and
never claims more than the code does. Leave out "seamless", "effortless",
"peace of mind", and "powerful", along with "not X but Y" contrasts and
three-item lists where one accurate sentence does the work. Icons are controls,
not decoration.

No em dashes anywhere: interface copy, code comments, commit messages,
documentation. A comma, a colon, a full stop, or brackets will do the job.

## The browser extension boundary

The extension itself is in
[sesame-browser-extension](https://github.com/usesesame/sesame-browser-extension).
The desktop side of that boundary is here, in
`src-tauri/src/adapters/platform/browser_host/` and `browser_pipe.rs`, with
the wire format under `src-tauri/contracts/browser/`.

Changing either side needs a security-boundary review and the clean-profile
verification described in the extension repository's
[README](https://github.com/usesesame/sesame-browser-extension/blob/main/README.md).

## Reporting a security issue

Do not open a public issue. Follow [.github/SECURITY.md](.github/SECURITY.md).
