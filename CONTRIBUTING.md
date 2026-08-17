# Contributing to Sesame

Sesame is split into products with different trust boundaries. Whenever
possible, keep a change in one primary area:

- `src/` and `src-tauri/`: desktop interface and local vault core
- `backend/`: vault-blind Go API and PostgreSQL migrations
- `website/`: public pages, account portal, and support portal
- `admin/`: separate vault-blind administration application
- `extensions/sesame/`: maintained TypeScript browser extension
- `.github/`: delivery controls

Do not combine unrelated product work in one pull request. If an API contract
must land before its consumer, use separate linked issues and state the merge
order.

## Your first change

```bash
npm ci
```

```bash
npm run ci:all
```

That runs clean from a fresh clone with no `.env`, no running API, no
PostgreSQL, no staged browser host, and no generated frontend output. If it
fails before you have changed anything, the problem is your toolchain, not your
change. You need Node.js 24.13, Rust 1.93.1, Go 1.25 or newer, and the Windows
WebView2 runtime.

The table under "Before review" maps each part of the repository to the checks
that cover it.

Before changing code, confirm the work item with the owner.
Long plans and dated reviews are inputs, not task queues. Record exact commands
and results before handing work to another contributor.

## Never include secrets

Do not commit or attach real vaults, password-manager exports, passwords, PINs,
recovery kits, backup codes, TOTP seeds, account tokens, production database
data, private signing material, or screenshots containing them. Tests and
documentation must use fictional data.

CI runs a full-history secret scan. A secret that reaches a branch must be
rotated; amending a commit cannot remove it.

## Before review

Run the checks for the area you changed and list the exact commands in the pull
request. As a minimum:

| You changed | Run |
| --- | --- |
| `src/` | `npm run lint:js`, `npm run desktop:check` |
| `src-tauri/` | `npm run lint:rust`, `cargo check --manifest-path src-tauri/Cargo.toml --workspace` |
| `backend/` | `npm run lint:go`, `npm run backend:test` |
| `website/` | `npm run website:check` |
| `admin/` | `npm run admin:check` |
| `extensions/sesame/` | `npm run extension:ci` |
| Anything | `npm run contracts` |

The test suites were removed in 2026-08 and are being rewritten. Until they
land, the commands above check types, lint, and builds, and `npm run contracts`
checks the repository's structural invariants. None of them checks behaviour,
so a change to unlock, migration, import, or the fill flow needs describing and
exercising by hand in the pull request.

Phase 0 release blockers also need the evidence named in their issue. A
documentation claim must describe shipped behaviour, not an intended feature.

## Filling in the pull request template

The security and data boundary section is not a formality. Tick "not
applicable" only when the change cannot affect unlock, encryption, backup,
import, browser messaging, authentication, or audit behaviour. If you had to
think about whether it applies, it applies: explain what changed and what still
holds.

Under Validation, name the exact commands you ran. "Tested" is not an answer.

## Code rules

Lint encodes the rules that matter, so `npm run lint:all` is the fastest way to
find out whether a change respects them. The rules exist for a reason and the
reason is written down:

- No `console` output in shipped frontends, and no raw error strings, paths,
  domains, or entry identifiers in diagnostics.
- No cross-surface imports. The website, the admin app, and the desktop UI are
  separate products that happen to share a repository.
- No `unwrap()` in the Rust vault core. A panic in a vault process is a
  usability failure at the worst possible moment.
- No credential persistence in extension storage. See
  [extensions/sesame/DESIGN.md](extensions/sesame/DESIGN.md).

## Interface copy

Write like a useful desktop tool. Buttons start with a verb (`Import`, `Copy`,
`Create backup`), labels explain state (`Missing`, `3 codes stored`), and errors
say what failed and the next safe action. Security text states a boundary
plainly rather than promising a feeling, and never claims more than the current
implementation does.

Avoid `seamless`, `effortless`, `peace of mind`, `powerful`, "not X but Y"
contrasts, three-item marketing lists when one precise sentence will do, and
icons used as decoration rather than as controls.

No em dashes. Use a comma, a colon, a full stop, or brackets. That covers
interface copy, code comments, commit messages, and documentation.

## Reporting a security issue

Do not open a public issue. Follow [.github/SECURITY.md](.github/SECURITY.md).

## Browser extension

`extensions/sesame/` is the maintained browser extension. Changes to its
native-host boundary require a security-boundary review and the clean-profile
verification in [extensions/sesame/README.md](extensions/sesame/README.md).
