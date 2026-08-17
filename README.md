# Sesame

Sesame is a password and recovery vault that is local-first. The desktop app
stands on its own: you can create, unlock, search, import, back up, and export a
vault with no account and no Sesame server.

The repository also ships an optional hosted stack for accounts, downloads,
support, and administration. It sits outside the vault's trust boundary and
never receives a vault, master password, recovery kit, PIN, TOTP seed, or
wrapping key.

Sesame is early software, and an independent security review has not finished
yet. Do not rely on it for your only copy of important credentials for now.

## Project shape

The repository is a monorepo because the surfaces share release contracts,
rather than because they must be deployed together.

| Path | What it is | Required to use a local vault? |
| --- | --- | --- |
| `src/` | Svelte desktop interface | Yes |
| `src-tauri/` | Tauri host and Rust vault core | Yes |
| `extensions/sesame/` | Chrome and Edge extension | No |
| `backend/` | Vault-blind Go API | No |
| `website/` | Public marketing site | No |
| `account/` | Account portal served with the API | No |
| `admin/` | Administration interface for the API | No |
| `design/` | Shared design tokens, the single source for every surface | Yes |
| `tools/` | Contract tests, release evidence, and CI helpers | No |

This split supports three ways to run Sesame:

1. Use or build only the desktop app. This is the default and needs no server.
2. Run the desktop app with your own optional account service.
3. Host the complete website, API, database, account portal, and admin
   interface.

The website should remain replaceable. A self-hosted API should not depend on
Sesame's public marketing site, and the desktop must keep working when every
hosted service is unavailable. Sync code exists but is disabled and must stay
disabled until its security gate passes.

Before changing vault, browser, or authentication code, read the security
rules in [CONTRIBUTING.md](CONTRIBUTING.md).

## Run it

Requirements: Node.js 24.13, Rust 1.93.1, Go 1.25 or newer, and Windows
WebView2. Docker is needed only for the optional API stack.

```powershell
npm.cmd ci
npm.cmd run tauri dev
```

Optional surfaces run separately:

```powershell
npm.cmd run website:dev   # http://localhost:4173
npm.cmd run admin:dev     # http://localhost:4174
npm.cmd run api:up        # API, PostgreSQL, and local test mail
```

`npm.cmd run api:up` writes development-only secrets into the ignored root
`.env` file. Do not reuse them in a deployment.

Run the checks that cover the area you changed. The usual full local check is:

```powershell
npm.cmd run ci:all
```

The contributor workflow is in [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence and trademarks

Sesame is licensed under the
[GNU Affero General Public License v3.0 or later](LICENSE). The licence covers
the desktop, browser extension, website, account portal, admin interface, and
hosted API in this repository. In particular, a modified hosted version must
offer its corresponding source, as the AGPL requires.

The source licence does not grant rights to present a modified build or hosted
service as an official Sesame product. The separate [trademark policy](TRADEMARKS.md)
allows truthful compatibility and attribution references, while requiring
modified distributions to use their own product name, artwork, identifiers,
and publisher identity.

## Security

Security issues should be reported through [.github/SECURITY.md](.github/SECURITY.md),
not a public issue. Examples, fixtures, screenshots, and bug reports must use
fictional data.
