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

Requirements: Node.js 24.13 and Rust 1.93.1. Windows also needs WebView2.
Linux needs WebKitGTK 4.1 and the tray libraries:

Debian and Ubuntu:

```sh
sudo apt-get install --no-install-recommends \
  libwebkit2gtk-4.1-dev libjavascriptcoregtk-4.1-dev libsoup-3.0-dev \
  libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev \
  libdbus-1-dev libsecret-tools build-essential curl wget file pkg-config xdg-utils
```

Arch Linux:

```sh
sudo pacman -Syu
sudo pacman -S --needed \
  webkit2gtk-4.1 base-devel curl wget file openssl \
  libayatana-appindicator librsvg libsecret xdg-utils
```

```sh
npm ci
npm run desktop:linux:dev
```

`npm run release:bundle:windows:unsigned` builds the NSIS installer.
`npm run release:bundle:linux:unsigned` builds the deb, rpm, and AppImage.
Linux packaging also requires `patchelf`, `dpkg-deb`, and `rpmbuild`. On Arch,
install them with `sudo pacman -S --needed patchelf dpkg rpm-tools`. The Linux
bundle command checks these tools before building.

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

## Platforms

| Capability | Windows | Linux |
| --- | --- | --- |
| Local vault: create, unlock, search, import, back up, export | Yes | Yes |
| Tray, quick access, start at sign-in | Yes | Yes |
| Global quick access shortcut | Yes | X11 sessions only |
| Browser extension connection | Yes | DEB and RPM builds, validation pending |
| Automatic lock on screen lock | Yes | Built, validation pending |
| Automatic lock on inactivity | Yes | GNOME and KDE, validation pending |
| Unlock with PIN | Yes | Secret Service wallet, validation pending |
| Unlock with Windows Hello | Yes | No |
| Auto-type | Yes | No |
| Account linking | Yes | No |
| Signed desktop updates | Yes | No |

Linux reads the screen lock from systemd-logind, falling back to the desktop's
own screensaver interface. Inactivity has no shared Linux interface, so it is
read from GNOME's or KDE's idle monitor and the automatic lock delay is hidden
on desktops that publish neither.

Wayland publishes no protocol for global hotkeys, so the quick access shortcut
is registered only in an X11 session and the setting is hidden elsewhere. Open
quick access from the tray icon there, or start Sesame with `GDK_BACKEND=x11`.

Linux keeps Sesame's random device-protection key in the desktop Secret Service
wallet. PIN peppers and local attempt-throttle state are authenticated and
encrypted with that key. Windows uses DPAPI for the same boundary. Windows
Hello and auto-type remain unavailable on Linux.

PIN unlock requires a Secret Service wallet provider. GNOME Keyring supplies
one on GNOME. KWallet supplies `ksecretd`, which Sesame starts when needed on
other desktops such as Hyprland. On Arch, install either `kwallet` or
`gnome-keyring` if the desktop does not already provide one.

The browser connection uses a socket in the per-user runtime directory rather
than a named pipe. Both ends check the peer's user id and executable path
before any vault data moves, and the peer's process start time is recorded so a
reused process id cannot inherit an approved connection.

Browser registration requires a stable native-host path, so it is disabled in
the AppImage build. The DEB and RPM paths are built but remain beta until the
extension's clean-profile verification passes on Linux.

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
