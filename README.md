# Sesame

Sesame is a local-first password and recovery vault. The desktop app works
without an account or Sesame server. You can create, unlock, search, import,
back up, and export a vault locally.

The account service, public website, and browser extension are separate
projects. They are outside the vault trust boundary. Sesame never receives a
vault, master password, recovery kit, PIN, TOTP seed, or wrapping key.

Sesame is early software, and an independent security review has not finished
yet. Do not rely on it for your only copy of important credentials for now.

## Repository shape

This repository contains the desktop app and native-messaging host. The other
projects have their own releases and CI.

| Path | What it is | Required to use a local vault? |
| --- | --- | --- |
| `src/` | Svelte desktop interface | Yes |
| `src-tauri/` | Tauri host and Rust vault core | Yes |
| `design/` | Desktop design tokens | Yes |
| `tools/` | Contract tests, release evidence, and CI helpers | No |

Other Sesame projects:

- [sesame-browser-extension](https://github.com/usesesame/sesame-browser-extension):
  the Chrome, Edge, and experimental Firefox packages
- [sesame-server](https://github.com/usesesame/sesame-server): the vault-blind
  Go API, account portal, and administration portal
- [sesame-website](https://github.com/usesesame/sesame-website): the static
  public site

The desktop must work when hosted services are unavailable. Sync preview code
is excluded from shipping builds. It remains unavailable until it passes its
security gate.

Before changing vault, browser, or authentication code, read the security
rules in [CONTRIBUTING.md](CONTRIBUTING.md).

## Run it

Requirements: Node.js 24.20 and Rust 1.98.0. Windows also needs WebView2.
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

On Windows:

```powershell
npm.cmd ci
npm.cmd run tauri:dev:browser
```

On Linux, after installing the dependencies above:

```sh
npm ci
npm run desktop:linux:dev
```

`npm run release:bundle:windows:unsigned` builds the NSIS installer.
`npm run release:bundle:linux:unsigned` builds the deb, rpm, and AppImage, and
also needs `patchelf`, `dpkg-deb`, and `rpmbuild`.

`npm run desktop:test` runs the unit, vault core, and contract tests.
`npm run desktop:ci` is the full local check. The contributor workflow is in
[CONTRIBUTING.md](CONTRIBUTING.md).

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
| Account linking | Yes | Secret Service wallet, validation pending |
| Signed desktop updates | Yes | No |

On Linux:

- Idle time comes from GNOME or KDE. The automatic-lock delay is hidden on
  other desktops.
- Wayland has no global-hotkey protocol. Use the tray icon, or start Sesame
  with `GDK_BACKEND=x11`.
- PIN unlock and account linking need a Secret Service wallet. Sesame starts
  `gnome-keyring-daemon` or `ksecretd` when none is running. On Arch, install
  `gnome-keyring` or `kwallet` if the desktop has neither.
- The AppImage cannot register the browser connection. Use the deb or rpm.

The wallet on Linux and DPAPI on Windows protect the PIN data from other
users. They do not protect it from other programs running as you, so the PIN
is a convenience unlock. See [.github/SECURITY.md](.github/SECURITY.md#known-limits).

## Licence and trademarks

Sesame is licensed under the
[GNU Affero General Public License v3.0 or later](LICENSE). It covers the
desktop app and native-messaging host in this repository. The related Sesame
repositories publish their own licence files.

The licence does not let a modified build or hosted service present itself as
official Sesame. The [trademark policy](TRADEMARKS.md) sets what modified
distributions must rename.

## Security

Security issues should be reported through [.github/SECURITY.md](.github/SECURITY.md),
not a public issue. Examples, fixtures, screenshots, and bug reports must use
fictional data.
