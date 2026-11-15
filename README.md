# Sesame

Sesame is a password manager that keeps your vault on your own computer. You
can use it without an account, and optional Sync keeps an encrypted copy on a
server you choose. That server never sees your master password, your recovery
kit or anything inside the vault.

Sesame is early software and nobody independent has reviewed it yet, so don't
keep your only copy of important passwords in it for now.

This repository holds the desktop app for Windows and Linux and the browser
helper that the extension talks to. The
[browser extension](https://github.com/usesesame/sesame-browser-extension),
the [server](https://github.com/usesesame/sesame-server) and the
[website](https://github.com/usesesame/sesame-website) live in their own
repositories.

## Run it

You need Node.js 24.20 and Rust 1.98.0 with `rustfmt` and `clippy`, which
`rustup component add rustfmt clippy` adds. Windows also needs WebView2, and
Linux needs WebKitGTK 4.1 and the tray libraries.

On Debian and Ubuntu:

```sh
sudo apt-get install --no-install-recommends \
  libwebkit2gtk-4.1-dev libjavascriptcoregtk-4.1-dev libsoup-3.0-dev \
  libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev \
  libdbus-1-dev libsecret-tools build-essential curl wget file pkg-config xdg-utils
```

On Arch Linux:

```sh
sudo pacman -Syu
sudo pacman -S --needed \
  webkit2gtk-4.1 base-devel curl wget file openssl \
  libayatana-appindicator librsvg libsecret xdg-utils
```

Then start the app. On Linux:

```sh
npm ci
npm run desktop:linux:dev
```

On Windows:

```powershell
npm.cmd ci
npm.cmd run tauri:dev:browser
```

`npm run desktop:ci` runs the local checks, and CI also checks the generated
bindings and runs the browser helper for real.
[CONTRIBUTING.md](CONTRIBUTING.md) explains the workflow and the security
rules for vault, browser and sign-in code. To build installers, run
`npm run release:bundle:windows:unsigned` for the Windows installer or
`npm run release:bundle:linux:unsigned` for the deb, rpm and AppImage, which
also needs `patchelf`, `dpkg-deb` and `rpmbuild`. A local AppImage still
carries its own GLib until you run `node tools/strip-appimage-host-libs.mjs`
on it, as CI does for releases.

## What works where

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

A few things on Linux need your attention:

- Wayland has no global shortcut, so open quick access from the tray icon or
  start Sesame with `GDK_BACKEND=x11`. The AppImage always sets
  `GDK_BACKEND=x11`, and [SECURITY.md](.github/SECURITY.md#known-limits)
  explains what that costs on Wayland.
- PIN unlock and account linking need a Secret Service wallet. Sesame starts
  `gnome-keyring-daemon` or `ksecretd` when one is installed, so on Arch
  install `gnome-keyring` or `kwallet` if you have neither.
- The released AppImage uses your system's GLib 2.80 or newer, so GLib
  security fixes arrive with your normal updates.
- After you update the AppImage, start it once so it refreshes the browser
  helper it copies to `~/.local/share/sesame/browser-host`.

The rest of the limits, including what the PIN does and doesn't protect, are
in [SECURITY.md](.github/SECURITY.md#known-limits).

## Licence and security

Sesame is licensed under the
[GNU Affero General Public License v3.0 or later](LICENSE). A modified build or
hosted service can't present itself as official Sesame, and the
[trademark policy](TRADEMARKS.md) says what it must rename.

Report security problems through [SECURITY.md](.github/SECURITY.md), not a
public issue, and use made-up data in examples, screenshots and bug reports.
