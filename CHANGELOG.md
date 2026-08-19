# Changelog

Every released version has a section here. The release workflow reads the
section matching the tag and puts it at the top of the GitHub release, so a
release cannot be published without saying what changed in it.

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
