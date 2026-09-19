# Cross-repository contracts

These suites were written when the desktop app, the API, the website, and the
browser extension lived in one repository. None of them can pass from a single
checkout, and `npm run contracts` no longer runs them. Every invariant now has
a check in the repository that owns the files, or a recorded retirement. This
folder is the record of that split.

| Suite | What it protects | Where it belongs | State |
| --- | --- | --- | --- |
| `sync-boundary-contracts` | Sync stays disabled, the service stores bytes it cannot read, signing and key agreement use separate keys, removing a device rotates the vault key | Split: the Go assertions to `sesame-server`, the Rust ones here | Split on 2026-09-19 into `tools/sync-boundary-contracts.test.mjs` here and `scripts/sync-boundary-contracts.test.mjs` in `sesame-server`; the original is deleted. Both website-side joins are ported: this suite pins the Settings link to `/roadmap#sync`, and `sesame-website/scripts/sync-status-contracts.test.mjs` proves the site carries that page and fragment and reports availability from the product status endpoint. |
| `governance-contracts` | Every workflow pins third-party actions and declares permissions, every repository routes review and vulnerability reports | Duplicated per repository, each asserting its own | Ported on 2026-09-19: each repository runs a `governance-contracts` suite over its own workflows, job needs, CODEOWNERS paths, dependabot ecosystems, and security policy. The routing check found 16 desktop CODEOWNERS paths left over from the monorepo; they are removed. The required-status-check table is retired because branch protection lives in repository settings, not in source. |
| `design-token-contracts` | One shared token vocabulary, no hardcoded white on a themed background, one focus treatment | Per repository, each checking its own surfaces | Ported on 2026-09-19 into each surface's own `design:tokens:check`. The desktop check reads the canonical file and its sources: required tokens, base typography, surface aliases, retired focus tokens, focus-ring contrast, undefined properties, hardcoded white, the wordmark, field focus, the 2FA button, and the sidebar tokens. The website, admin, account, and extension checks cover their own sources and snapshots; the extension also pins the overlay to its generated tokens. The original is deleted. |
| `workspace-contracts` | Layout of a monorepo that no longer exists | Mostly obsolete; salvage anything product-specific before deleting | Salvaged and deleted on 2026-09-19. `tools/installer-contracts.test.mjs` covers the Cargo version gate, the owned NSIS template with no delete-app-data path, the uninstaller hook, DLL search order and per-machine install, quoted `ExecWait` launches, and the lifecycle-evidence row format. `tools/command-surface-contracts.test.mjs` covers documented and workflow npm commands. `tools/hardening-contracts.test.mjs` covers tools orphans, Edge inspection, per-webview Tauri permissions, OS and HTTP adapter boundaries, the updater VM lab, signed static update integrity, the installed-app test bridge, and the diagnostics allowlists. The extension's pinned manifest runs in `sesame-browser-extension/scripts/manifest-contracts.test.mjs`, the Compose secret ordering in the server's `deploy:contract`, and the public client boundary in `sesame-website/scripts/public-client-contracts.test.mjs`. |

Retired with the monorepo layout: the clean-workspace gate and its runner, the
per-product CI-shape and sibling-subtree checks (a standalone checkout cannot
resolve a path above its root), the cross-repository token equality and version
independence assertions, the root `extension:check` and `:next` script names,
the VM scratch ignore paths, the local capability-key runners, the Sync preview
port agreement (the preview API runner is gone), and the account fixture key
match against the removed local CI runner. The server OpenAPI invariants moved
with `openapi:check` and the server tests.

The gap this leaves is not hypothetical. The release-candidate receipt broke
in exactly this way: the payload gained a field, the signer and the API were
updated together, and five other readers were not, because no suite spanned
them any more.
