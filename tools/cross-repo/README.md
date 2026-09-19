# Cross-repository contracts

These suites were written when the desktop app, the API, the website, and the
browser extension lived in one repository. They assert across products, so none
of them can pass from a single checkout, and `npm run contracts` no longer runs
them. They are kept because what they assert is still true and still worth
asserting, not because they run today.

| Suite | What it protects | Where it belongs | State |
| --- | --- | --- | --- |
| `sync-boundary-contracts` | Sync stays disabled, the service stores bytes it cannot read, signing and key agreement use separate keys, removing a device rotates the vault key | Split: the Go assertions to `sesame-server`, the Rust ones here | Split on 2026-09-19 into `tools/sync-boundary-contracts.test.mjs` here and `scripts/sync-boundary-contracts.test.mjs` in `sesame-server`; the original is deleted. Both website-side joins are ported: this suite pins the Settings link to `/roadmap#sync`, and `sesame-website/scripts/sync-status-contracts.test.mjs` proves the site carries that page and fragment and reports availability from the product status endpoint. |
| `governance-contracts` | Every workflow pins third-party actions and declares permissions, every repository routes review and vulnerability reports | Duplicated per repository, each asserting its own | Ported on 2026-09-19: each repository runs a `governance-contracts` suite over its own workflows, job needs, CODEOWNERS paths, dependabot ecosystems, and security policy. The routing check found 16 desktop CODEOWNERS paths left over from the monorepo; they are removed. The required-status-check table is retired because branch protection lives in repository settings, not in source. |
| `design-token-contracts` | One shared token vocabulary, no hardcoded white on a themed background, one focus treatment | Per repository, each checking its own surfaces | Not started; each product already runs its own `design:tokens:check` |
| `workspace-contracts` | Layout of a monorepo that no longer exists | Mostly obsolete; salvage anything product-specific before deleting | Partly salvaged on 2026-09-19: the installer and Windows-hardening checks now run as `tools/installer-contracts.test.mjs`, and the documented and workflow npm-command checks as `tools/command-surface-contracts.test.mjs`. The rest still needs review, including the per-webview Tauri permission map, the updater VM lab, the diagnostics allowlist, the adapter boundaries, and the embedded-inspection exclusions. |

Re-homing is real work: `sync-boundary-contracts` alone was over 900 lines and
read both Go and Rust. Until a suite is split, treat its file here as a
specification of invariants nobody is currently checking.

The gap this leaves is not hypothetical. The release-candidate receipt broke
in exactly this way: the payload gained a field, the signer and the API were
updated together, and five other readers were not, because no suite spanned
them any more.
