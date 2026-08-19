# Cross-repository contracts

These suites were written when the desktop app, the API, the website, and the
browser extension lived in one repository. They assert across products, so none
of them can pass from a single checkout, and `npm run contracts` no longer runs
them. They are kept because what they assert is still true and still worth
asserting, not because they run today.

| Suite | What it protects | Where it belongs |
| --- | --- | --- |
| `sync-boundary-contracts` | Sync stays disabled, the service stores bytes it cannot read, signing and key agreement use separate keys, removing a device rotates the vault key | Split: the Go assertions to `sesame-server`, the Rust ones here |
| `governance-contracts` | Every workflow pins third-party actions and declares permissions, every repository routes review and vulnerability reports | Duplicated per repository, each asserting its own |
| `design-token-contracts` | One shared token vocabulary, no hardcoded white on a themed background, one focus treatment | Per repository, each checking its own surfaces |
| `workspace-contracts` | Layout of a monorepo that no longer exists | Mostly obsolete; salvage anything product-specific before deleting |

Re-homing them is real work: `sync-boundary-contracts` alone is over 900 lines
and reads both Go and Rust. Until that happens, treat this directory as a
specification of invariants nobody is currently checking.

The gap this leaves is not hypothetical. The release-candidate receipt broke
in exactly this way: the payload gained a field, the signer and the API were
updated together, and five other readers were not, because no suite spanned
them any more.
