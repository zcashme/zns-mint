# Git and Release Patterns

The `librustzcash` repository uses disciplined Git commit, branching, and tagging patterns to manage changes across its complex multi-crate workspace. When making changes to or interacting with this codebase, the following conventions are standard:

## 1. Commit Message Prefixes

Commit messages generally begin with the scope or the name of the crate they modify, followed by a colon and a brief description.

**Format:**
`<crate_or_scope>: <description>`

**Examples:**
- `zcash_client_sqlite: Add Ironwood received notes to the output views`
- `zcash_client_backend: remove gather_account_transparent_inputs in favor of batched query`
- `zcash_client_backend, zcash_client_sqlite: adapt to upstream API changes`

## 2. Branch Organization

Branches follow a strict naming convention to distinguish between active development, developer experiments, and long-term support.

- **Main Branch:** `main` is the primary integration branch.
- **Developer Namespaces:** Developers often prefix branches with their handle for personal or early-stage work (e.g., `adam/ironwood-split-1-foundation`, `dw/ironwood-scan-model`, `roman/6.2-decrypt`).
- **Feature & Fix Branches:** Shared feature work uses `feat/` or `feature/` (e.g., `feat/ironwood`), while bug fixes use `fix/` (e.g., `fix/proper-error-types-for-unifiedfullviewingkey-decode`).
- **Maintenance Branches:** Because the monorepo contains multiple crates that may require backports, maintenance branches are scoped to specific crates and minor versions using the `maint/<crate>-<version>.x` format.
  - Examples: `maint/zcash_client_backend-0.20.x`, `maint/zcash_primitives-0.26.x`, `maint/pczt-0.4.x`.

## 3. Crate Organization by Tags and Releases

`librustzcash` is a monorepo, but its crates are versioned and released independently. This is reflected in its tagging strategy:

- **Independent Tags:** Git tags are strictly prefixed with the crate name followed by its semantic version.
  - **Format:** `<crate_name>-<version>`
  - **Examples:** `zcash_primitives-0.29.0-pre.0`, `zcash_client_sqlite-0.21.1`, `equihash-0.3.0`.
- **Pre-releases:** Tags indicating release candidates or pre-releases use standard semver suffixes (e.g., `-pre.0`, `-rc.1`).
- **Release Tooling:** The workspace utilizes `cargo-release` (as indicated by `workspace.metadata.release` in the root `Cargo.toml`). Versions are bumped deliberately, and individual crates are tagged only when they are updated.

## 4. Pull Requests and Changelogs

- **Merge Commits:** GitHub's standard merge commits are utilized when integrating PRs into the main branch (`Merge pull request #<number> from <branch>`).
- **Changelog Management:** Commits that explicitly update `CHANGELOG.md` often use the `CHANGELOG:` prefix (e.g., `CHANGELOG: Add Orchard received-note version entry`). The project maintains rigorous changelogs per crate.
