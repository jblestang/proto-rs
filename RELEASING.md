# Releasing

The crates.io package is `proto-rs-dynamic`; its library target is `proto_rs`.
Crate versions are permanent on crates.io and cannot be overwritten.

## Prepare a release

1. Confirm `proto-rs-dynamic` is still the intended crates.io package name.
2. Update `version` and, when required, `rust-version` in `Cargo.toml`.
3. Move the changelog entries from `Unreleased` to a dated version heading.
4. Run all checks from `CONTRIBUTING.md`, including the official Protocol
   Buffers conformance test suite when compatibility code changed, and verify
   that `CONFORMANCE.md` still describes every skip or exclusion accurately.
5. Inspect the exact archive and verify it locally:

   ```bash
   cargo package --list
   cargo publish --dry-run
   ```

6. Commit the release, create an annotated `vX.Y.Z` tag, and push the commit
   and tag only after CI is green. Do not publish the GitHub Release until all
   preparation is complete, because that event starts crates.io publication.

## First crates.io release

The first version must be published manually because crates.io trusted
publishing can only be configured after the package exists. Create a
short-lived crates.io token limited to publishing the new
`proto-rs-dynamic` crate, expose it as `CARGO_REGISTRY_TOKEN` for this command,
and revoke it immediately afterward:

```bash
cargo publish
```

Then open the crate settings on crates.io and add a GitHub Actions trusted
publisher with owner `jblestang`, repository `proto-rs`, workflow
`publish.yml`, and environment `release`. Create a GitHub environment named
`release`. Do not require environment approval if publication must remain fully
automatic; publishing the GitHub Release is already the deliberate release
action.

After trusted publishing is configured, publish the GitHub Release associated
with the already-uploaded first tag. The workflow detects that the crates.io
version exists and completes successfully without attempting a duplicate
upload.

## Later releases

After the release commit and tag are pushed and CI is green, publish the GitHub
Release for that tag. GitHub automatically starts **Publish crate**. The
workflow refuses to publish unless the release tag exactly matches the Cargo
package version, performs a dry run, and exchanges GitHub's OIDC identity for a
short-lived crates.io token. No long-lived registry secret is stored in
GitHub. Manual workflow dispatch is retained only as a recovery mechanism and
must be dispatched against an exact version tag.

After one automated release has succeeded, enable crates.io's option to accept
publications only through trusted publishing. This prevents a leaked personal
API token from publishing later versions.
