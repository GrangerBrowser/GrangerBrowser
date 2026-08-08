# Granger Browser Git workflow

The repository keeps `main` as the last accepted baseline. Product work is done
on focused branches and proposed through pull requests.

## Branches

- Start from an up-to-date `main`.
- Use `agent/<scope>` for Codex-assisted work and a similarly descriptive
  prefix for human work.
- Keep one coherent product change per branch.
- Do not force-push `main` or rewrite its published history.

## Commits

- Commit completed logical stages, not arbitrary activity checkpoints.
- Use descriptive messages such as `fix(sidebar): anchor bottom navigation`.
- Build and run the relevant focused tests before pushing each stage.
- Never commit generated packages, profiles, logs, dumps, credentials, or
  private browsing data.

## Pull requests

Pull requests should explain the root cause, implementation, user impact,
tests, screenshots, performance impact, and known limitations. They remain
unmerged until the repository owner reviews them.

## Release artifacts

Portable binaries are produced locally by `scripts/build-release.ps1`. They do
not belong in source commits. A future tagged release may publish them through
GitHub Releases or CI artifacts after signing and release policy are defined.

