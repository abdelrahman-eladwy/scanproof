# Releasing

Releases are cut by pushing a `vX.Y.Z` tag. `.github/workflows/release.yml` first proves the\ntag commit belongs to `main` and that the exact commit passed the `ci.yml` main-push run.\nOnly then does it test and build without OIDC permission, sign distributions in a separate\nOIDC job, publish to PyPI and GHCR, and create a GitHub pre-release.

## One-time setup (maintainer)

1. **PyPI trusted publisher** - on pypi.org: Account > Publishing > *Add a new pending publisher*:
   - PyPI project name: `scanproof`
   - Owner: `abdelrahman-eladwy`, Repository: `scanproof`
   - Workflow: `release.yml`, Environment: `pypi`
2. **GitHub environment** - repo Settings > Environments > New environment `pypi`. Optionally add
   yourself as a required reviewer so every PyPI upload needs a click.
3. **Private vulnerability reporting** - Settings > Code security > enable *Private vulnerability
   reporting* (SECURITY.md links to it).
4. **After the first release** - GitHub > Packages > `scanproof` > Package settings > change
   visibility to **Public**, so `docker pull ghcr.io/abdelrahman-eladwy/scanproof` works without login.

No API tokens or passwords are stored anywhere.

## Each release

1. PR that sets the version in **both** `pyproject.toml` and `src/scanproof/__init__.py`
   (the workflow refuses a tag that doesn't match), and moves the `CHANGELOG.md` entries under
   the new version with today's date.
2. Merge and verify **successful `ci.yml` on the exact `main` commit**. Only then, on `main`:
   ```bash
   git pull
   git tag -a v0.1.0 -m "ScanProof v0.1.0"
   git push origin v0.1.0
   ```
3. Watch the `release` workflow: the tag ancestry and successful main-push CI preflight must\n   both pass, followed by build, distribution attestation and publishing. Approve the `pypi`\n   environment if you added a reviewer. Do not bypass a rejected preflight by rerunning\n   unreviewed or orphaned tag commits.\n\nThis release path is still subject to a controlled live-tag acceptance run. Unit tests of the\nworkflow are necessary but do not prove external publishing credentials, environment gates,\nprovenance or registry availability.

## Verifying a release (for users)

```bash
gh attestation verify scanproof-0.1.0-py3-none-any.whl -R abdelrahman-eladwy/scanproof
gh attestation verify oci://ghcr.io/abdelrahman-eladwy/scanproof:0.1.0 -R abdelrahman-eladwy/scanproof
```
