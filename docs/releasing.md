# Releasing

Releases are cut by pushing a `vX.Y.Z` tag. `.github/workflows/release.yml` then tests, builds,
publishes to PyPI and GHCR, attaches SLSA provenance, and creates a GitHub (pre-)release.

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
   (the workflow refuses a tag that doesn't match), and updates the README roadmap.
2. Merge, then on `main`:
   ```bash
   git pull
   git tag -a v0.1.0 -m "ScanProof v0.1.0"
   git push origin v0.1.0
   ```
3. Watch the `release` workflow. Approve the `pypi` environment if you added a reviewer.

## Verifying a release (for users)

```bash
gh attestation verify scanproof-0.1.0-py3-none-any.whl -R abdelrahman-eladwy/scanproof
gh attestation verify oci://ghcr.io/abdelrahman-eladwy/scanproof:0.1.0 -R abdelrahman-eladwy/scanproof
```
