# Releasing aiopyronix

Releases are built and uploaded by GitHub Actions. No PyPI API token exists:
PyPI trusts the `Release` workflow through
[trusted publishing](https://docs.pypi.org/trusted-publishers/), and each
upload carries a signed attestation of the workflow run that built it.

## One-time setup

- **GitHub:** the public repository `Herbertmt978/aiopyronix`, with issues
  enabled. Its `pypi` environment accepts deployments only from tags matching
  `v*`.
- **PyPI:** a trusted publisher for the `aiopyronix` project, bound to owner
  `Herbertmt978`, repository `aiopyronix`, workflow `release.yml` and
  environment `pypi`. Before the first upload it is a pending publisher; the
  first successful upload creates the project.

Changing the workflow file name, the environment name or the repository owner
breaks publishing until the PyPI publisher is updated to match.

## Versioning

The project follows [Semantic Versioning](https://semver.org/). Before 1.0:

- a patch release fixes behaviour without changing the public API;
- a minor release adds or changes public API, or changes what reaches the
  panel. The changelog calls out any change to commands, confirmation or
  session lifetime.

The version is written once, in `pyproject.toml`. The release workflow stops
unless the tag is exactly `v` followed by that version.

## Cutting a release

1. Update `version` in `pyproject.toml` and add a `CHANGELOG.md` entry.
2. Run the checks locally:

   ```bash
   ruff check .
   ruff format --check .
   mypy
   pytest --cov
   ```

3. Merge to `main` and wait for CI to pass.
4. Publish a GitHub release whose tag is `v<version>`, targeting `main`:

   ```bash
   gh release create v0.1.1 --target main --title 0.1.1 --notes-file notes.md
   ```

5. The `Release` workflow reruns CI, checks the tag, builds the sdist and
   wheel, and uploads both to PyPI. Confirm the new version at
   <https://pypi.org/project/aiopyronix/>.
6. In [HA-Pyronix](https://github.com/Herbertmt978/HA-Pyronix), update the
   pin in `manifest.json` and `requirements-dev.txt`, then run its tests on
   the minimum and current Home Assistant versions.

A published version cannot be replaced on PyPI. If a release is wrong, yank it
on PyPI and publish a new patch version.

## Licence

aiopyronix is MIT licensed, like the integration. Its runtime dependencies are
also OSI approved: aiohttp (Apache-2.0) and cryptography (Apache-2.0 or
BSD-3-Clause). The wheel records the licence as an SPDX expression and
includes the `LICENSE` file.
