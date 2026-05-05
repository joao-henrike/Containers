# Contributing

Thanks for considering a contribution. This project moves slowly and
deliberately — predictability for forensic users matters more than
moving fast.

## How to file a bug

Open a GitHub issue with the **Bug report** template. Please include:

- The output of `forensics-health` and `docker version`.
- Whether you're on Linux/macOS/Windows + Docker Desktop.
- The exact command you ran and the full error.
- Whether the bug is reproducible from a fresh `docker compose build`.

## How to propose a feature

Open an issue with the **Feature request** template *first*. Get a
maintainer's nod before you start coding. We routinely close PRs that
expand scope without prior discussion.

## Development setup

```bash
git clone https://github.com/joao-henrike/Containers.git
cd Containers/forensics-professional

# Host-side dev tools (lint, type-check, test)
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
```

Run the local checks:

```bash
make lint        # ruff + mypy
make test        # pytest
make build       # docker compose build
make smoke       # spin up + run validate.sh + tear down
```

## Commit style

[Conventional Commits](https://www.conventionalcommits.org/) — please:

```
feat(modules): add binwalk submodule to disk-forensics
fix(audit): handle malformed entries in verify()
docs(readme): correct memory-forensics size estimate
```

Keep commits small and focused. PRs that touch >500 LOC almost
always need rework before merging.

## Code style

- **Python**: ruff for lint, mypy for types. Type annotations
  required on new public functions.
- **Bash**: ShellCheck-clean. `set -euo pipefail` mandatory.
- **YAML**: 2-space indent.
- **Docs**: 80-character line limit. Markdown files use ATX-style
  headings (`#`, not underline).

## Adding a module

See the [Architecture: Extension points](ARCHITECTURE.md#extension-points)
section. Required for a module PR:

1. Entry in `modules/registry.json` with `verify` hints for *every*
   submodule. PRs without verify hints are rejected — installations
   that we can't verify aren't useful.
2. Installer functions in `core/forensics/modules/installers.py`.
3. Removal commands in `REMOVERS` where reasonable.
4. Documentation update: a row in the README catalogue table.
5. A test in `tests/test_modules.py` that exercises the registry
   parsing of the new module.

## Adding a forensic tool to an existing module

Smaller change. Required:

1. Add the apt/pip/git command to the existing installer function.
2. Add a verify hint for the new tool.
3. Update the `tools_overview` in the module registry entry.
4. Note the change in `CHANGELOG.md`.

## Testing

```bash
pytest -v
pytest -v -k modules            # only module tests
pytest --cov=forensics core/    # coverage report
```

## Release process

Maintainer-only:

1. Bump `VERSION`.
2. Update `CHANGELOG.md` with the new section.
3. Tag: `git tag -a v3.x.y -m "Release v3.x.y"`.
4. `docker compose build` and push the image.
5. GitHub Release notes copied from the changelog section.

## Code of conduct

Be civil, be patient. We assume good faith. Bad-faith comments,
harassment, or attempts to weaponize the project for unauthorized
investigations get you instantly banned.
