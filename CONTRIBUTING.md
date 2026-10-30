# Contributing

Thank you for considering a contribution to this project. Please read this guide before opening a pull request.

## Development Setup

```bash
git clone https://github.com/your-org/unifi-zone-manager.git
cd unifi-zone-manager
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Branch Strategy

| Branch | Purpose |
|---|---|
| `main` | Stable, releasable code only |
| `develop` | Integration branch for features |
| `feat/<short-description>` | New features |
| `fix/<short-description>` | Bug fixes |
| `chore/<short-description>` | Tooling, deps, docs |

All pull requests must target `develop`, not `main`.

## Commit Message Convention

This project follows [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

```
<type>(<scope>): <short summary in imperative mood>

[optional body — wrap at 72 characters]

[optional footer — e.g. Closes #123]
```

### Types

| Type | When to use |
|---|---|
| `feat` | A new feature |
| `fix` | A bug fix |
| `docs` | Documentation only |
| `test` | Adding or updating tests |
| `refactor` | Code change that is neither a fix nor a feature |
| `chore` | Build process, dependency updates, tooling |
| `ci` | CI/CD pipeline changes |

### Examples

```
feat(api): add traffic matching list delete endpoint

fix(crypto): raise ValueError on truncated ciphertext input

docs(architecture): add backup encryption sequence diagram

test(policy): add coverage for subnet destination filter
```

## Code Style

This project uses [Ruff](https://docs.astral.sh/ruff/) for linting and formatting.

```bash
ruff check .
ruff format .
```

CI will fail if either command reports errors.

## Running Tests

```bash
pytest
```

Coverage must not drop below 80% on a pull request.

## Pull Request Checklist

- [ ] Tests added or updated for any changed behaviour
- [ ] `ruff check .` passes with no errors
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] Commit messages follow the Conventional Commits convention
- [ ] No credentials, secrets, or `.unf` backup files committed
