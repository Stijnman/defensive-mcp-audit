# PyPI trusted publishing setup

One-time configuration to enable automatic PyPI uploads on tag push.

## 1. Create the PyPI project (first time only)

1. Sign in at [pypi.org](https://pypi.org)
2. Ensure the project name `defensive-mcp-audit` is available

## 2. Add a trusted publisher

On PyPI → **Account settings** → **Publishing** → **Add a new pending publisher**:

| Field | Value |
|-------|-------|
| PyPI project name | `defensive-mcp-audit` |
| Owner | `Stijnman` |
| Repository name | `defensive-mcp-audit` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

## 3. Create matching GitHub environment

In the repository → **Settings** → **Environments** → **New environment**:

- Name: `pypi`
- (Optional) Add required reviewers for manual approval

## 4. Release

```bash
git tag v0.3.2
git push origin v0.3.2
```

The `release.yml` workflow publishes to PyPI automatically after the GitHub Release is created.