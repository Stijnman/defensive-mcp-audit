# PyPI trusted publishing setup

One-time configuration (2 minutes). After this, every `v*` tag auto-publishes to PyPI.

## Add trusted publisher on PyPI

1. Sign in at [pypi.org](https://pypi.org)
2. Go to **Account settings → Publishing → Add a new pending publisher**
3. Enter **exactly**:

| Field | Value |
|-------|-------|
| PyPI project name | `defensive-mcp-audit` |
| Owner | `Stijnman` |
| Repository name | `defensive-mcp-audit` |
| Workflow filename | `release.yml` |
| Environment name | `pypi` |

4. Save the publisher

## Re-run publish (after publisher is saved)

```bash
gh workflow run release.yml --ref v0.3.2
```

Or push a new patch tag:

```bash
git tag v0.3.3 && git push origin v0.3.3
```

## Verify

```bash
pip install defensive-mcp-audit[cli]
defensive-mcp-audit --help
```

Package page: https://pypi.org/project/defensive-mcp-audit/

## GitHub environment

The `pypi` environment already exists in this repository (required for OIDC claims).