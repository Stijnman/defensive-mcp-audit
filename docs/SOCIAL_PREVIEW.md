# Social preview image

GitHub social preview must be uploaded via the repository **Settings** UI (no stable public API).

## Image file

Use: `.github/social-preview.png` (1280×640, 161 KB)

## Option A — Manual (fastest)

1. Open [Repository Settings → Social preview](https://github.com/Stijnman/defensive-mcp-audit/settings#social-preview)
2. Click **Edit → Upload an image**
3. Select `.github/social-preview.png` from this repo

## Option B — Script (automated)

Requires Chrome Default profile logged into GitHub (close other Chrome windows first):

```bash
cd defensive-mcp-audit
npm install playwright
node scripts/upload_social_preview.mjs Stijnman/defensive-mcp-audit
```