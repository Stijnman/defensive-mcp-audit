#!/usr/bin/env bash
# Finish GitHub social preview + PyPI trusted publisher via Kimi WebBridge.
set -euo pipefail
API="http://127.0.0.1:10086/command"
IMAGE="/home/linuxmint/defensive-mcp-audit/.github/social-preview.png"
REPO="Stijnman/defensive-mcp-audit"

wb() {
  curl -s -X POST "$API" -H 'Content-Type: application/json' -d "$1"
}

wb_val() {
  wb "$1" | python3 -c "import json,sys; d=json.load(sys.stdin); print(json.loads(d['data']['value']))" 2>/dev/null
}

wait_github_login() {
  echo "Waiting for GitHub login in WebBridge 'Repo Setup' tab..."
  for _ in $(seq 1 60); do
    if [ "$(wb_val '{"action":"evaluate","args":{"code":"JSON.stringify(!location.href.includes(\"/login\"))"},"session":"repo-setup"}')" = "True" ]; then
      echo "GitHub logged in."
      return 0
    fi
    sleep 5
  done
  echo "GitHub login timeout — sign in on the Repo Setup tab first." >&2
  return 1
}

upload_social_preview() {
  python3 - <<'PY'
import base64, json, pathlib, subprocess, tempfile

api = "http://127.0.0.1:10086/command"
img = pathlib.Path("/home/linuxmint/defensive-mcp-audit/.github/social-preview.png")
b64 = base64.b64encode(img.read_bytes()).decode()
code = f"""(async () => {{
  const b64 = `{b64}`;
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  const file = new File([arr], 'social-preview.png', {{ type: 'image/png' }});
  const input = document.querySelector('#repo-image-file-input');
  if (!input) return JSON.stringify({{error:'no input'}});
  const dt = new DataTransfer();
  dt.items.add(file);
  input.files = dt.files;
  input.dispatchEvent(new Event('change', {{ bubbles: true }}));
  await new Promise(r => setTimeout(r, 5000));
  const imageId = document.querySelector('input.js-repository-image-id')?.value || '';
  return JSON.stringify({{imageId}});
}})()"""
payload = {"action": "evaluate", "args": {"code": code}, "session": "repo-setup"}
with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
    json.dump(payload, fh)
    payload_path = fh.name
subprocess.run(
    ["curl", "-s", "-X", "POST", api, "-H", "Content-Type: application/json", "-d", f"@{payload_path}"],
    check=True,
)
PY
  echo "Social preview upload attempted."
}

wait_pypi_login() {
  echo "Waiting for PyPI login in WebBridge 'PyPI Setup' tab..."
  for _ in $(seq 1 120); do
    if [ "$(wb_val '{"action":"evaluate","args":{"code":"JSON.stringify(!location.pathname.includes(\"/login\"))"},"session":"pypi-setup"}')" = "True" ]; then
      echo "PyPI logged in."
      return 0
    fi
    sleep 5
  done
  echo "PyPI login timeout — sign in on the PyPI Setup tab first." >&2
  return 1
}

configure_pypi_publisher() {
  wb '{"action":"navigate","args":{"url":"https://pypi.org/manage/account/publishing/","newTab":false},"session":"pypi-setup"}' >/dev/null
  sleep 3
  result=$(wb '{"action":"evaluate","args":{"code":"(() => { const f=document.querySelector(\"#pending-github-publisher-form\"); if(!f) return JSON.stringify({error:\"no-form\", url:location.href}); const set=(id,v)=>{const el=f.querySelector(`#${id}, [name=${id}]`); if(el) el.value=v;}; set(\"project_name\",\"defensive-mcp-audit\"); set(\"owner\",\"Stijnman\"); set(\"repository\",\"defensive-mcp-audit\"); set(\"workflow_filename\",\"release.yml\"); set(\"environment\",\"pypi\"); const btn=f.querySelector(\"input[type=submit], button[type=submit]\"); if(btn && !btn.classList.contains(\"button--disabled\")) { btn.click(); return JSON.stringify({submitted:true}); } return JSON.stringify({filled:true, disabled: btn?.classList?.contains(\"button--disabled\")}); })()"},"session":"pypi-setup"}' | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['data']['value'])" 2>/dev/null)
  echo "PyPI publisher form: $result"
  sleep 3
  wb '{"action":"evaluate","args":{"code":"JSON.stringify({url:location.href, pending:[...document.querySelectorAll(\"table.table--publisher-list tbody tr\")].map(r=>r.textContent.trim())})"},"session":"pypi-setup"}' | python3 -m json.tool
}

main() {
  curl -s -X POST "$API" -H 'Content-Type: application/json' \
    -d '{"action":"navigate","args":{"url":"https://github.com/Stijnman/defensive-mcp-audit/settings","newTab":true,"group_title":"Repo Setup"},"session":"repo-setup"}' >/dev/null
  curl -s -X POST "$API" -H 'Content-Type: application/json' \
    -d '{"action":"navigate","args":{"url":"https://pypi.org/account/login/?next=%2Fmanage%2Faccount%2Fpublishing%2F","newTab":true,"group_title":"PyPI Setup"},"session":"pypi-setup"}' >/dev/null

  if wait_github_login; then
    upload_social_preview
  fi

  if wait_pypi_login; then
    configure_pypi_publisher
    echo "Triggering PyPI republish workflow..."
    gh workflow run release.yml --ref main -R "$REPO" || true
  fi

  echo "Done. Verify: pip index versions defensive-mcp-audit"
}

main "$@"