"""
Self-Service Token Portal and OAuth Consent UI rendering.

Provides styled HTML pages for:
1. Self-service developer token portal (displaying streamable MCP URLs and config snippets).
2. Interactive OAuth 2.1 authorization consent screen.
"""

import html
import json
from typing import Optional

from starlette.responses import HTMLResponse


def render_portal_html(
    *,
    base_url: str,
    mcp_token: str,
    expires_in: int,
    user_hint: Optional[str] = None,
) -> str:
    """Render the self-service developer portal HTML page with configuration snippets."""
    safe_mcp_url = html.escape(f"{base_url}/mcp")
    safe_sse_url = html.escape(f"{base_url}/sse")
    safe_token = html.escape(mcp_token)
    safe_user = html.escape(user_hint or "Authenticated ServiceNow User")
    cursor_json = html.escape(
        json.dumps(
            {
                "mcpServers": {
                    "servicenow": {
                        "url": f"{base_url}/mcp",
                        "headers": {"Authorization": f"Bearer {mcp_token}"},
                    }
                }
            },
            indent=2,
        )
    )
    claude_json = html.escape(
        json.dumps(
            {
                "mcpServers": {
                    "servicenow": {
                        "command": "npx",
                        "args": [
                            "-y",
                            "mcp-remote",
                            f"{base_url}/sse",
                            "--header",
                            f"Authorization: Bearer {mcp_token}",
                        ],
                    }
                }
            },
            indent=2,
        )
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ServiceNow MCP — Self-Service Token Portal</title>
  <style>
    :root {{
      --bg: #0f172a;
      --card-bg: #1e293b;
      --card-border: #334155;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --accent-hover: #0ea5e9;
      --code-bg: #0b1120;
      --badge-bg: #064e3b;
      --badge-text: #34d399;
      --btn-bg: #334155;
      --btn-hover: #475569;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      background: var(--bg);
      color: var(--text-main);
      line-height: 1.6;
      padding: 2.5rem 1rem;
    }}
    .container {{
      max-width: 860px;
      margin: 0 auto;
    }}
    header {{
      margin-bottom: 2rem;
      border-bottom: 1px solid var(--card-border);
      padding-bottom: 1.5rem;
    }}
    .logo-row {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 0.75rem;
      flex-wrap: wrap;
      gap: 1rem;
    }}
    h1 {{
      font-size: 1.6rem;
      font-weight: 700;
      letter-spacing: -0.02em;
    }}
    .status-badge {{
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      background: var(--badge-bg);
      color: var(--badge-text);
      padding: 0.35rem 0.85rem;
      border-radius: 9999px;
      font-size: 0.85rem;
      font-weight: 600;
    }}
    .status-dot {{
      width: 8px;
      height: 8px;
      background: var(--badge-text);
      border-radius: 50%;
      box-shadow: 0 0 8px var(--badge-text);
    }}
    .user-info {{
      color: var(--text-muted);
      font-size: 0.95rem;
    }}
    .card {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
    }}
    .card-header {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 0.75rem;
    }}
    .card-title {{
      font-size: 1.15rem;
      font-weight: 600;
      color: var(--text-main);
    }}
    .copy-btn {{
      background: var(--btn-bg);
      color: var(--text-main);
      border: 1px solid var(--card-border);
      padding: 0.35rem 0.85rem;
      border-radius: 6px;
      font-size: 0.85rem;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.15s ease;
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
    }}
    .copy-btn:hover {{
      background: var(--btn-hover);
      border-color: var(--text-muted);
    }}
    .copy-btn.copied {{
      background: #064e3b;
      color: #34d399;
      border-color: #34d399;
    }}
    pre {{
      background: var(--code-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 1rem;
      overflow-x: auto;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.9rem;
      color: #e2e8f0;
      word-break: break-all;
      white-space: pre-wrap;
    }}
    code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      color: var(--accent);
      background: rgba(56, 189, 248, 0.1);
      padding: 0.15rem 0.35rem;
      border-radius: 4px;
      font-size: 0.88em;
    }}
    pre code {{
      background: transparent;
      padding: 0;
      color: inherit;
    }}
    .meta-list {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1rem;
      margin-bottom: 1rem;
    }}
    .meta-item {{
      background: var(--code-bg);
      padding: 0.75rem 1rem;
      border-radius: 8px;
      border: 1px solid var(--card-border);
    }}
    .meta-label {{
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      margin-bottom: 0.25rem;
    }}
    .meta-val {{
      font-family: ui-monospace, monospace;
      font-size: 0.9rem;
      word-break: break-all;
    }}
    .instructions {{
      font-size: 0.9rem;
      color: var(--text-muted);
      margin-bottom: 0.75rem;
    }}
    .logout-bar {{
      display: flex;
      justify-content: flex-end;
      margin-top: 2rem;
    }}
    .logout-btn {{
      background: transparent;
      color: #f87171;
      border: 1px solid #7f1d1d;
      padding: 0.5rem 1.25rem;
      border-radius: 6px;
      font-size: 0.9rem;
      cursor: pointer;
      transition: all 0.15s ease;
    }}
    .logout-btn:hover {{
      background: #7f1d1d;
      color: #fef2f2;
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo-row">
        <h1>ServiceNow MCP Server</h1>
        <div class="status-badge">
          <div class="status-dot"></div>
          Connected
        </div>
      </div>
      <p class="user-info">
        Signed in as <strong>{safe_user}</strong> • Session active for <strong>{int(expires_in)}s</strong> • Upstream token automatically refreshed
      </p>
    </header>

    <div class="card">
      <div class="card-header">
        <span class="card-title">1. Web AI Platforms (Dify / OpenWebUI / Agents)</span>
        <button class="copy-btn" onclick="copyId('raw-token', this)">Copy Token</button>
      </div>
      <p class="instructions">Use these values when configuring the MCP tool in Dify or your agent framework:</p>
      <div class="meta-list">
        <div class="meta-item">
          <div class="meta-label">Streamable HTTP URL (Recommended)</div>
          <div class="meta-val">{safe_mcp_url}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Server SSE URL (Legacy)</div>
          <div class="meta-val">{safe_sse_url}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Authorization Header</div>
          <div class="meta-val">Bearer {safe_token[:16]}...</div>
        </div>
      </div>
      <pre id="raw-token"><code>{safe_token}</code></pre>
    </div>

    <div class="card">
      <div class="card-header">
        <span class="card-title">2. Cursor & Windsurf Configuration</span>
        <button class="copy-btn" onclick="copyId('cursor-code', this)">Copy JSON</button>
      </div>
      <p class="instructions">Paste this into your <code>~/.cursor/mcp.json</code> or workspace <code>.cursor/mcp.json</code>:</p>
      <pre id="cursor-code"><code>{cursor_json}</code></pre>
    </div>

    <div class="card">
      <div class="card-header">
        <span class="card-title">3. Claude Desktop Configuration</span>
        <button class="copy-btn" onclick="copyId('claude-code', this)">Copy JSON</button>
      </div>
      <p class="instructions">Paste this into <code>~/Library/Application Support/Claude/claude_desktop_config.json</code>:</p>
      <pre id="claude-code"><code>{claude_json}</code></pre>
    </div>

    <div class="logout-bar">
      <form action="/auth/logout" method="post">
        <input type="hidden" name="token" value="{safe_token}" />
        <button type="submit" class="logout-btn">Log Out & Revoke Token</button>
      </form>
    </div>
  </div>

  <script>
    function copyText(text, btn) {{
      navigator.clipboard.writeText(text).then(() => {{
        const original = btn.innerText;
        btn.innerText = "Copied!";
        btn.classList.add("copied");
        setTimeout(() => {{
          btn.innerText = original;
          btn.classList.remove("copied");
        }}, 2000);
      }});
    }}
    function copyId(id, btn) {{
      const el = document.getElementById(id);
      if (el) {{
        copyText(el.innerText, btn);
      }}
    }}
  </script>
</body>
</html>"""


# Backward-compatibility alias
_render_portal_html = render_portal_html


def render_portal_response(
    *,
    base_url: str,
    mcp_token: str,
    expires_in: int,
    user_hint: Optional[str] = None,
) -> HTMLResponse:
    """Render the developer portal as an HTMLResponse with Cache-Control: no-store."""
    content = render_portal_html(
        base_url=base_url,
        mcp_token=mcp_token,
        expires_in=expires_in,
        user_hint=user_hint,
    )
    return HTMLResponse(
        content=content,
        status_code=200,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


def render_consent_html(
    *,
    client_name: str,
    client_id: str,
    redirect_uri: str,
    approve_url: str,
    deny_url: str,
) -> str:
    """
    Render the OAuth 2.1 authorization consent screen.

    Displays client identity details and provides Approve and Deny actions.
    """
    safe_client_name = html.escape(client_name)
    safe_client_id = html.escape(client_id)
    safe_redirect_uri = html.escape(redirect_uri)
    safe_approve_url = html.escape(approve_url)
    safe_deny_url = html.escape(deny_url)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Authorize ServiceNow MCP Access</title>
  <style>
    :root {{
      --bg: #0f172a;
      --card-bg: #1e293b;
      --card-border: #334155;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --code-bg: #0b1120;
      --btn-approve-bg: #0284c7;
      --btn-approve-hover: #0369a1;
      --btn-deny-bg: #334155;
      --btn-deny-hover: #475569;
      --btn-deny-border: #64748b;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      background: var(--bg);
      color: var(--text-main);
      line-height: 1.6;
      padding: 3rem 1rem;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }}
    .container {{
      max-width: 540px;
      width: 100%;
    }}
    .card {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 14px;
      padding: 2rem;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.4);
    }}
    header {{
      margin-bottom: 1.5rem;
      text-align: center;
    }}
    h1 {{
      font-size: 1.5rem;
      font-weight: 700;
      letter-spacing: -0.02em;
      margin-bottom: 0.5rem;
    }}
    .subtitle {{
      color: var(--text-muted);
      font-size: 0.95rem;
    }}
    .client-details {{
      background: var(--code-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 1.25rem;
      margin-bottom: 1.75rem;
    }}
    .detail-row {{
      display: flex;
      flex-direction: column;
      margin-bottom: 0.85rem;
    }}
    .detail-row:last-child {{
      margin-bottom: 0;
    }}
    .detail-label {{
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      margin-bottom: 0.2rem;
    }}
    .detail-val {{
      font-size: 0.95rem;
      color: var(--text-main);
      word-break: break-all;
    }}
    code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      color: var(--accent);
      font-size: 0.9em;
    }}
    .actions {{
      display: flex;
      gap: 1rem;
      margin-top: 1.5rem;
    }}
    .btn {{
      flex: 1;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0.75rem 1rem;
      border-radius: 8px;
      font-size: 0.95rem;
      font-weight: 600;
      text-decoration: none;
      cursor: pointer;
      transition: all 0.15s ease;
      text-align: center;
    }}
    .btn-approve {{
      background: var(--btn-approve-bg);
      color: #ffffff;
      border: 1px solid transparent;
    }}
    .btn-approve:hover {{
      background: var(--btn-approve-hover);
    }}
    .btn-deny {{
      background: var(--btn-deny-bg);
      color: #f87171;
      border: 1px solid var(--btn-deny-border);
    }}
    .btn-deny:hover {{
      background: var(--btn-deny-hover);
      color: #fca5a5;
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="card">
      <header>
        <h1>Authorize ServiceNow MCP Access</h1>
        <p class="subtitle">An application is requesting access to your ServiceNow instance.</p>
      </header>

      <div class="client-details">
        <div class="detail-row">
          <span class="detail-label">Application</span>
          <span class="detail-val"><strong>{safe_client_name}</strong></span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Client ID</span>
          <span class="detail-val"><code>{safe_client_id}</code></span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Redirect URI</span>
          <span class="detail-val"><code>{safe_redirect_uri}</code></span>
        </div>
      </div>

      <div class="actions">
        <a href="{safe_deny_url}" class="btn btn-deny">Deny</a>
        <a href="{safe_approve_url}" class="btn btn-approve">Approve</a>
      </div>
    </div>
  </div>
</body>
</html>"""


def render_consent_response(
    *,
    client_name: str,
    client_id: str,
    redirect_uri: str,
    approve_url: str,
    deny_url: str,
) -> HTMLResponse:
    """Render the OAuth consent screen as an HTMLResponse with Cache-Control: no-store."""
    content = render_consent_html(
        client_name=client_name,
        client_id=client_id,
        redirect_uri=redirect_uri,
        approve_url=approve_url,
        deny_url=deny_url,
    )
    return HTMLResponse(
        content=content,
        status_code=200,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )
