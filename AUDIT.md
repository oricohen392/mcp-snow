# AUDIT: servicenow-mcp for Dify (SSE), air-gapped OpenShift

## Scope and method

- **Upstream:** `https://github.com/echelon-ai-labs/servicenow-mcp`. The README badges point to `osomai/servicenow-mcp`. `git ls-remote` on 2026-10-11 showed both repositories at the same HEAD, so they are the same project.
- **Pinned start commit:** `06250607bdfc814f9bb56551bba16c3a7fb5a8c9` ("Fixed repo url in README.md (#41)").
- **Working branch:** `feature/itsm-query-hardening`.
- **Method:**
  - Read all of `src/`, `pyproject.toml`, `uv.lock`, `config/tool_packages.yaml`, `Dockerfile` and `tests/`.
  - Ran the code in a `python:3.11-slim` container with the dependency versions from `uv.lock`.
- **What was not available:** a real ServiceNow instance and a real Dify. Nothing in this document has been verified against a live instance. "Confirmed" means one of two things:
  - confirmed by reading the code (file:line), or
  - confirmed by running the code locally against mocks.

Line numbers refer to the pinned commit `0625060`.

---

## Part 1: Pre-change findings

### Items given as already verified (re-checked)

| # | Status | Evidence |
|---|---|---|
| 1 | **Confirmed** | `tools/incident_tools.py:69-77`: `ListIncidentsParams` has only limit, offset, state, assigned_to, category, query. There is no `assignment_group`. |
| 2 | **Confirmed** | `incident_tools.py:487-492`: values are interpolated raw (`state=<v>`, `assigned_to=<v>`, `category=<v>`). `assigned_to` is a reference field, so `assigned_to=John Doe` compares against a sys_id and never matches a name. |
| 3 | **Refuted as stated (per docs, not live-verified)** | `incident_tools.py:494,497` builds `...^short_descriptionLIKEq^ORdescriptionLIKEq`. Under ServiceNow encoded-query semantics, `^OR` binds to the immediately preceding condition, so `state=1^sdLIKEq^ORdescLIKEq` means `state=1 AND (sd LIKE q OR desc LIKE q)`. That is correct. The real risks are item 4 (a value containing `^OR`/`^NQ` rewrites the query) and the raw passthrough in `change_tools.py:446-447`. The fix still makes OR groups atomic and adds structural tests. **Must verify manually** (see Part 3). |
| 4 | **Confirmed** | No sanitization anywhere. Same pattern in `incident_tools.py:488-494`, `change_tools.py:426-447` (the `query` param is appended verbatim **by design**: "Additional query string"), and `user_tools.py:382-447`. |
| 5 | **Confirmed** | `incident_tools.py:72,478-483`: no date filters, no `ORDERBY`, `limit` is not capped, and `X-Total-Count` is not read. `change_tools.py:492` sets `"total": count` (the page size, not the total). |
| 6 | **Confirmed** | `incident_tools.py:500-545`: the sent query is not logged. HTTP 200 with an empty `result` becomes `"Found 0 incidents"`. Only `logger.error` runs on exceptions. |
| 7 | **Confirmed** | `incident_tools.py:481`: `sysparm_display_value=true`, so `state` comes back as `"New"`. Feeding `"New"` back into `state=` matches nothing. |
| 8 | **Confirmed** | `incident_tools.py:95-456` (create/update/add_comment/resolve) sit next to the list/get tools and are all in the `full` and `service_desk` packages (`config/tool_packages.yaml`). `resolve_incident` hard-codes `state=6` (`incident_tools.py:426`). |

### Items to verify

**9. LOG_LEVEL / logging: confirmed not honored.**
- `LOG_LEVEL` is not read anywhere in `src/` (grep).
- `server.py:28` calls `logging.basicConfig(level=logging.INFO)` **at import time**.
- `cli.py:25-28` configures INFO, and `cli.py:255-259` switches to DEBUG only through `--debug`/`SERVICENOW_DEBUG`.
- `server_sse.py:124-138` (the Dify entrypoint) never configures logging, so it inherits the import-time INFO from `server.py`.
- Related leak: `auth/auth_manager.py:113,133` logs the **OAuth token response body** (which contains `access_token`) at INFO.
- Basic auth headers are not logged anywhere.

**10. change_request / sc_request / sc_req_item.**
- `change_request`: tools exist (`tools/change_tools.py`) and have the same problems, plus some of their own:
  - Raw `state`/`type`/`category` (`:426-431`).
  - `assignment_group=<v>` is an exact match on the reference value, so a group *name* doesn't match (`:432-433`).
  - No date filters except `timeframe`, which uses the pod's local naive time (`datetime.now()`, `:437`).
  - `query` is a raw encoded-query passthrough (`:446-447`).
  - No timeout on any `requests` call (`:284,378,479,554,566,651,729,740,811,835`), so a hung instance blocks the tool forever.
  - `get_change_request_details` only accepts a sys_id: it is put in the URL path (`:547`), so `CHG0030001` returns 404.
  - **Argument-order bug:** every change tool is declared as `(auth_manager, server_config, params)`, but `server.py:277` calls `impl(self.config, self.auth_manager, params)`. It works only by accident, because `_get_instance_url`/`_get_headers` (`:161-206`) duck-type whichever object has `instance_url`/`get_headers`.
- **sc_request / sc_req_item: confirmed absent.** No tool touches either table (grep `sc_request|sc_req_item`: no hits).

**11. MCP_TOOL_PACKAGE: confirmed silent failure, and the most likely cause of "connected but no tools".**
- `server.py:32`: `TOOL_PACKAGE_CONFIG_PATH` defaults to `config/tool_packages.yaml`, resolved relative to `src/servicenow_mcp/../../` (`server.py:124-126`).
- If the file is missing or unparsable, `package_definitions = {}` and only `logger.error` runs (`:139-151`).
- `_determine_enabled_tools` (`:153-177`) then treats the default `"full"` as invalid and falls back to `"none"`. `_list_tools_impl` (`:184`) also hides `list_tool_packages` under `"none"`.
- **Result: zero tools, and the server still accepts connections.** Reproduced locally:

  | Scenario | Package | tools/list |
  |---|---|---|
  | config present | full | 83 tools |
  | config missing | none | **0** |
  | `MCP_TOOL_PACKAGE=servicedesk` (typo) | none | **0** |

- The upstream `Dockerfile` does **not** copy `config/` (your local edit adds `COPY config/`), so an image built from upstream serves 0 tools.
- Any non-editable install (`pip install .`/wheel) also loses the file, because it is not packaged.
- The `full` package lists 11 tools that do not exist, and they are silently ignored: `create_catalog_item`, `create_catalog_variable_choice`, `create_ui_policy`, `create_ui_policy_action`, `create_user_criteria`, `create_user_criteria_condition`, `delete_catalog_item_variable`, `execute_script_include`, `get_syslog_entry`, `list_catalogs`, `list_syslog_entries`.

**12. SSE app: confirmed.**
- `server_sse.py:24-46`: `GET /sse` (event stream) and `POST /messages/?session_id=…` (via `SseServerTransport("/messages/")`). The `endpoint` event sends the **relative** path `/messages/?session_id=<hex>` (mcp 1.3.0 `server/sse.py:98`), so any reverse-proxy path prefix breaks the second leg.
- **No endpoint authentication of any kind.**
- `Starlette(debug=True)` (`:75`) returns tracebacks to clients.
- Defaults are host `0.0.0.0`, port `8080` (`:129-130`).
- Only Basic auth is supported, read from `SERVICENOW_INSTANCE_URL/USERNAME/PASSWORD` (`:133-137`). `SERVICENOW_TIMEOUT` is ignored (the default 30 s is used). Missing variables raise a pydantic `ValidationError` traceback instead of a clear message.
- Sessions live in process memory, so the server cannot scale beyond **one replica** without sticky sessions.
- mcp 1.3.0 advertises protocol `2024-11-05` (`mcp/types.py:32`).
- An unused `from mcp.server.fastmcp import FastMCP` (`:14`) is imported.
- The upstream branch `origin/fix/sse-auth-hardening` (c77861e) adds bearer auth and a host allowlist, but also bumps `mcp` to `>=1.23`. It is not used as a base here.

**13. Tool JSON schema: confirmed constructs; Dify impact unconfirmed.**
- Schemas come straight from `params_model.model_json_schema()` (`server.py:209`). Every `Optional[str] = None` field becomes:
  ```json
  {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null, "title": "State", "description": "Filter by incident state"}
  ```
  It has no top-level `type`.
- Descriptions are minimal ("Filter by incident state") and give no valid values or examples.
- `list_tool_packages` declares a **required** dummy parameter `random_string` (`server.py:191-197`).
- **What Dify does with this:** current Dify `main` (`api/services/tools/tools_transform_service.py`, `resolve_property_type`) walks `anyOf`/`oneOf` and skips `null`, so current Dify parses these schemas. I could **not** confirm the behavior of the Dify version you run (it is not known here), and I did not check older Dify releases line by line.
- **"Connected but no tools" is fully explained by item 11** (a missing config, or a package-name typo, produces an empty `tools/list`) without needing a schema problem.
- The fix flattens `anyOf[X, null]` to `X` anyway, as a cheap defensive measure.

**14. Dockerfile: confirmed issues.**
- Upstream `Dockerfile`:
  - single stage, `python:3.11-slim`
  - runs as **root**
  - `pip install -e .` (editable: the source tree must stay at `/app/src`)
  - does not copy `config/` (see item 11)
  - no `.dockerignore`, so the build context includes `.git`, `.env` and anything else in the folder (here, a 74 MB `snow-mcp.tar`)
- Under the OpenShift `restricted` SCC (random UID, GID 0), the image has no group-0-writable `HOME`, no non-root `USER`, and nothing sets `PYTHONDONTWRITEBYTECODE`.
- **Dependency resolution is broken without the lock:**
  - `pyproject.toml` pins `mcp[cli]==1.3.0` but leaves `pydantic` unbounded. A fresh `pip install .` today resolves pydantic 2.14, and `import mcp.server` then fails (`ImportError: cannot import name 'eval_type_backport'`, raised from `mcp/server/fastmcp/utilities/func_metadata.py`). The server cannot start.
  - `uv.lock` pins a working set (pydantic 2.10.6, starlette 0.46.0, …), but it is **stale**: it lacks `PyYAML`, which `pyproject.toml` requires and `server.py:13` imports.
  - Your current image works only because it happened to resolve compatible versions when it was built.

### Other findings (not in the original list)

- `user_tools.py:387,447`: `list_users`/`list_groups` build `"^nameLIKE…"` and then join with `^`, producing `active=true^^nameLIKE…` (an empty term).
- `server.py:264-281`: argument-validation errors are re-raised as `ValueError`. mcp 1.3.0 turns them into `isError=true` results (`lowlevel/server.py:415-419`), which is acceptable.
- **Pre-existing test failures at `0625060`**, before any change: 3 test modules fail at import (`tests/test_catalog_resources.py`, `tests/test_changeset_resources.py`, `tests/test_script_include_resources.py` import the non-existent `servicenow_mcp.resources`). Of the rest: **121 passed, 10 failed, 5 errors**.
  - Failing tests are in `test_change_tools.py` (2 "swapped parameters" tests), `test_knowledge_base.py` (1), `test_server_catalog.py` (5), `test_server_workflow.py` (1) and `test_workflow_tools.py` (1).
  - The errors are in `test_workflow_tools_direct.py` (5, missing fixtures).
  - None of these touch code changed on this branch. They are left as they are.

---

## Part 2: Changes on this branch

_Filled in as commits land; see the end of the document._
