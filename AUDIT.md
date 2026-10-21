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

**Verification status: unit-tested and mock-tested only.** No request on this branch has been sent to a real ServiceNow instance or made by a real Dify. Everything below was verified one of three ways:
- pytest with mocked HTTP,
- the Docker image run locally against an unreachable placeholder instance (`example.invalid`),
- the MCP Python client 1.3.0 talking to that container over SSE.

### Commits (`0625060..feature/itsm-query-hardening`)

| Commit | Topic |
|---|---|
| `docs: add AUDIT.md` | Part 1 of this file |
| `logging: … (J)` | `LOG_LEVEL`; `utils/http.py` (`sn_get`: timeout, `CA_BUNDLE`, `X-Total-Count`, typed errors, DEBUG request log); OAuth token body no longer logged |
| `query: … (E, F)` | `utils/query.py`: `sanitize_value`, `split_list`, `QueryBuilder` with atomic OR groups |
| `choices: … (B)` | `utils/choices.py`: label → value through `sys_choice`, TTL cache, fallback to `task` |
| `dates: … (C)` | `utils/dates.py`: ISO → UTC, `timezone` / `DEFAULT_TIMEZONE`; `tzdata` dependency |
| `tools: shared task list engine … (A, D, G, I)` | `tools/ticket_query.py`; incident/change rewired; new `request_tools.py`, `search_groups` |
| `tools: add check_access (H)` | `tools/access_tools.py` |
| `server: READ_ONLY … (K, L)` | read-only default, loud package/config errors, packaged YAML, `^` guard, null-free schemas |
| `sse: … (M)` | optional Bearer auth, `/healthz`, `debug=False`, fail-fast startup |
| `packaging: … (N)` | multi-stage Dockerfile, wheelhouse script, `requirements.lock`, `k8s/`, README |
| `smoke: …` | `servicenow-mcp-smoke` / `scripts/smoke_test.py` |

### What each fix does

- **A. Group filters.** All four list tools now take:
  - `assignment_group`: `assignment_group.nameLIKE<v>`. Comma-separated values, a JSON array or a list become an OR group. A 32-hex value is treated as an exact sys_id.
  - `assignment_group_exact`: `assignment_group.name=<v>` (OR for several).
  - `assigned_to`: `assigned_to.nameLIKE<v>^ORassigned_to.user_name=<v>`, or a sys_id.
  - New tool `search_groups(name_part)` on `sys_user_group`.
  - Test: `"NOC"` → `assignment_group.nameLIKENOC^ORDERBYDESCsys_created_on`.
- **B. Label resolution.** Applies to state, priority and category (incident); state, type, risk, priority and category (change); state, request_state and priority (sc_request); state, stage and priority (sc_req_item).
  - Matching order: value, then case-insensitive label, then label without a leading `N - ` prefix.
  - Unknown input returns an error listing every `Label (value)` pair.
  - No state numbers are hard-coded.
  - If `sys_choice` is unreadable: numeric fields accept numeric values (with a warning) and reject labels with a clear message; string fields pass through with a warning.
- **C. Dates.**
  - `created_after/before` and `updated_after/before` on all four tables; `start_after/before` and `end_after/before` on change.
  - Input without an offset is read in `timezone` (else `DEFAULT_TIMEZONE`) and sent as UTC `YYYY-MM-DD HH:MM:SS`.
  - `_after` means `>=`, `_before` means `<`.
  - `timeframe` now uses UTC and rejects unknown values.
- **D. Number.**
  - `number` filter (list → `numberIN…`) with prefix validation `^(INC|CHG|REQ|RITM)\d+$`.
  - Exact get tools: `get_incident_by_number`, `get_request_by_number`, `get_request_item_by_number`.
  - `get_change_request_details` now accepts a CHG number as well as a sys_id.
- **E. Sanitization.** Every user value goes through `sanitize_value`, which rejects:
  - `^`
  - control characters (newline, tab, NUL, ESC, DEL)
  - empty values, and values over 200 characters
  - commas inside `IN` lists

  Field names and operators are whitelisted. As defense in depth, the server rejects `^` in any string argument of any read tool, including the older catalog/KB/user tools.
- **F. Precedence.** Free text becomes one atomic group, `short_descriptionLIKEq^ORdescriptionLIKEq`. Tests assert that every OR group is contiguous and that no term starts with `^OR`.
- **G. Transparency.**
  - Every list response adds `query_used`, `total_count`, `returned`, `limit` and `offset`. `limit_capped` and `warnings` appear when relevant.
  - Get-by-number responses add `query_used`.
  - HTTP 200 with no rows adds a `hint` explaining the ACL/domain possibility and pointing to `check_access`.
  - When `X-Total-Count` is larger than what was returned, a row-ACL hint is added.
  - 401, 403, 404, 5xx, timeouts, connection errors and non-JSON (SSO page) responses return `success:false` with `status_code` and `error_type`. ServiceNow's error body is included when present.
  - Existing keys are kept: `incidents`, `message: "Found N incidents"`, and `change_requests`/`count`/`total`. `total` is now `X-Total-Count` when available.
- **H. `check_access`.** Reports:
  - instance host
  - configured and verified user (`sys_user`, domain, and roles from `sys_user_has_role` when readable)
  - per table (incident, change_request, sc_request, sc_req_item, sys_user_group, sys_choice): HTTP status, readable, and `visible_count` from `X-Total-Count`

  If nothing is readable, it returns `success:false`.
- **I. Limits and ordering.**
  - `MAX_LIMIT` (default 100) clamps `limit`.
  - `order_by` comes from a per-table whitelist: `sys_created_on, sys_updated_on, opened_at, number, priority, state`, plus `start_date`/`end_date` for change and `due_date` for requests.
  - `descending` defaults to true.
  - Default ordering is `ORDERBYDESCsys_created_on`.
- **J. Logging.**
  - `LOG_LEVEL` is honored by both entrypoints. An invalid value fails startup; `SERVICENOW_DEBUG=true` still means DEBUG.
  - At DEBUG, every ServiceNow GET logs method, path, sysparm params, status, elapsed ms and `X-Total-Count`.
  - The Authorization header, password and OAuth token are never logged (covered by tests).
  - Each list call logs its `query_used` at INFO.
- **K. Read-only and package loading.**
  - `READ_ONLY` defaults to true. Only tools named `list_*`, `get_*`, `search_*` or `check_*` are registered; write tools need `READ_ONLY=false`.
  - An invalid `MCP_TOOL_PACKAGE`, or a missing or malformed YAML, raises at startup (exit code 2 from `servicenow-mcp-sse`).
  - `tool_packages.yaml` is shipped inside the wheel.
  - Package entries that don't match any tool are logged as a WARNING.
- **L. Schemas and descriptions.**
  - `anyOf[X, null]` is collapsed to `X`; `default: null` and `title` are dropped.
  - `list_tool_packages` no longer requires `random_string`.
  - Every ITSM parameter description has examples and valid values, and states that labels come from the instance. Checked by a test and by the in-container MCP `tools/list`, which shows no `anyOf` in any of the 36 schemas.
  - List inputs are typed as `string` (comma-separated) to avoid array or union schemas. JSON arrays and real lists are also accepted.
- **M. Endpoint auth.**
  - With `MCP_AUTH_TOKEN` set, `/sse` and `/messages/` require `Authorization: Bearer` (constant-time compare). Without it, a WARNING at startup says the endpoints are unauthenticated.
  - `/healthz` is always open.
  - Starlette `debug=False`.
- **N. Packaging.**
  - Multi-stage Dockerfile with a non-editable wheel install in `/opt/venv`.
  - Runs as UID 1001, and works under an arbitrary UID in group 0 with a read-only root filesystem (both verified locally).
  - No source, `.git` or `.tar` in the final image (verified).
  - `scripts/download_wheels.sh` plus `--build-arg OFFLINE=1`: verified with `docker build --network=none`.
  - `requirements.lock`.
  - `k8s/` manifests.
  - `CA_BUNDLE` support.

### Deliberate behavior changes (not strictly backward compatible)

1. `list_change_requests`:
   - `query` was a raw encoded query appended verbatim; it is now free text over short_description and description.
   - `assignment_group` was exact (sys_id) equality; it is now a partial name match (a sys_id still matches exactly).
   - `state`, `type` and `category` labels are now resolved.

   The one existing test that pinned the old raw behavior (`test_list_change_requests_with_filters`) was updated.
2. Write tools are hidden unless `READ_ONLY=false`.
3. An invalid `MCP_TOOL_PACKAGE`, or a missing tool config, now stops the server instead of serving zero tools.
4. `pyproject.toml` bounds `pydantic<2.14`: mcp 1.3.0 fails to import with 2.14 (bisected: 2.13.0 works, 2.14.0 does not).
5. `uv.lock` was re-locked (it lacked PyYAML). The only additions are pyyaml 6.0.3 and tzdata; every other pin is unchanged.

### Not changed / remaining risks

- The other tool modules (catalog, knowledge base, workflow, user, agile, …) still interpolate raw values into `sysparm_query`. Read tools are covered by the server-level `^` guard. Write tools are not, and they are only reachable with `READ_ONLY=false`. The `^^nameLIKE` construction in `user_tools.py:387,447` is still there.
- `tool_packages.yaml` still lists the 11 non-existent tools. They are now reported at startup instead of ignored silently.
- MCP stays at 1.3.0: SSE transport only (no streamable HTTP) and protocol `2024-11-05`. The `endpoint` event still uses a relative `/messages/` path, so a reverse proxy that adds a path prefix breaks it.
- The SSE entrypoint supports Basic auth only, as before. OAuth/API-key configuration exists only in the stdio CLI.
- The 15 pre-existing failing tests and 3 un-importable test modules (Part 1) are untouched.

### Test results

Run in `python:3.11-slim` with the dependency versions in `requirements.lock`, ignoring the 3 test modules that can't be imported at baseline:

```
baseline (0625060):  121 passed, 10 failed, 5 errors
this branch (HEAD):  331 passed, 10 failed, 5 errors
```

The set of failing and erroring test IDs is **identical** to the baseline (diffed). There are 210 new tests:

| File | Tests | Covers |
|---|---|---|
| `test_sanitize.py` | 30 | injection strings (`foo^ORnumberISNOTEMPTY`, `x^NQ…`, `^ORDERBY`, CR/LF/TAB/NUL/ESC/DEL), length, list parsing |
| `test_query_precedence.py` | 5 | OR-group atomicity, ORDERBY last, IN |
| `test_query_builder.py` | 34 | group partial/OR/exact/sys_id on all 4 tables, labels, dates with timezone, numbers and prefixes, injection before any HTTP call, limit cap, order whitelist, timeout and CA bundle passed |
| `test_choices.py` | 8 | label/value/`1 - Critical`, unknown label lists valid ones, TTL expiry, `task` fallback, `sys_choice` 403 |
| `test_dates.py` | 16 | Z/offset/naive, Asia/Jerusalem DST and winter, `DEFAULT_TIMEZONE`, invalid input |
| `test_list_tools_http.py` | 79 | every list/get tool × {200-empty, 200-rows, 401, 403, 500, read/connect timeout, connection error, non-JSON}, not-found hint |
| `test_check_access.py` | 6 | identity, roles, per-table counts, 401/403/500/timeout everywhere |
| `test_server_startup.py` | 14 | READ_ONLY default/false/invalid, hidden write-tool call, bad package, missing/invalid config, packaged config, schema flattening, `^` guard |
| `test_sse_auth.py` | 8 | 401 without or with a wrong token on `/sse` and `/messages/`, `/healthz` open, no-token mode, `debug=False` |
| `test_logging_redaction.py` | 8 | `LOG_LEVEL`, DEBUG request log content, no Authorization/password/OAuth token in logs |
| `test_smoke_test.py` | 2 | smoke test PASS on rows, FAIL on 401, never prints the password |

### Container verification (local Docker, placeholder instance `https://example.invalid`)

- `docker run --user 123456:0 --read-only --tmpfs /tmp …`:
  - `/healthz` returns 200.
  - The packaged config loads from site-packages.
  - Log line: `Tool package 'full': 35 tools enabled, READ_ONLY=true, 53 write tools hidden.`
- `servicenow-mcp-smoke --mcp-only --mcp-url http://localhost:8080/sse` connected with protocol `2024-11-05` and `tools/list` returned 36 tools (35 plus `list_tool_packages`), none using `anyOf`.
- With `MCP_AUTH_TOKEN`:
  - `GET /sse` without a token returns 401; `/healthz` returns 200.
  - The MCP client with a wrong token fails with 401; with the right token it lists 36 tools.
- `MCP_TOOL_PACKAGE=servicedesk` exits with code 2 and lists the valid names. Missing `SERVICENOW_*` variables also exit with code 2.
- The ServiceNow checks against the unreachable host report `FAILED (connection)` with `query_used` for every call. They are never reported as 0 results.
- `docker build --network=none --build-arg OFFLINE=1` succeeds from `wheelhouse/`.

---

## Part 3: Assumptions about your ServiceNow instance (verify manually)

None of these could be checked here. Run `servicenow-mcp-smoke` in the pod first; it answers several of them.

1. **`sys_choice` is readable** by the integration user (`check_access` → `tables.sys_choice.readable`). If it isn't, labels such as "New" cannot be translated for numeric fields; numeric values still work.
2. **Choice rows location.**
   - `incident.state` and `change_request.state/type/risk` have rows under their own table name.
   - `priority`, and `state` on sc_request/sc_req_item, are inherited from `task`; the resolver falls back to `name=task`.
   - Customized or extended choice lists on a child table are used as-is.
3. **Choice labels are in the account's language.** Labels from all languages are accepted. The same label mapping to two values returns an "ambiguous" error.
4. **`LIKE` is case-insensitive** on your database, so `noc` finds `INOC_1`. This is the default for ServiceNow's MySQL/MariaDB collations, but compare `search_groups("noc")` with `search_groups("NOC")` to confirm.
5. **Datetime literals in `sysparm_query` are compared in UTC** (the internal GlideDateTime value), not in the integration user's timezone. Check: pick a record, convert its `sys_created_on` to UTC, and query `created_after` one minute before and after it.
6. **`^OR` precedence (item 3):** `A^B^ORC` is `A AND (B OR C)`. Check by pasting a `query_used` into a list URL (`incident_list.do?sysparm_query=…`) and reading the breadcrumb.
7. **Number prefixes are INC / CHG / REQ / RITM** (`sys_number`). If you changed them, the prefix validation in `tools/ticket_query.py` (`TableSpec.number_prefix`) must be adjusted.
8. **`X-Total-Count` and row-level ACLs:** whether the header counts rows before or after "security constraints" removal. If `total_count` > `returned` on a page that isn't full, rows are being hidden.
9. **Domain separation.** If it is enabled, the service account only sees its own domain (`check_access` → `user.domain`), and an empty result can be correct.
10. **`sc_request`:** whether your process uses `request_state`, `state`, or both. The tool supports both filters.
11. **Group names contain no commas**, since a comma separates the OR values. Otherwise pass a JSON array: `'["Name, with comma"]'`.
12. **`assignment_group.name` is the display name** you see in lists. The display value comes from `sysparm_display_value=true`.
13. **Dify:**
    - Its version parses the tool schemas. They are now flat, but your exact version is unverified.
    - It is configured with the **SSE** URL `http://<service>:8080/sse`. This server does not offer streamable HTTP.
    - Your version can send a custom `Authorization` header if you set `MCP_AUTH_TOKEN`. If it can't, leave the token unset and rely on the NetworkPolicy.
14. **Network and TLS:** the pod resolves and reaches the instance on 443. If an egress proxy is needed, set `HTTPS_PROXY`/`NO_PROXY`, which `requests` honors. A private CA needs `CA_BUNDLE`, and the NetworkPolicy CIDR must be filled in.
15. **Basic auth works for the account:** it is not SSO-only and has no MFA, is a "web service access only" user or a normal user with a password, and is not blocked by REST API access policies or IP allowlists.
16. **The account can read** `sys_user` (its own record) and `sys_user_has_role` for `check_access` identity and roles. This is optional; `check_access` reports when they can't be read.
17. **If you expose the server through an OpenShift Route** rather than the in-cluster Service: there must be no path prefix (the SSE `endpoint` is the relative `/messages/`), and the route timeout must be long, e.g. `haproxy.router.openshift.io/timeout: 1h`.
18. **`DEFAULT_TIMEZONE`** should match how users phrase dates, e.g. `Asia/Jerusalem`. It is UTC unless set.
19. **The Aggregate API (`/api/now/stats/<table>`) is allowed** for the integration user (`check_access` → `aggregate_api.available`). Without it, `count_records` and `count_ignoring_status` fall back to `X-Total-Count`, and `group_by` is unavailable.
20. **`sysparm_display_value=all` on the Aggregate API** returns `display_value` in `groupby_fields`. If your instance returns only `value`, `group_by` breakdowns show raw values (for example `2` instead of `In Progress`); the counts are still correct.
21. **`sys_user_group` is readable**, so group names can be resolved to sys_ids. If it isn't (403), the old `assignment_group.nameLIKE<text>` filter is used and a warning says so.
22. **The integration user has the `itil` role** (or equivalent). Without it, the out-of-box incident query business rule limits it to incidents it opened or is listed on. That would make every count too low without any error, and is one possible explanation for "1598".
23. **The Table API has no lower row cap than 500** (`MAX_LIMIT`). If your instance limits REST responses (for example through a REST API rate or response-size policy), lower `MAX_LIMIT` to that value; paging with `next_offset` still reaches every record.
24. **The "cloud infrastructure" group(s)** are the assignment groups your teams actually use. If tickets also sit in child groups with unrelated names, pass `include_child_groups=true`. Check `matched_groups` in the response against what you expect.

---

## Part 4: Follow-up after the first Dify run (ServiceNow Zurich)

**Verification status: unit-tested and mock-tested only.** Same as Part 2: nothing here was run against your instance. The ServiceNow APIs used (Table API, Aggregate API `/api/now/stats`) are standard REST APIs available in Zurich; no Zurich-specific behavior was verified.

### Reported symptoms and the likely causes in the code

| # | Symptom in Dify | Likely cause (from the code; the actual Dify trace / `query_used` was not available) |
|---|---|---|
| 1 | "Cloud infrastructure" INCs: 6 of the 9 that exist | The group filter was a single `assignment_group.nameLIKE<whole text>`. A multi-word name matches only if the words appear in that exact order and spacing, so a second group named e.g. `ענן - תשתיות Tier2` was missed. The LLM may also have added `active`/`state` on its own. The response did not show which groups matched or how many records the status filter removed, so the gap was invisible. |
| 2 | Hard to get relevant "activities" (change requests) | The LLM had to guess state labels to mean "everything still active". `list_change_requests` also returned every raw field (~150 per record), so long lists were hard for the model to use. |
| 3 | "Only 1598 open incidents ever" | There was no counting tool. The model read `total_count` of a filtered list (probably `active=true`) and presented it as "ever". An account without `itil` would also undercount (assumption 22). |
| 4 | Won't show more than a certain number of records | `MAX_LIMIT` capped every list at 100, and nothing told the model to fetch the next page. |

### Commits

| Commit | Topic |
|---|---|
| `groups: resolve assignment groups by words, report matched_groups` | Every word of `assignment_group` must appear in the group name, in any order. Groups are looked up in `sys_user_group`; the list filters `assignment_groupIN<sys_ids>` and returns `matched_groups`. `include_child_groups`. An unknown name returns `no_matching_group`. A 403 on `sys_user_group` or more than 100 matches falls back to the old LIKE, with a warning. `search_groups` uses the same word matching. |
| `status_scope: open/closed/all, change default open, count_ignoring_status` | `status_scope` on every list tool (`active` is an alias). `list_change_requests` defaults to `open` = every active state. When a status filter narrows a list, the same filters are counted in any status (`count_ignoring_status`, plus a `status_note`). Adds `filters_description`. |
| `count_records: exact counts through the Aggregate API` | New read-only tool. Defaults to every state; optional `group_by`; returns `scope_description` (count, ServiceNow user, every filter in words). Falls back to `X-Total-Count`. `check_access` reports whether the Aggregate API is usable. |
| `paging: MAX_LIMIT 500, has_more/next_offset, compact list payloads` | `MAX_LIMIT` default is 500. Adds `has_more`/`next_offset` and an explicit "N more, call again with offset=…" message. `sysparm_fields` per table, compact change records, and descriptions cut at 200 characters in lists. |
| `smoke: print filters, matched_groups, paging and count_records results` | The in-pod smoke test shows the new fields and three counts to compare with the UI. |

### Behavior changes

1. `list_change_requests` without a status filter now sends `active=true`. It returns only changes in an active state unless you pass `status_scope='all'`, a `number` or a `state`.
2. `list_change_requests` records contain the fields in `CHANGE_FIELDS` (`tools/ticket_query.py`) instead of every raw field. `get_change_request_details` is unchanged and still returns the full record.
3. `assignment_group` now resolves groups first. A name that matches no group returns `success=false` with `error_type=no_matching_group` instead of an empty list.
4. In list results, `description` is cut at 200 characters.
5. `MAX_LIMIT` defaults to 500 instead of 100.
6. Each `assignment_group` lookup costs one extra request, up to three more with `include_child_groups`. A status-filtered list costs one extra count request. A failed count never fails the list.

### Test results

The Docker daemon was not available during this round, so the suite ran in a local Python 3.12 virtualenv with the versions from `requirements.lock` (mcp 1.3.0, pydantic 2.10.6). The same 3 un-importable modules were ignored.

```
previous round (container):  331 passed, 10 failed, 5 errors
this round (local venv):     378 passed, 10 failed, 5 errors
```

The 15 failing and erroring test IDs are the same baseline set as in Part 2. New tests in this round: 47.

| File | Tests | Covers |
|---|---|---|
| `test_group_resolution.py` | 10 | Hebrew words in any order, separators, `matched_groups`, child groups, inactive fallback, unknown group → `no_matching_group`, sys_id skip, 403 → LIKE fallback, 401 reported, more than 100 matches |
| `test_status_scope.py` | 14 | open/closed/all, `active` alias and contradiction, change default `open` and when it is not applied, `count_ignoring_status` (query without status), Aggregate API 403 fallback, a count failure does not break the list, `filters_description` |
| `test_count_records.py` | 16 | default `all`, change default `all`, group and status filters, `group_by` sorted breakdown, invalid table/group_by/filter combinations, X-Total-Count fallback, `group_by` without the Aggregate API, 401/500/timeout, malformed stats body |
| `test_paging.py` | 7 | `has_more`/`next_offset` and message, last page, no `X-Total-Count`, MAX_LIMIT 500, `sysparm_fields`, compact change records, truncation in lists but not in get |

Existing tests updated for the new semantics: group expectations in `test_query_builder.py`, `test_change_tools.py::test_list_change_requests_with_filters` and `test_smoke_test.py`; change queries now start with `active=true`; the limit cap test uses 500. The image was not rebuilt in this round.

### How to check against your instance

```bash
oc exec deploy/servicenow-mcp -- servicenow-mcp-smoke --group "תשתיות ענן" --mcp-url http://localhost:8080/sse
```

Compare against the ServiceNow UI:
- `matched_groups` should be exactly the groups you consider "cloud infrastructure".
- `count_records(incident, every state ever)` should equal the record count of an unfiltered incident list in the UI. If it is much lower, check the roles printed by `check_access` (assumption 22).
- `total_count` and `count_ignoring_status` for the group should add up to the 9 incidents you saw in the UI.

In Dify, the response fields `filters_description`, `matched_groups`, `count_ignoring_status` and `scope_description` show what the model actually asked for.
