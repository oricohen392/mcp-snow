import pytest
from servicenow_mcp.utils.url import safe_table_url, SafeUrlError


def test_safe_table_url_valid_without_record_id():
    url = safe_table_url("https://dev12345.service-now.com", "incident")
    assert url == "https://dev12345.service-now.com/api/now/table/incident"

    url = safe_table_url("https://dev12345.service-now.com/", "incident")
    assert url == "https://dev12345.service-now.com/api/now/table/incident"

    url = safe_table_url("https://dev12345.service-now.com/api/now", "incident")
    assert url == "https://dev12345.service-now.com/api/now/table/incident"

    url = safe_table_url("https://dev12345.service-now.com/api/now/", "incident")
    assert url == "https://dev12345.service-now.com/api/now/table/incident"


def test_safe_table_url_valid_with_record_id():
    url = safe_table_url("https://dev12345.service-now.com", "incident", "9d385017c611228701d22104cc95c371")
    assert url == "https://dev12345.service-now.com/api/now/table/incident/9d385017c611228701d22104cc95c371"

    url = safe_table_url("https://dev12345.service-now.com/api/now", "sys_user", "admin.user-1_test")
    assert url == "https://dev12345.service-now.com/api/now/table/sys_user/admin.user-1_test"


def test_safe_table_url_path_traversal_rejection():
    with pytest.raises(SafeUrlError, match="Path traversal detected"):
        safe_table_url("https://dev12345.service-now.com", "incident", "../sys_user")

    with pytest.raises(SafeUrlError, match="Path traversal detected"):
        safe_table_url("https://dev12345.service-now.com", "incident", r"..\sys_user")

    with pytest.raises(SafeUrlError, match="Path traversal detected"):
        safe_table_url("https://dev12345.service-now.com", "incident", "../../etc/passwd")


def test_safe_table_url_invalid_table_names():
    invalid_tables = [
        "sys_user/../incident",
        "bad table",
        "sys_user;drop",
        "",
        "incident!",
        "table$name",
    ]
    for tbl in invalid_tables:
        with pytest.raises(SafeUrlError, match="Invalid table name"):
            safe_table_url("https://dev12345.service-now.com", tbl)


def test_safe_table_url_forbidden_characters():
    forbidden_ids = [
        "id?query=1",
        "id#frag",
        "id\x00",
        "id\n",
        "id\r",
        "id\t",
        "id with space",
        "id;drop",
    ]
    for fid in forbidden_ids:
        with pytest.raises(SafeUrlError):
            safe_table_url("https://dev12345.service-now.com", "incident", fid)


def test_safe_table_url_empty_record_id():
    with pytest.raises(SafeUrlError, match="record_id cannot be empty"):
        safe_table_url("https://dev12345.service-now.com", "incident", "")

    with pytest.raises(SafeUrlError, match="record_id cannot be empty"):
        safe_table_url("https://dev12345.service-now.com", "incident", "   ")
