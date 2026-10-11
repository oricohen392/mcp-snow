"""
Structural tests for OR-group atomicity / precedence in built queries.
"""

from servicenow_mcp.utils.query import QueryBuilder


def _and_terms(query: str):
    """Split a built query into its AND-ed terms (each may contain ^OR)."""
    terms, current = [], []
    for part in query.split("^"):
        if part.startswith("OR") and current and not part.startswith("ORDERBY"):
            current.append(part)
        else:
            if current:
                terms.append("^".join(current))
            current = [part]
    if current:
        terms.append("^".join(current))
    return terms


def test_or_group_is_one_contiguous_term():
    query = (
        QueryBuilder()
        .eq("active", "true")
        .or_group([("short_description", "LIKE", "vpn"), ("description", "LIKE", "vpn")])
        .eq("priority", "1")
        .build()
    )
    assert query == (
        "active=true^short_descriptionLIKEvpn^ORdescriptionLIKEvpn^priority=1"
    )
    assert _and_terms(query) == [
        "active=true",
        "short_descriptionLIKEvpn^ORdescriptionLIKEvpn",
        "priority=1",
    ]


def test_two_or_groups_stay_separate():
    query = (
        QueryBuilder()
        .or_group([("assignment_group.name", "LIKE", "NOC"), ("assignment_group.name", "LIKE", "DBA")])
        .or_group([("short_description", "LIKE", "disk"), ("description", "LIKE", "disk")])
        .build()
    )
    terms = _and_terms(query)
    assert terms == [
        "assignment_group.nameLIKENOC^ORassignment_group.nameLIKEDBA",
        "short_descriptionLIKEdisk^ORdescriptionLIKEdisk",
    ]
    # No term starts with ^OR (which would bind to the previous filter)
    assert not query.startswith("^") and "^^" not in query
    assert "^NQ" not in query


def test_single_item_or_group_is_plain_condition():
    assert QueryBuilder().or_group([("a", "LIKE", "x")]).build() == "aLIKEx"


def test_order_by_is_last():
    query = (
        QueryBuilder()
        .order_by("sys_created_on", descending=True)
        .eq("active", "true")
        .build()
    )
    assert query == "active=true^ORDERBYDESCsys_created_on"
    assert QueryBuilder().order_by("number").build() == "ORDERBYnumber"


def test_in_operator():
    assert QueryBuilder().in_("state", ["1", "2"]).build() == "stateIN1,2"
    assert QueryBuilder().in_("state", ["1"]).build() == "state=1"
