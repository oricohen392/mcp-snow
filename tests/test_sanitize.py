"""
Injection and sanitization tests for encoded-query values.
"""

import pytest

from servicenow_mcp.utils.query import (
    MAX_VALUE_LENGTH,
    QueryBuilder,
    QueryInputError,
    sanitize_value,
    split_list,
)

INJECTIONS = [
    "foo^ORnumberISNOTEMPTY",
    "x^NQactive=true",
    "^ORDERBYnumber",
    "NOC^",
    "a\nb",
    "a\rb",
    "a\tb",
    "a\x00b",
    "a\x1bb",
    "a\x7fb",
]


@pytest.mark.parametrize("value", INJECTIONS)
def test_sanitize_rejects_injection(value):
    with pytest.raises(QueryInputError):
        sanitize_value(value, "query")


@pytest.mark.parametrize("value", INJECTIONS)
def test_builder_never_emits_injected_operators(value):
    for build in (
        lambda: QueryBuilder().like("short_description", value),
        lambda: QueryBuilder().eq("state", value),
        lambda: QueryBuilder().in_("state", ["1", value]),
        lambda: QueryBuilder().or_group([("a", "LIKE", "ok"), ("b", "LIKE", value)]),
    ):
        with pytest.raises(QueryInputError):
            build()


def test_sanitize_rejects_empty_and_oversize():
    with pytest.raises(QueryInputError):
        sanitize_value("   ")
    with pytest.raises(QueryInputError):
        sanitize_value(None)
    with pytest.raises(QueryInputError):
        sanitize_value("x" * (MAX_VALUE_LENGTH + 1))
    assert sanitize_value("x" * MAX_VALUE_LENGTH) == "x" * MAX_VALUE_LENGTH


def test_sanitize_keeps_ordinary_text():
    assert sanitize_value("  Email server down (prod) - 50% users  ") == (
        "Email server down (prod) - 50% users"
    )
    assert sanitize_value("שרת דואר") == "שרת דואר"
    assert sanitize_value(True) == "true"


def test_in_list_rejects_commas_inside_values():
    with pytest.raises(QueryInputError):
        QueryBuilder().in_("number", ["INC1,INC2"])


def test_field_names_and_operators_are_whitelisted():
    with pytest.raises(QueryInputError):
        QueryBuilder().eq("state^ORactive", "1")
    with pytest.raises(QueryInputError):
        QueryBuilder().where("state", "ISNOTEMPTY", "x")
    with pytest.raises(QueryInputError):
        QueryBuilder().order_by("number^NQactive=true")


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("NOC", ["NOC"]),
        ("NOC, Network ,", ["NOC", "Network"]),
        ('["NOC", "Service Desk"]', ["NOC", "Service Desk"]),
        (["NOC", " DBA "], ["NOC", "DBA"]),
        (None, []),
    ],
)
def test_split_list(raw, expected):
    assert split_list(raw) == expected


def test_split_list_sanitizes_items():
    with pytest.raises(QueryInputError):
        split_list("NOC,foo^ORactive=true")
    with pytest.raises(QueryInputError):
        split_list('["a", "b^NQ"]')
