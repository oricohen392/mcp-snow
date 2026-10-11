"""
Safe construction of ServiceNow encoded queries (sysparm_query).

All user-supplied values must go through ``sanitize_value`` (directly or via
``QueryBuilder``). ``^`` is the encoded-query separator: a value containing it
could append arbitrary conditions (``foo^ORnumberISNOTEMPTY``) or start a new
top-level OR query (``^NQ``), so it is rejected rather than escaped (the Table
API has no escape syntax for it).

Precedence: in an encoded query ``^OR`` binds to the condition immediately
before it, so ``A^B^ORC`` means ``A AND (B OR C)``. ``QueryBuilder`` emits every
OR group as one contiguous term (``B^ORC``) joined to the others with ``^``,
so an OR group can never absorb or leak into a neighbouring filter.
"""

import json
import re
from typing import Any, Iterable, List, Optional, Sequence, Tuple, Union

MAX_VALUE_LENGTH = 200

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_FIELD_NAME = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)*$")
_SYS_ID = re.compile(r"^[0-9a-f]{32}$")

_OPERATORS = {"=", "!=", "LIKE", "NOT LIKE", "STARTSWITH", "IN", ">", ">=", "<", "<="}


class QueryInputError(ValueError):
    """A user-supplied filter value was rejected."""


def sanitize_value(value: Any, field: str = "value", max_length: int = MAX_VALUE_LENGTH) -> str:
    """
    Validate one user-supplied value for use inside an encoded query.

    Rejects: empty values, '^' (query separator), control characters
    (including newlines and NUL) and values longer than ``max_length``.
    Returns the stripped value.
    """
    if value is None:
        raise QueryInputError(f"{field}: a value is required")
    if isinstance(value, bool):
        value = "true" if value else "false"
    text = str(value).strip()
    if not text:
        raise QueryInputError(f"{field}: empty value")
    if "^" in text:
        raise QueryInputError(
            f"{field}: the character '^' is not allowed (it is the ServiceNow query separator)"
        )
    if _CONTROL_CHARS.search(text):
        raise QueryInputError(f"{field}: control characters (newline, tab, NUL, ...) are not allowed")
    if len(text) > max_length:
        raise QueryInputError(f"{field}: value longer than {max_length} characters")
    return text


def is_sys_id(value: str) -> bool:
    """True for a 32-character lowercase hex ServiceNow sys_id."""
    return bool(_SYS_ID.match(value.strip().lower())) if isinstance(value, str) else False


def split_list(value: Union[None, str, Sequence[Any]], field: str = "value") -> List[str]:
    """
    Normalise list-like input to a list of sanitized strings.

    Accepts a Python list, a JSON array string ('["NOC","Network"]') or a
    comma-separated string ('NOC, Network'). Empty items are dropped.
    """
    if value is None:
        return []
    items: Iterable[Any]
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("["):
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError as e:
                raise QueryInputError(f"{field}: invalid JSON list ({e.msg})") from e
            if not isinstance(parsed, list):
                raise QueryInputError(f"{field}: expected a JSON list")
            items = parsed
        else:
            items = text.split(",")
    elif isinstance(value, (list, tuple)):
        items = value
    else:
        items = [value]
    result = []
    for item in items:
        if item is None or (isinstance(item, str) and not item.strip()):
            continue
        result.append(sanitize_value(item, field))
    return result


def _check_field(field: str) -> str:
    if not _FIELD_NAME.match(field):
        raise QueryInputError(f"invalid field name {field!r}")
    return field


def _check_operator(operator: str) -> str:
    if operator not in _OPERATORS:
        raise QueryInputError(f"unsupported operator {operator!r}")
    return operator


Condition = Tuple[str, str, Any]


class QueryBuilder:
    """Accumulates AND-ed terms; each term is a condition or an atomic OR group."""

    def __init__(self) -> None:
        self._terms: List[str] = []
        self._order: Optional[str] = None

    @staticmethod
    def _condition(field: str, operator: str, value: Any) -> str:
        _check_field(field)
        _check_operator(operator)
        if operator == "IN":
            values = value if isinstance(value, (list, tuple)) else [value]
            cleaned = []
            for item in values:
                item = sanitize_value(item, field)
                if "," in item:
                    raise QueryInputError(f"{field}: ',' is not allowed inside an IN list value")
                cleaned.append(item)
            if not cleaned:
                raise QueryInputError(f"{field}: empty list")
            if len(cleaned) == 1:
                return f"{field}={cleaned[0]}"
            return f"{field}IN{','.join(cleaned)}"
        return f"{field}{operator}{sanitize_value(value, field)}"

    def where(self, field: str, operator: str, value: Any) -> "QueryBuilder":
        self._terms.append(self._condition(field, operator, value))
        return self

    def eq(self, field: str, value: Any) -> "QueryBuilder":
        return self.where(field, "=", value)

    def like(self, field: str, value: Any) -> "QueryBuilder":
        return self.where(field, "LIKE", value)

    def in_(self, field: str, values: Sequence[Any]) -> "QueryBuilder":
        return self.where(field, "IN", list(values))

    def gte(self, field: str, value: Any) -> "QueryBuilder":
        return self.where(field, ">=", value)

    def lt(self, field: str, value: Any) -> "QueryBuilder":
        return self.where(field, "<", value)

    def or_group(self, conditions: Sequence[Condition]) -> "QueryBuilder":
        """Add (c1 OR c2 OR ...) as a single AND-ed term."""
        parts = [self._condition(f, op, v) for f, op, v in conditions]
        if not parts:
            raise QueryInputError("empty OR group")
        self._terms.append("^OR".join(parts))
        return self

    def order_by(self, field: str, descending: bool = False) -> "QueryBuilder":
        _check_field(field)
        self._order = f"ORDERBYDESC{field}" if descending else f"ORDERBY{field}"
        return self

    @property
    def terms(self) -> List[str]:
        return list(self._terms)

    def build(self) -> str:
        parts = list(self._terms)
        if self._order:
            parts.append(self._order)
        return "^".join(parts)
