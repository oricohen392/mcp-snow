"""
Resolve human labels ("New", "1 - Critical", "High") to the internal values
ServiceNow stores for choice fields, using the instance's own sys_choice table.

Nothing is hard-coded: the valid labels/values are whatever the instance
returns for ``sys_choice`` rows with ``name=<table>``, ``element=<field>`` and
``inactive=false``. Fields inherited from ``task`` (e.g. ``priority``) usually
only have rows under ``name=task``, so the lookup falls back to the parent
table when the table itself has none.

Results are cached in memory per (instance, table, field) for
CHOICE_CACHE_TTL_SECONDS (default 3600).
"""

import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from servicenow_mcp.utils import settings
from servicenow_mcp.utils.http import sn_get
from servicenow_mcp.utils.query import QueryBuilder, QueryInputError, sanitize_value

logger = logging.getLogger(__name__)

_NUMBER_PREFIX = re.compile(r"^\s*\d+\s*-\s*")
_SYS_CHOICE_LIMIT = 1000


class ChoiceResolutionError(QueryInputError):
    """A label could not be mapped to a valid choice value."""


@dataclass
class ChoiceList:
    """The choices of one field, as loaded from sys_choice."""

    table: str
    element: str
    source_table: Optional[str]
    values: List[str] = field(default_factory=list)  # ordered, unique
    labels: Dict[str, str] = field(default_factory=dict)  # value -> first label
    index: Dict[str, set] = field(default_factory=dict)  # casefolded label -> {values}
    error: Optional[str] = None  # set when sys_choice could not be read

    @property
    def available(self) -> bool:
        return self.error is None and bool(self.values)

    def describe(self) -> str:
        return ", ".join(f"{self.labels.get(v) or v} ({v})" for v in self.values)


@dataclass
class Resolution:
    values: List[str]
    warnings: List[str] = field(default_factory=list)


def _label_keys(label: str) -> List[str]:
    keys = [label.strip().casefold()]
    stripped = _NUMBER_PREFIX.sub("", label).strip().casefold()
    if stripped and stripped not in keys:
        keys.append(stripped)
    return keys


class ChoiceResolver:
    """Process-wide sys_choice cache and label->value resolver."""

    def __init__(
        self,
        ttl_seconds: Callable[[], int] = settings.choice_cache_ttl_seconds,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl_seconds = ttl_seconds
        self._clock = clock
        self._cache: Dict[Tuple[str, str, str], Tuple[float, ChoiceList]] = {}
        self._lock = threading.Lock()

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()

    def _fetch(
        self, config: Any, auth_manager: Any, table: str, element: str
    ) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
        query = (
            QueryBuilder()
            .eq("name", table)
            .eq("element", element)
            .eq("inactive", "false")
            .order_by("sequence")
            .build()
        )
        result = sn_get(
            config,
            auth_manager,
            "table/sys_choice",
            {
                "sysparm_query": query,
                "sysparm_fields": "value,label",
                "sysparm_limit": _SYS_CHOICE_LIMIT,
                "sysparm_display_value": "false",
                "sysparm_exclude_reference_link": "true",
            },
        )
        if not result.ok:
            status = f"HTTP {result.status_code}" if result.status_code else result.error_type
            return None, f"could not read sys_choice ({status}): {result.message}"
        return result.records, None

    def get_choices(
        self,
        config: Any,
        auth_manager: Any,
        table: str,
        element: str,
        fallback_tables: Sequence[str] = ("task",),
    ) -> ChoiceList:
        key = (str(getattr(config, "instance_url", "")), table, element)
        now = self._clock()
        with self._lock:
            cached = self._cache.get(key)
            if cached and cached[0] > now:
                return cached[1]

        choices = ChoiceList(table=table, element=element, source_table=None)
        for candidate in (table, *[t for t in fallback_tables if t != table]):
            records, error = self._fetch(config, auth_manager, candidate, element)
            if error:
                choices.error = error
                break
            if records:
                choices.source_table = candidate
                for record in records:
                    value = str(record.get("value", "")).strip()
                    label = str(record.get("label", "")).strip()
                    if not value:
                        continue
                    if value not in choices.labels:
                        choices.values.append(value)
                        choices.labels[value] = label
                    if label:
                        for k in _label_keys(label):
                            choices.index.setdefault(k, set()).add(value)
                break

        if choices.error is None:
            # Only successful loads are cached; errors are retried on the next call.
            with self._lock:
                self._cache[key] = (now + self._ttl_seconds(), choices)
            logger.debug(
                "Loaded %d choices for %s.%s from sys_choice name=%s",
                len(choices.values),
                table,
                element,
                choices.source_table,
            )
        else:
            logger.warning("Choice lookup for %s.%s failed: %s", table, element, choices.error)
        return choices

    def resolve(
        self,
        config: Any,
        auth_manager: Any,
        table: str,
        element: str,
        raw_values: Sequence[str],
        numeric: bool = False,
        fallback_tables: Sequence[str] = ("task",),
    ) -> Resolution:
        """
        Map labels or values to internal values.

        Matching order per input: exact value, case-insensitive label,
        label without a leading "N - " prefix. Raises ChoiceResolutionError
        listing the valid labels when nothing matches.

        If sys_choice is unreadable, inputs are passed through with a warning;
        for ``numeric`` fields (state, priority, risk ...) non-numeric labels are
        rejected because they could never match.
        """
        inputs = [sanitize_value(v, element) for v in raw_values]
        choices = self.get_choices(config, auth_manager, table, element, fallback_tables)
        resolution = Resolution(values=[])

        if not choices.available:
            reason = choices.error or f"sys_choice has no active rows for {table}.{element}"
            for value in inputs:
                if numeric and not value.lstrip("-").isdigit():
                    raise ChoiceResolutionError(
                        f"Cannot translate {element} label '{value}' for {table}: {reason}. "
                        f"Pass the internal numeric value instead (e.g. {element}=2)."
                    )
                resolution.values.append(value)
            resolution.warnings.append(
                f"{element} values were not validated against sys_choice ({reason}); "
                "they are sent to ServiceNow as given."
            )
            return resolution

        for value in inputs:
            if value in choices.labels:
                matched = {value}
            else:
                matched = set()
                for key in _label_keys(value):
                    matched = choices.index.get(key, set())
                    if matched:
                        break
            if not matched:
                raise ChoiceResolutionError(
                    f"Unknown {element} '{value}' for {table}. "
                    f"Valid {element} labels (value): {choices.describe()}"
                )
            if len(matched) > 1:
                options = ", ".join(f"{choices.labels.get(v)} ({v})" for v in sorted(matched))
                raise ChoiceResolutionError(
                    f"Ambiguous {element} '{value}' for {table}; matches {options}. Pass the value."
                )
            for v in sorted(matched):
                if v not in resolution.values:
                    resolution.values.append(v)
        return resolution


CHOICES = ChoiceResolver()
