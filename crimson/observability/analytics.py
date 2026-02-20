"""Query historical attack data from Datadog Spans API.

All methods are best-effort: returns empty results when DD is not configured
or when the datadog-api-client package is not installed.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from crimson import config

logger = logging.getLogger(__name__)


class AttackAnalytics:
    """Query Datadog for historical attack spans."""

    def __init__(self, service: str = "crimson") -> None:
        self._service = service
        if not config.DD_API_KEY or not config.DD_APP_KEY:
            raise RuntimeError(
                "DD_API_KEY and DD_APP_KEY are required. "
                "Set them in your environment or .env file."
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_past_attacks(
        self,
        testee_id: str,
        time_range: str = "now-7d",
    ) -> list[dict[str, Any]]:
        """Return past attack spans for a given testee, categorised by result.

        Returns a list of dicts with keys:
            attack_id, attack_category, success, severity, timestamp
        """
        try:
            raw_spans = self._list_spans(
                query=f"service:{self._service} @tags.testee_id:{testee_id}",
                time_from=time_range,
                time_to="now",
                limit=200,
            )
            return self._normalize_spans(raw_spans)
        except Exception:
            logger.warning("get_past_attacks failed", exc_info=True)
            return []

    def get_attack_summary(
        self,
        testee_id: str,
        time_range: str = "now-7d",
    ) -> dict[str, Any]:
        """Return an aggregate summary of past attacks for a testee.

        Returns::

            {
                "total": int,
                "successful": int,
                "by_category": { "<category>": {"total": N, "success": N} },
                "by_severity": { "<severity>": {"total": N, "success": N} },
            }
        """
        attacks = self.get_past_attacks(testee_id, time_range=time_range)

        summary: dict[str, Any] = {
            "total": len(attacks),
            "successful": sum(1 for a in attacks if a.get("success")),
            "by_category": {},
            "by_severity": {},
        }

        for atk in attacks:
            cat = atk.get("attack_category", "other")
            sev = atk.get("severity", "low")
            success = atk.get("success", False)

            for key, val in [("by_category", cat), ("by_severity", sev)]:
                bucket = summary[key].setdefault(val, {"total": 0, "success": 0})
                bucket["total"] += 1
                if success:
                    bucket["success"] += 1

        return summary

    # ------------------------------------------------------------------
    # Internal: Datadog Spans API
    # ------------------------------------------------------------------

    def _list_spans(
        self,
        query: str,
        time_from: str,
        time_to: str,
        limit: int = 100,
    ) -> list[Any]:
        """Call the Datadog Spans API (v2) to list matching spans."""
        from datadog_api_client import ApiClient, Configuration
        from datadog_api_client.v2.api.spans_api import SpansApi
        from datadog_api_client.v2.model.spans_list_request import SpansListRequest
        from datadog_api_client.v2.model.spans_list_request_attributes import (
            SpansListRequestAttributes,
        )
        from datadog_api_client.v2.model.spans_list_request_data import (
            SpansListRequestData,
        )
        from datadog_api_client.v2.model.spans_list_request_page import (
            SpansListRequestPage,
        )
        from datadog_api_client.v2.model.spans_list_request_type import (
            SpansListRequestType,
        )
        from datadog_api_client.v2.model.spans_query_filter import SpansQueryFilter
        from datadog_api_client.v2.model.spans_sort import SpansSort

        configuration = Configuration()

        body = SpansListRequest(
            data=SpansListRequestData(
                attributes=SpansListRequestAttributes(
                    filter=SpansQueryFilter(
                        _from=time_from,
                        query=query,
                        to=time_to,
                    ),
                    page=SpansListRequestPage(limit=limit),
                    sort=SpansSort.TIMESTAMP_ASCENDING,
                ),
                type=SpansListRequestType.SEARCH_REQUEST,
            ),
        )

        with ApiClient(configuration) as api_client:
            api_instance = SpansApi(api_client)
            response = api_instance.list_spans(body=body)
            return list(response.data) if response.data else []

    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_spans(raw_spans: list[Any]) -> list[dict[str, Any]]:
        """Convert raw Datadog span objects into flat dicts."""
        results: list[dict[str, Any]] = []
        for span in raw_spans:
            try:
                attrs = span.attributes if hasattr(span, "attributes") else {}
                tags: dict = {}
                if hasattr(attrs, "tags"):
                    tags = attrs.tags if isinstance(attrs.tags, dict) else {}
                elif isinstance(attrs, dict):
                    tags = attrs.get("tags", {})

                results.append(
                    {
                        "span_id": getattr(span, "id", ""),
                        "attack_id": tags.get("attack_id", ""),
                        "attack_category": tags.get("attack_category", ""),
                        "success": tags.get("success", "false").lower() == "true",
                        "severity": tags.get("severity", ""),
                        "scan_id": tags.get("scan_id", ""),
                        "testee_id": tags.get("testee_id", ""),
                        "component_id": tags.get("component_id", ""),
                        "timestamp": getattr(attrs, "timestamp", ""),
                    }
                )
            except Exception:
                logger.debug("Failed to normalize span", exc_info=True)
        return results
