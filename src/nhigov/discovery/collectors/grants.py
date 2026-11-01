"""Delegated permission grants (oauth2PermissionGrants): an app acting *for* users.

Our agents are app-only, so these mostly matter for spotting third-party apps
someone consented to (e.g. "read all users' mail on their behalf").
"""

from __future__ import annotations

from typing import Any

from nhigov.graph.client import GraphClient


def collect_delegated_grants(graph: GraphClient) -> list[dict[str, Any]]:
    return list(graph.list_all("oauth2PermissionGrants"))
