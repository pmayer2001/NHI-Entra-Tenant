from __future__ import annotations

import httpx
import pytest
import respx

from nhigov.graph.client import GraphClient, GraphError

BASE = "https://graph.microsoft.com/v1.0"


@pytest.fixture
def sleeps() -> list[float]:
    return []


@pytest.fixture
def client(sleeps: list[float]) -> GraphClient:
    return GraphClient(lambda: "test-token", sleep=sleeps.append)


@respx.mock
def test_sends_bearer_token(client: GraphClient) -> None:
    route = respx.get(f"{BASE}/applications").respond(json={"value": []})
    client.get("applications")
    assert route.calls.last.request.headers["Authorization"] == "Bearer test-token"


@respx.mock
def test_list_all_follows_next_link(client: GraphClient) -> None:
    next_link = f"{BASE}/applications?$skiptoken=abc"
    respx.get(next_link).respond(json={"value": [{"id": "2"}]})
    respx.get(f"{BASE}/applications").respond(
        json={"value": [{"id": "1"}], "@odata.nextLink": next_link}
    )
    assert [a["id"] for a in client.list_all("applications")] == ["1", "2"]


@respx.mock
def test_retries_429_honouring_retry_after(client: GraphClient, sleeps: list[float]) -> None:
    route = respx.get(f"{BASE}/servicePrincipals").mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "7"}),
            httpx.Response(200, json={"value": []}),
        ]
    )
    client.get("servicePrincipals")
    assert route.call_count == 2
    assert sleeps == [7.0]


@respx.mock
def test_gives_up_after_max_retries(sleeps: list[float]) -> None:
    client = GraphClient(lambda: "t", max_retries=2, sleep=sleeps.append)
    respx.get(f"{BASE}/applications").respond(503)
    with pytest.raises(GraphError) as exc:
        client.get("applications")
    assert exc.value.status == 503
    assert len(sleeps) == 2


@respx.mock
def test_get_after_create_retries_404(client: GraphClient, sleeps: list[float]) -> None:
    route = respx.get(f"{BASE}/applications/abc").mock(
        side_effect=[
            httpx.Response(404),
            httpx.Response(404),
            httpx.Response(200, json={"id": "abc"}),
        ]
    )
    assert client.get_after_create("applications/abc")["id"] == "abc"
    assert route.call_count == 3
    assert sleeps == [2.0, 4.0]


@respx.mock
def test_plain_get_does_not_retry_404(client: GraphClient) -> None:
    route = respx.get(f"{BASE}/applications/abc").respond(404)
    with pytest.raises(GraphError):
        client.get("applications/abc")
    assert route.call_count == 1


@respx.mock
def test_graph_error_carries_code_and_request_id(client: GraphClient) -> None:
    respx.get(f"{BASE}/auditLogs/signIns").respond(
        403,
        headers={"request-id": "req-1"},
        json={"error": {"code": "Authorization_RequestDenied", "message": "nope"}},
    )
    with pytest.raises(GraphError) as exc:
        client.get("auditLogs/signIns")
    assert exc.value.code == "Authorization_RequestDenied"
    assert exc.value.request_id == "req-1"


@respx.mock
def test_check_false_returns_error_response(client: GraphClient) -> None:
    respx.get(f"{BASE}/x").respond(403)
    assert client.request("GET", "x", check=False).status_code == 403


@respx.mock
def test_odata_version_header_on_typed_cast_url(client: GraphClient) -> None:
    cast = respx.get(f"{BASE}/applications/microsoft.graph.agentIdentityBlueprint").respond(
        json={"value": []}
    )
    plain = respx.get(f"{BASE}/applications").respond(json={"value": []})
    client.get("applications/microsoft.graph.agentIdentityBlueprint")
    client.get("applications")
    assert cast.calls.last.request.headers["OData-Version"] == "4.0"
    assert "OData-Version" not in plain.calls.last.request.headers


@respx.mock
def test_odata_version_header_on_odata_type_body(client: GraphClient) -> None:
    route = respx.post(f"{BASE}/applications").respond(201, json={"id": "1"})
    client.post("applications", {"@odata.type": "Microsoft.Graph.AgentIdentityBlueprint"})
    assert route.calls.last.request.headers["OData-Version"] == "4.0"


@respx.mock
def test_beta_version_override(client: GraphClient) -> None:
    route = respx.get("https://graph.microsoft.com/beta/reports/x").respond(json={})
    client.get("reports/x", version="beta")
    assert route.called
