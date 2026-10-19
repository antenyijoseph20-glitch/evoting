"""Static pages, health endpoints and public configuration."""
import config


def test_pages_and_health(client):
    for path in ("/", "/admin", "/results"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert "text/html" in response.headers["content-type"]

    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").json() == {"status": "ready"}


def test_public_elections_and_security_headers(client):
    response = client.get("/api/v1/elections")
    assert response.status_code == 200
    elections = response.json()["elections"]
    assert {e["election_type"] for e in elections} == set(config.ELECTION_PARTIES)
    assert all(e["status"] == "PENDING" for e in elections)
    presidential = next(e for e in elections if e["election_type"] == "PRESIDENTIAL")
    assert {p["code"] for p in presidential["parties"]} == set(config.ELECTION_PARTIES["PRESIDENTIAL"])
    assert presidential["parties"][0]["name"]

    csp = response.headers["content-security-policy"]
    assert "script-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
