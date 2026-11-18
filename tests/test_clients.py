import base64

import pytest
import requests

from ioc_enricher.clients import VirusTotalClient, url_to_id

STATS = {"data": {"attributes": {"last_analysis_stats": {
    "malicious": 3, "suspicious": 1, "harmless": 60, "undetected": 20}}}}
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


class FakeSession:
    """Gerçek ağa çıkmadan, sıraya dizilmiş yanıtları döndürür."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, headers=None, timeout=None):
        self.calls.append({"url": url, "headers": headers, "timeout": timeout})
        # yanıt kalmadıysa IndexError: beklenmeyen fazladan istek
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def make_client(*responses, min_interval=0, api_key="test-anahtar"):
    session = FakeSession(*responses)
    sleeps = []
    client = VirusTotalClient(api_key=api_key, session=session,
                              min_interval=min_interval, sleep=sleeps.append)
    return client, session, sleeps


def test_ok_response_is_parsed():
    client, _, _ = make_client(FakeResponse(200, STATS))
    result = client.lookup("sha256", SHA256)
    assert result["status"] == "ok"
    assert (result["malicious"], result["suspicious"]) == (3, 1)
    assert (result["harmless"], result["undetected"]) == (60, 20)


def test_missing_fields_default_to_zero():
    client, _, _ = make_client(FakeResponse(200, {"data": {}}))
    result = client.lookup("ip", "8.8.8.8")
    assert result["status"] == "ok"
    assert result["malicious"] == 0


def test_not_found_is_not_clean():
    client, _, _ = make_client(FakeResponse(404))
    result = client.lookup("domain", "yeni-kayit.example")
    assert result["status"] == "not_found"
    assert "temiz demek değildir" in result["detail"]


def test_invalid_key():
    client, _, _ = make_client(FakeResponse(401))
    result = client.lookup("ip", "8.8.8.8")
    assert result["status"] == "error"
    assert "geçersiz" in result["detail"]


def test_rate_limit_then_success():
    client, session, sleeps = make_client(
        FakeResponse(429), FakeResponse(200, STATS))
    result = client.lookup("ip", "8.8.8.8")
    assert result["status"] == "ok"
    assert len(session.calls) == 2
    assert sleeps == [60]  # 429 sonrası bir dakika bekledi


def test_rate_limit_exhausted():
    client, session, sleeps = make_client(
        FakeResponse(429), FakeResponse(429), FakeResponse(429))
    result = client.lookup("ip", "8.8.8.8")
    assert result["status"] == "rate_limited"
    assert len(session.calls) == 3  # ilk deneme + 2 yeniden deneme
    assert sleeps == [60, 60]


def test_network_error():
    client, _, _ = make_client(requests.ConnectionError("bağlantı koptu"))
    result = client.lookup("ip", "8.8.8.8")
    assert result["status"] == "error"
    assert "ağ hatası" in result["detail"]


def test_unexpected_status():
    client, _, _ = make_client(FakeResponse(500))
    result = client.lookup("ip", "8.8.8.8")
    assert result["status"] == "error"
    assert "500" in result["detail"]


def test_unsupported_kind_makes_no_request():
    client, session, _ = make_client()
    result = client.lookup("email", "a@b.example")
    assert result["status"] == "error"
    assert session.calls == []


@pytest.mark.parametrize("kind,value,expected_path", [
    ("sha256", SHA256, f"files/{SHA256}"),
    ("sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709",
     "files/da39a3ee5e6b4b0d3255bfef95601890afd80709"),
    ("md5", "d41d8cd98f00b204e9800998ecf8427e",
     "files/d41d8cd98f00b204e9800998ecf8427e"),
    ("ip", "8.8.8.8", "ip_addresses/8.8.8.8"),
    ("domain", "example.org", "domains/example.org"),
])
def test_endpoint_paths(kind, value, expected_path):
    client, session, _ = make_client(FakeResponse(200, STATS))
    client.lookup(kind, value)
    assert session.calls[0]["url"].endswith(f"/api/v3/{expected_path}")


def test_url_lookup_uses_encoded_id():
    client, session, _ = make_client(FakeResponse(200, STATS))
    client.lookup("url", "http://example.com/login")
    assert session.calls[0]["url"].endswith(
        "/urls/" + url_to_id("http://example.com/login"))


def test_url_to_id_is_unpadded_and_reversible():
    original = "https://example.com/a?b=c"
    encoded = url_to_id(original)
    assert "=" not in encoded
    padded = encoded + "=" * (-len(encoded) % 4)
    assert base64.urlsafe_b64decode(padded).decode() == original


def test_api_key_sent_in_header_not_in_result():
    key = "gizli-test-anahtari"
    client, session, _ = make_client(FakeResponse(200, STATS), api_key=key)
    result = client.lookup("ip", "8.8.8.8")
    assert session.calls[0]["headers"]["x-apikey"] == key
    assert key not in str(result)


def test_requests_are_spaced():
    client, _, sleeps = make_client(FakeResponse(200, STATS), FakeResponse(200, STATS),
                                    min_interval=15.5)
    client.lookup("ip", "8.8.8.8")
    client.lookup("ip", "1.1.1.1")
    assert len(sleeps) == 1  # ilk istek beklemez, ikincisi bekler
    assert 0 < sleeps[0] <= 15.5


def test_missing_key_raises(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        VirusTotalClient()
