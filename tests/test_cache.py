from ioc_enricher.cache import Cache
from ioc_enricher.enricher import enrich


class FakeClient:
    def __init__(self, result):
        self.result = result
        self.calls = 0

    def lookup(self, kind, value):
        self.calls += 1
        return self.result


OK = {"status": "ok", "malicious": 0, "suspicious": 0,
      "harmless": 70, "undetected": 18, "detail": ""}
IOCS = [{"kind": "ip", "value": "8.8.8.8"}]


def test_roundtrip_persists_across_instances(tmp_path):
    path = str(tmp_path / "cache.json")
    c1 = Cache(path)
    c1.set("ip", "8.8.8.8", OK)
    c1.save()
    assert Cache(path).get("ip", "8.8.8.8") == OK


def test_expired_entry_is_ignored(tmp_path):
    path = str(tmp_path / "cache.json")
    clock = {"t": 1000.0}
    c = Cache(path, ttl=60, now=lambda: clock["t"])
    c.set("ip", "8.8.8.8", OK)
    assert c.get("ip", "8.8.8.8") == OK
    clock["t"] += 61
    assert c.get("ip", "8.8.8.8") is None


def test_errors_are_not_cached(tmp_path):
    c = Cache(str(tmp_path / "cache.json"))
    c.set("ip", "8.8.8.8", {"status": "rate_limited", "detail": ""})
    c.set("ip", "1.1.1.1", {"status": "error", "detail": ""})
    assert c.get("ip", "8.8.8.8") is None
    assert c.get("ip", "1.1.1.1") is None


def test_not_found_is_cached(tmp_path):
    c = Cache(str(tmp_path / "cache.json"))
    c.set("domain", "x.example", {"status": "not_found", "detail": ""})
    assert c.get("domain", "x.example")["status"] == "not_found"


def test_corrupt_file_starts_empty(tmp_path):
    path = tmp_path / "cache.json"
    path.write_text("{bozuk json", encoding="utf-8")
    assert Cache(str(path)).get("ip", "8.8.8.8") is None


def test_second_run_makes_no_api_calls(tmp_path):
    path = str(tmp_path / "cache.json")
    client = FakeClient(OK)

    first = enrich(IOCS, client, Cache(path))
    assert client.calls == 1
    assert first[0]["cached"] is False

    second = enrich(IOCS, client, Cache(path))
    assert client.calls == 1  # API'ye ikinci kez gidilmedi
    assert second[0]["cached"] is True
