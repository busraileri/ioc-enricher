from ioc_enricher.scoring import add_verdicts, verdict


def ok(m=0, s=0):
    return {"status": "ok", "malicious": m, "suspicious": s}


def test_clean():
    assert verdict(ok(0, 0)) == "clean_looking"


def test_single_engine_is_suspicious_not_malicious():
    # Zararsız göstergede gördüğün 'malicious: 1' durumu
    assert verdict(ok(1, 0)) == "suspicious"


def test_suspicious_flag_only():
    assert verdict(ok(0, 2)) == "suspicious"


def test_threshold_boundaries():
    assert verdict(ok(2, 0)) == "suspicious"
    assert verdict(ok(3, 0)) == "likely_malicious"


def test_not_found_is_not_clean():
    assert verdict({"status": "not_found"}) == "no_data"


def test_failures_are_unavailable():
    assert verdict({"status": "rate_limited"}) == "unavailable"
    assert verdict({"status": "error"}) == "unavailable"


def test_add_verdicts_adds_fields():
    out = add_verdicts([{"kind": "ip", "value": "8.8.8.8", **ok(0, 0)}])
    assert out[0]["verdict"] == "clean_looking"
    assert "advice" in out[0]
