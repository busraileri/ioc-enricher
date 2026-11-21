import csv

from ioc_enricher.report import (csv_safe, defang, format_table,
                                 write_csv, write_markdown)


def r(kind, value, verdict, m=0, s=0, cached=False, detail=""):
    return {"kind": kind, "value": value, "verdict": verdict, "status": "ok",
            "malicious": m, "suspicious": s, "cached": cached,
            "advice": "advice", "detail": detail}


RESULTS = [
    r("ip", "8.8.8.8", "clean_looking"),
    r("url", "http://evil.example/x", "likely_malicious", m=5),
]


def test_defang_url():
    assert defang(
        "url", "https://evil.example/x") == "hxxps://evil[.]example/x"


def test_defang_ip_and_domain():
    assert defang("ip", "8.8.8.8") == "8[.]8[.]8[.]8"
    assert defang("domain", "evil.example") == "evil[.]example"


def test_defang_hash_unchanged():
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert defang("sha256", h) == h


def test_csv_safe():
    assert csv_safe("=1+1") == "'=1+1"
    assert csv_safe("+cmd") == "'+cmd"
    assert csv_safe("normal") == "normal"


def test_table_is_sorted_and_defanged():
    table = format_table(RESULTS)
    assert "http://" not in table
    assert table.index("LIKELY MALICIOUS") < table.index("LOOKS CLEAN")


def test_markdown_has_no_live_links(tmp_path):
    path = tmp_path / "r.md"
    write_markdown(RESULTS, str(path), skipped=[("http://x.example", "unrecognized format")],
                   generated_at="2026-01-01 00:00 UTC")
    text = path.read_text(encoding="utf-8")
    assert "http://" not in text and "https://" not in text
    assert "2026-01-01" in text
    assert "Total indicators" in text


def test_csv_written_and_formula_neutralized(tmp_path):
    path = tmp_path / "r.csv"
    write_csv([r("ip", "8.8.8.8", "clean_looking", detail="=1+1")], str(path))
    with open(path, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.reader(f))
    assert rows[0][0] == "type"
    assert rows[1][-1] == "'=1+1"
    assert rows[1][1] == "8[.]8[.]8[.]8"
