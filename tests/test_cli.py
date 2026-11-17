from ioc_enricher.cli import main

OK = {"status": "ok", "malicious": 0, "suspicious": 0,
      "harmless": 70, "undetected": 18, "detail": ""}


class FakeClient:
    def __init__(self):
        self.calls = 0

    def lookup(self, kind, value):
        self.calls += 1
        return OK


def no_client():
    raise AssertionError("istemci oluşturulmamalıydı")


def make_input(tmp_path, text="8.8.8.8\nexample.org\n"):
    p = tmp_path / "iocs.txt"
    p.write_text(text, encoding="utf-8")
    return str(p)


def base_args(tmp_path, inp):
    return [inp, "--out-dir", str(tmp_path / "out"), "--cache-file", str(tmp_path / "cache.json")]


def test_dry_run_makes_no_api_calls_and_writes_nothing(tmp_path, capsys):
    args = base_args(tmp_path, make_input(tmp_path)) + ["--dry-run"]
    assert main(args, client_factory=no_client) == 0
    assert "2 API sorgusu" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()


def test_run_writes_reports_and_defanged_table(tmp_path, capsys):
    client = FakeClient()
    assert main(base_args(tmp_path, make_input(tmp_path)),
                client_factory=lambda: client) == 0
    assert client.calls == 2
    assert "8[.]8[.]8[.]8" in capsys.readouterr().out
    assert (tmp_path / "out" / "report.csv").exists()
    assert (tmp_path / "out" / "report.md").exists()


def test_second_run_uses_cache(tmp_path):
    client = FakeClient()
    args = base_args(tmp_path, make_input(tmp_path))
    main(args, client_factory=lambda: client)
    main(args, client_factory=lambda: client)
    assert client.calls == 2  # ikinci çalıştırmada API'ye gidilmedi


def test_missing_input_file(tmp_path):
    assert main([str(tmp_path / "yok.txt")], client_factory=no_client) == 2


def test_no_valid_iocs(tmp_path):
    inp = make_input(tmp_path, "192.168.1.1\n???\n")
    assert main(base_args(tmp_path, inp), client_factory=no_client) == 2


def test_max_queries_guard(tmp_path):
    args = base_args(tmp_path, make_input(tmp_path)) + ["--max-queries", "1"]
    assert main(args, client_factory=no_client) == 2


def test_csv_only(tmp_path):
    client = FakeClient()
    args = base_args(tmp_path, make_input(tmp_path)) + ["--formats", "csv"]
    assert main(args, client_factory=lambda: client) == 0
    assert (tmp_path / "out" / "report.csv").exists()
    assert not (tmp_path / "out" / "report.md").exists()
