# IOC Enricher

A small command-line tool that automates a routine SOC task: it takes a list of IOCs (IPs, domains, URLs, file hashes), enriches them with VirusTotal, produces a **verdict** for each indicator, and writes **defanged** reports.
When an alert fires, an analyst usually looks up each indicator by hand on several sites. That is slow and error-prone. This tool automates the lookup step and outputs results in a form that can go straight into a ticket or report.

## Features

- **Type detection:** IPv4/IPv6, domain, URL, MD5/SHA1/SHA256 (the hash type is inferred from its length)
- **Refang/defang:** reads inputs like `hxxps://bad[.]com` and writes all output indicators in a non-clickable form
- **Filtering:** drops private/local IPs (10.x, 192.168.x, 127.x), duplicates, and unrecognized input, and reports what was skipped and why
- **Caching:** does not look the same indicator up twice within 24 hours (protects the free quota)
- **Rate limiting:** spaces out requests and waits and retries on HTTP 429
- **Verdict rules:** instead of a raw count, `likely malicious / suspicious / looks clean / no data`
- **Safety flags:** `--dry-run` (show the plan without calling the API) and `--max-queries` (quota guard)
- **Reports:** terminal table, CSV, Markdown

## Installation

```bash
git clone https://github.com/busraileri/ioc-enricher.git
cd ioc-enricher
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
cp .env.example .env     # Windows: Copy-Item .env.example .env
# put your own VirusTotal API key into .env
```

## Usage

```bash
# See the plan first (no API calls, no key needed)
python -m ioc_enricher examples/iocs.txt --dry-run

# Run it
python -m ioc_enricher examples/iocs.txt

# All options
python -m ioc_enricher --help
```

Input file format: one indicator per line; lines starting with `#` are comments.

## Example output

```
Type    Indicator                                                         Verdict      Malicious/Suspicious  Cached
------  ----------------------------------------------------------------  -----------  --------------------  ------
ip      8[.]8[.]8[.]8                                                     SUSPICIOUS   1/0                   no
url     hxxps://example[.]com/login                                       LOOKS CLEAN  0/0                   no
domain  example[.]org                                                     LOOKS CLEAN  0/0                   no
md5     d41d8cd98f00b204e9800998ecf8427e                                  LOOKS CLEAN  0/0                   no
sha256  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  LOOKS CLEAN  0/0                   no
```

**An interesting observation:** Google's public DNS address `8.8.8.8` was flagged by a single engine in one run. That is almost certainly a false positive, which is why the tool **never calls something malicious based on a single signal**: it says "suspicious, verify manually".

## Design decisions

| Decision                                                   | Rationale                                                                                                                            |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Query only, never upload files or URLs                     | Privacy: uploaded content can be shared with third parties. The tool only **asks** about hashes, IPs and domains                     |
| `404` means "no data", not "clean"                         | New or targeted malware may not be recorded yet                                                                                      |
| Threshold: 3+ engines = likely malicious, 1-2 = suspicious | Several independent engines agreeing makes coincidence unlikely. The threshold is a design choice and can be changed in `scoring.py` |
| Errors and rate-limit results are not cached               | A temporary problem should not look like a permanent result for 24 hours                                                             |
| `--max-queries` defaults to 100                            | A wrong file should not silently burn the daily quota                                                                                |
| Formula protection in CSV cells                            | Values starting with `=`, `+`, `-` or `@` can run as formulas in Excel; input is treated as untrusted                                |
| API key only via environment variable / `.env`             | It never enters the code or the repository                                                                                           |

## Security and ethics

- The tool only **queries public reputation data**; it does not connect to or scan any target.
- Do not commit real incident data: `cache.json` and `reports/` are in `.gitignore` for this reason.
- The VirusTotal free (Public) API is for non-commercial use. Check VirusTotal's current terms; the free quota is 500 requests per day and 4 per minute.

## Limitations

- **Single data source** (VirusTotal); one source can be wrong.
- The verdict rule is simple: it ignores indicator type and context (for example a newly registered domain).
- Cached results can be up to 24 hours old.
- It is a reputation lookup only; it performs **no** malware analysis (static or dynamic).
- Not tested at production scale or in a real SOC workflow.

## Tests

```bash
python -m pytest -v
```

The tests never touch the real API; they use mocked HTTP responses to verify 404, 429, invalid-key and network-error handling. To check that the tests actually protect the code, small deliberate bugs were introduced (for example changing a status code) and the matching test was confirmed to fail.

## Roadmap

- [ ] Second source (AbuseIPDB / URLhaus)
- [ ] Automated tests with GitHub Actions
- [ ] MITRE ATT&CK tagging
- [ ] Per-type thresholds

## License

MIT
