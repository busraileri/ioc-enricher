# IOC Enrichment Report

**Generated:** 2026-11-20 19:33 UTC  
**Total indicators:** 5

## Summary

- SUSPICIOUS: 1
- LOOKS CLEAN: 4

## Results

| Type | Indicator | Verdict | Malicious/Suspicious | Advice |
|---|---|---|---|---|
| ip | `8[.]8[.]8[.]8` | SUSPICIOUS | 1/0 | Suspicious: flagged by few engines, check the context and verify manually |
| url | `hxxps://example[.]com/login` | LOOKS CLEAN | 0/0 | Looks clean: but not proven clean |
| domain | `example[.]org` | LOOKS CLEAN | 0/0 | Looks clean: but not proven clean |
| md5 | `d41d8cd98f00b204e9800998ecf8427e` | LOOKS CLEAN | 0/0 | Looks clean: but not proven clean |
| sha256 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | LOOKS CLEAN | 0/0 | Looks clean: but not proven clean |

## Skipped inputs

- `192[.]168[.]1[.]10`: private/local IP
- `bu-bir-ioc-degil`: unrecognized format

## Notes and limitations

- Results rely on VirusTotal data only; a single source can be wrong
- Thresholds: 3+ malicious flags = likely malicious, 1-2 flags = suspicious (verify manually).
- "No data" does not mean clean: new or targeted malware may not be recorded yet.
- Cached results can be up to 24 hours old.
- Indicators are defanged so they cannot be clicked by accident.
