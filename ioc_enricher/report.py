import csv
import re
from datetime import datetime, timezone

from .scoring import HIGH_THRESHOLD, SUSPICIOUS_THRESHOLD

VERDICT_LABELS = {
    "likely_malicious": "LIKELY MALICIOUS",
    "suspicious": "SUSPICIOUS",
    "no_data": "NO DATA",
    "unavailable": "LOOKUP FAILED",
    "clean_looking": "LOOKS CLEAN",
}
ORDER = list(VERDICT_LABELS)  # most important first


def defang_text(text: str) -> str:
    """Make links and dots in free text non-clickable."""
    t = re.sub(r"^http", "hxxp", text.strip(), flags=re.IGNORECASE)
    return t.replace(".", "[.]")


def defang(kind: str, value: str) -> str:
    if kind in ("md5", "sha1", "sha256"):
        return value  # nothing clickable in a hash, and altering it would break searching
    return defang_text(value)


def csv_safe(value) -> str:
    """Prevent CSV formula injection: neutralize cells starting with =, +, -, @.."""
    s = str(value)
    return "'" + s if s.startswith(("=", "+", "-", "@", "\t", "\r")) else s


def _sorted(results):
    return sorted(results, key=lambda r: ORDER.index(r["verdict"]))


def _counts(r) -> str:
    if r.get("status") != "ok":
        return "-"
    return f'{r.get("malicious", 0)}/{r.get("suspicious", 0)}'


def format_table(results) -> str:
    headers = ["Type", "Indicator", "Verdict",
               "Malicious/Suspicious", "Cached"]
    body = [
        [r["kind"], defang(r["kind"], r["value"]), VERDICT_LABELS[r["verdict"]],
         _counts(r), "yes" if r.get("cached") else "no"]
        for r in _sorted(results)
    ]
    widths = [max(len(str(row[i])) for row in [headers] + body)
              for i in range(len(headers))]

    def line(row): return "  ".join(str(c).ljust(w)
                                    for c, w in zip(row, widths))
    return "\n".join([line(headers), "  ".join("-" * w for w in widths)] + [line(r) for r in body])


def write_csv(results, path):
    # utf-8-sig so Excel detects the encoding correctly
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["type", "indicator", "verdict", "malicious",
                   "suspicious", "cached", "advice", "detail"])
        for r in _sorted(results):
            w.writerow([csv_safe(x) for x in [
                r["kind"], defang(r["kind"], r["value"]
                                  ), VERDICT_LABELS[r["verdict"]],
                r.get("malicious", ""), r.get("suspicious", ""),
                "yes" if r.get("cached") else "no", r.get(
                    "advice", ""), r.get("detail", ""),
            ]])


def _md(cell) -> str:
    return str(cell).replace("|", "\\|").replace("\n", " ")


def write_markdown(results, path, skipped=None, generated_at=None):
    generated_at = generated_at or datetime.now(
        timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    ordered = _sorted(results)
    lines = [
        "# IOC Enrichment Report",
        "",
        f"**Generated:** {generated_at}  ",
        f"**Total indicators:** {len(results)}",
        "",
        "## Summary",
        "",
    ]
    for v in ORDER:
        n = sum(1 for r in results if r["verdict"] == v)
        if n:
            lines.append(f"- {VERDICT_LABELS[v]}: {n}")

    lines += ["", "## Results", "",
              "| Type | Indicator | Verdict | Malicious/Suspicious | Advice |",
              "|---|---|---|---|---|"]
    for r in ordered:
        lines.append("| " + " | ".join(_md(c) for c in [
            r["kind"], f'`{defang(r["kind"], r["value"])}`', VERDICT_LABELS[r["verdict"]],
            _counts(r), r.get("advice", ""),
        ]) + " |")

    if skipped:
        lines += ["", "## Skipped inputs", ""]
        for raw, reason in skipped:
            lines.append(f"- `{_md(defang_text(raw))}`: {reason}")

    lines += [
        "", "## Notes and limitations", "",
        "- Results rely on VirusTotal data only; a single source can be wrong",
        f"- Thresholds: {HIGH_THRESHOLD}+ malicious flags = likely malicious, "
        f"{SUSPICIOUS_THRESHOLD}-{HIGH_THRESHOLD - 1} flags = suspicious (verify manually).",
        "- \"No data\" does not mean clean: new or targeted malware may not be recorded yet.",
        "- Cached results can be up to 24 hours old.",
        "- Indicators are defanged so they cannot be clicked by accident.",
        "",
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
