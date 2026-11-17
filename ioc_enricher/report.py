import csv
import re
from datetime import datetime, timezone

from .scoring import HIGH_THRESHOLD, SUSPICIOUS_THRESHOLD

VERDICT_LABELS = {
    "likely_malicious": "ZARARLI OLASILIĞI YÜKSEK",
    "suspicious": "ŞÜPHELİ",
    "no_data": "BİLGİ YOK",
    "unavailable": "SORGU BAŞARISIZ",
    "clean_looking": "TEMİZ GÖRÜNÜYOR",
}
ORDER = list(VERDICT_LABELS)  # önem sırası: en önemli üstte


def defang_text(text: str) -> str:
    """Metindeki bağlantıları ve noktaları tıklanamaz hâle getirir."""
    t = re.sub(r"^http", "hxxp", text.strip(), flags=re.IGNORECASE)
    return t.replace(".", "[.]")


def defang(kind: str, value: str) -> str:
    if kind in ("md5", "sha1", "sha256"):
        return value  # hash'te tıklanacak bir şey yok
    return defang_text(value)


def csv_safe(value) -> str:
    """CSV formül enjeksiyonunu önler: =, +, -, @ ile başlayan hücreleri etkisizleştirir."""
    s = str(value)
    return "'" + s if s.startswith(("=", "+", "-", "@", "\t", "\r")) else s


def _sorted(results):
    return sorted(results, key=lambda r: ORDER.index(r["verdict"]))


def _counts(r) -> str:
    if r.get("status") != "ok":
        return "-"
    return f'{r.get("malicious", 0)}/{r.get("suspicious", 0)}'


def format_table(results) -> str:
    headers = ["Tür", "Gösterge", "Karar", "Zararlı/Şüpheli", "Önbellek"]
    body = [
        [r["kind"], defang(r["kind"], r["value"]), VERDICT_LABELS[r["verdict"]],
         _counts(r), "evet" if r.get("cached") else "hayır"]
        for r in _sorted(results)
    ]
    widths = [max(len(str(row[i])) for row in [headers] + body)
              for i in range(len(headers))]

    def line(row): return "  ".join(str(c).ljust(w)
                                    for c, w in zip(row, widths))
    return "\n".join([line(headers), "  ".join("-" * w for w in widths)] + [line(r) for r in body])


def write_csv(results, path):
    # utf-8-sig: Excel Türkçe karakterleri doğru açar
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["tür", "gösterge", "karar", "zararlı",
                   "şüpheli", "önbellek", "öneri", "ayrıntı"])
        for r in _sorted(results):
            w.writerow([csv_safe(x) for x in [
                r["kind"], defang(r["kind"], r["value"]
                                  ), VERDICT_LABELS[r["verdict"]],
                r.get("malicious", ""), r.get("suspicious", ""),
                "evet" if r.get("cached") else "hayır", r.get(
                    "advice", ""), r.get("detail", ""),
            ]])


def _md(cell) -> str:
    return str(cell).replace("|", "\\|").replace("\n", " ")


def write_markdown(results, path, skipped=None, generated_at=None):
    generated_at = generated_at or datetime.now(
        timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    ordered = _sorted(results)
    lines = [
        "# IOC Zenginleştirme Raporu",
        "",
        f"**Oluşturulma:** {generated_at}  ",
        f"**Toplam gösterge:** {len(results)}",
        "",
        "## Özet",
        "",
    ]
    for v in ORDER:
        n = sum(1 for r in results if r["verdict"] == v)
        if n:
            lines.append(f"- {VERDICT_LABELS[v]}: {n}")

    lines += ["", "## Sonuçlar", "",
              "| Tür | Gösterge | Karar | Zararlı/Şüpheli | Öneri |",
              "|---|---|---|---|---|"]
    for r in ordered:
        lines.append("| " + " | ".join(_md(c) for c in [
            r["kind"], f'`{defang(r["kind"], r["value"])}`', VERDICT_LABELS[r["verdict"]],
            _counts(r), r.get("advice", ""),
        ]) + " |")

    if skipped:
        lines += ["", "## Atlanan girdiler", ""]
        for raw, reason in skipped:
            lines.append(f"- `{_md(defang_text(raw))}`: {reason}")

    lines += [
        "", "## Notlar ve sınırlar", "",
        "- Sonuçlar yalnızca VirusTotal verisine dayanır; tek kaynak yanılabilir.",
        f"- Eşikler: {HIGH_THRESHOLD}+ zararlı işareti = olasılık yüksek, "
        f"{SUSPICIOUS_THRESHOLD}-{HIGH_THRESHOLD - 1} işaret = şüpheli (manuel doğrulama).",
        "- \"Bilgi yok\" temiz demek değildir; yeni ya da hedefe özel zararlılar henüz kayıtlı olmayabilir.",
        "- Önbellekli sonuçlar 24 saate kadar eski olabilir.",
        "- Göstergeler okunurken yanlışlıkla tıklanmasın diye defang edilmiştir.",
        "",
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
