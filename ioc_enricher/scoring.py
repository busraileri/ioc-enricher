# Eşikler bir tasarım kararıdır, "doğru" tek bir sayı yoktur.
# README'de nedenini açıkla ve gerektiğinde değiştir.
# bu kadar bağımsız motor hemfikirse zararlı olma olasılığı yüksek
HIGH_THRESHOLD = 3
SUSPICIOUS_THRESHOLD = 1  # en az bir işaret varsa manuel bakılmalı

VERDICTS = {
    "likely_malicious": "Zararlı olma olasılığı yüksek: engelle, SIEM/EDR'da ara, etkilenen sistemi incele",
    "suspicious": "Şüpheli: tek/az sayıda motor işaretledi, bağlama bak ve manuel doğrula",
    "clean_looking": "Temiz görünüyor: ama kanıtlanmış temiz değil",
    "no_data": "Bilgi yok: VirusTotal'de kayıt yok, bu 'temiz' demek değildir",
    "unavailable": "Sorgu başarısız: sonra tekrar dene",
}


def verdict(result: dict) -> str:
    status = result.get("status")

    if status == "not_found":
        return "no_data"
    if status != "ok":
        return "unavailable"

    malicious = result.get("malicious", 0)
    suspicious = result.get("suspicious", 0)

    if malicious >= HIGH_THRESHOLD:
        return "likely_malicious"
    if malicious >= SUSPICIOUS_THRESHOLD or suspicious >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "clean_looking"


def add_verdicts(results):
    """Her sonuca 'verdict' ve 'advice' alanlarını ekler."""
    out = []
    for r in results:
        v = verdict(r)
        out.append({**r, "verdict": v, "advice": VERDICTS[v]})
    return out
