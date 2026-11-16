import ipaddress
import re

HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
HEX_RE = re.compile(r"[a-fA-F0-9]+")
DOMAIN_RE = re.compile(
    r"(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}", re.IGNORECASE
)


def refang(value: str) -> str:
    """Raporlardaki 'defang' edilmiş göstergeyi gerçek haline çevirir."""
    v = value.strip()
    v = re.sub(r"^hxxp", "http", v, flags=re.IGNORECASE)
    v = v.replace("[.]", ".").replace("(.)", ".")
    v = v.replace("[:]", ":").replace("[://]", "://")
    return v


def classify(raw: str):
    """(tür, normalleştirilmiş_değer) döndürür. Tür tanınmazsa 'unknown'."""
    value = refang(raw)

    if value.lower().startswith(("http://", "https://")):
        return "url", value

    if HEX_RE.fullmatch(value) and len(value) in HASH_LENGTHS:
        return HASH_LENGTHS[len(value)], value.lower()

    try:
        return "ip", str(ipaddress.ip_address(value))
    except ValueError:
        pass

    if DOMAIN_RE.fullmatch(value):
        return "domain", value.lower()

    return "unknown", value


def is_public_ip(value: str) -> bool:
    """Özel (10.x, 192.168.x), yerel (127.x) ve ayrılmış adresleri eler."""
    return ipaddress.ip_address(value).is_global


def parse_iocs(lines):
    """Satırlardan (kabul_edilenler, atlananlar) listelerini üretir."""
    seen = set()
    accepted, skipped = [], []

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        kind, value = classify(line)

        if kind == "unknown":
            skipped.append((line, "tanınmayan biçim"))
            continue
        if kind == "ip" and not is_public_ip(value):
            skipped.append((line, "özel/yerel IP"))
            continue

        key = (kind, value)
        if key in seen:
            continue
        seen.add(key)
        accepted.append({"kind": kind, "value": value})

    return accepted, skipped
