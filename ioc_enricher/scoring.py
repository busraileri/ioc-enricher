# The thresholds are a design decision: there is no single "correct" number.
HIGH_THRESHOLD = 3  # this many independent engines agreeing makes "likely malicious"
SUSPICIOUS_THRESHOLD = 1  # at least one flag means a human should look

VERDICTS = {
    "likely_malicious": "Likely malicious: block, hunt in SIEM/EDR, investigate affected systems",
    "suspicious": "Suspicious: flagged by few engines, check the context and verify manually",
    "clean_looking": "Looks clean: but not proven clean",
    "no_data": "No data: no record in VirusTotal, this does not mean clean",
    "unavailable": "Lookup failed: try again later",
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
    """Add 'verdict' and 'advice' fields to every result."""
    out = []
    for r in results:
        v = verdict(r)
        out.append({**r, "verdict": v, "advice": VERDICTS[v]})
    return out
